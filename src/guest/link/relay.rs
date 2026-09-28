//! The host socket: dialling the relay and multiplexing guest sessions over it.

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::sync::mpsc::{self, TryRecvError};
use std::sync::Arc;
use std::time::Instant;

use tracing::debug;
use tungstenite::client::IntoClientRequest;
use tungstenite::http::{header, HeaderValue, StatusCode};
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Connector, HandshakeError, Message, WebSocket};

use super::frame::{Frame, HEADER_LEN};
use super::host::GuestHost;
use super::noise::ResponderKeys;
use super::session::Sessions;
use super::{poll, Ended, Signals, Timing, WakeReceiver};

/// Largest relay message: a 70000-byte guest message plus the frame header.
const MAX_RELAY_MESSAGE: usize = 70_000 + HEADER_LEN;
/// Outbound frames queued by sessions while the socket is busy (each at most
/// one Noise message), so a slow relay pushes back on session output.
const OUTBOUND_QUEUE: usize = 64;
/// Frames moved to the socket per turn, so reading keeps up with writing.
const OUTBOUND_BATCH: usize = 16;
/// Relay close code for a host socket replaced by a newer one.
const CLOSE_REPLACED: u16 = 4000;

/// The WebSocket URL of this host's socket. Production relays must use TLS;
/// tests also accept a plain `ws://` stub.
pub(super) fn host_socket_url(relay_url: &str, host_id: &str) -> Result<String, String> {
    let base = relay_url.trim_end_matches('/');
    let socket = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if cfg!(test) && base.starts_with("ws://") {
        base.to_owned()
    } else {
        return Err(format!("relay_url {relay_url:?} is not an https:// URL"));
    };
    if host_id.is_empty()
        || !host_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("host_id is not base64url".into());
    }
    Ok(format!("{socket}/v1/host/{host_id}"))
}

fn tls_connector() -> Result<Connector, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("tls setup: {error}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Connector::Rustls(Arc::new(config)))
}

fn dial(host: &str, port: u16, timing: &Timing) -> io::Result<TcpStream> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let mut last = io::Error::new(io::ErrorKind::NotFound, "relay host has no address");
    for address in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, timing.handshake_timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = error,
        }
    }
    Err(last)
}

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

pub(super) struct Connection {
    socket: Socket,
    /// A handle on the socket's file description, for polling and for
    /// switching it to nonblocking after the handshake.
    tcp: TcpStream,
    keys: Arc<ResponderKeys>,
}

impl Connection {
    /// Dials the relay and upgrades to this host's authenticated socket.
    pub(super) fn open<H: GuestHost>(host: &H, timing: &Timing) -> Result<Self, String> {
        let info = host
            .host_info()
            .map_err(|error| format!("guest keys unavailable: {error}"))?;
        let url = host_socket_url(&info.relay_url, &info.host_id)?;
        let mut request = url
            .into_client_request()
            .map_err(|error| format!("relay_url: {error}"))?;
        let mut bearer = HeaderValue::from_str(&format!("Bearer {}", info.relay_secret))
            .map_err(|_| "relay secret is not a valid header".to_owned())?;
        bearer.set_sensitive(true);
        request.headers_mut().insert(header::AUTHORIZATION, bearer);
        let uri = request.uri();
        let secure = uri.scheme_str() == Some("wss");
        let authority = uri.host().unwrap_or_default().to_owned();
        let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });

        let tcp = dial(&authority, port, timing)
            .map_err(|error| format!("relay unreachable: {error}"))?;
        let setup = |tcp: &TcpStream| {
            tcp.set_nodelay(true)?;
            tcp.set_read_timeout(Some(timing.handshake_timeout))?;
            tcp.set_write_timeout(Some(timing.handshake_timeout))?;
            tcp.try_clone()
        };
        let handle = setup(&tcp).map_err(|error| format!("relay socket: {error}"))?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_RELAY_MESSAGE))
            .max_frame_size(Some(MAX_RELAY_MESSAGE));
        let connector = if secure {
            tls_connector()?
        } else {
            Connector::Plain
        };
        let (socket, _) =
            tungstenite::client_tls_with_config(request, tcp, Some(config), Some(connector))
                .map_err(|error| match error {
                    HandshakeError::Failure(tungstenite::Error::Http(response))
                        if response.status() == StatusCode::UNAUTHORIZED =>
                    {
                        "relay rejected host secret".to_owned()
                    }
                    HandshakeError::Failure(tungstenite::Error::Http(response)) => {
                        format!("relay answered HTTP {}", response.status().as_u16())
                    }
                    HandshakeError::Failure(error) => format!("relay handshake: {error}"),
                    HandshakeError::Interrupted(_) => "relay handshake timed out".to_owned(),
                })?;
        handle
            .set_nonblocking(true)
            .map_err(|error| format!("relay socket: {error}"))?;
        Ok(Self {
            socket,
            tcp: handle,
            keys: Arc::new(ResponderKeys::new(info.node_secret, &info.host_id)),
        })
    }

    /// Serves guest sessions until the socket ends, the link is stopped, or it
    /// is no longer wanted. Every session ends with the connection.
    pub(super) fn run<H: GuestHost>(
        mut self,
        host: &Arc<H>,
        signals: &Signals,
        wake: &WakeReceiver,
        timing: &Timing,
    ) -> Ended {
        let (outbound_tx, outbound) = mpsc::sync_channel(OUTBOUND_QUEUE);
        let mut sessions = Sessions::new(
            Arc::clone(host),
            Arc::clone(&self.keys),
            outbound_tx,
            signals.waker.clone(),
            timing.handshake_timeout,
        );
        let mut last_pong = Instant::now();
        let mut next_ping = last_pong + timing.ping_interval;
        // The socket holds unsent bytes; wait for it before queueing more.
        let mut blocked = false;
        loop {
            if signals.stopped() {
                self.close(CloseCode::Away, "stopping");
                return Ended::Stopped;
            }
            if signals.take_changed() && !host.link_wanted() {
                self.close(CloseCode::Normal, "no guests");
                return Ended::Unwanted;
            }

            let mut moved = 0;
            while !blocked && moved < OUTBOUND_BATCH {
                let message = match outbound.try_recv() {
                    Ok(message) => message,
                    // `sessions` holds a sender, so the queue never disconnects.
                    Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                };
                moved += 1;
                if let Some(frame) = sessions.outbound(message) {
                    blocked = match self.write(frame) {
                        Ok(blocked) => blocked,
                        Err(ended) => return ended,
                    };
                }
            }
            loop {
                let message = match self.socket.read() {
                    Ok(message) => message,
                    Err(tungstenite::Error::Io(error))
                        if error.kind() == io::ErrorKind::WouldBlock =>
                    {
                        break;
                    }
                    Err(error) => return Ended::Failed(format!("relay connection lost: {error}")),
                };
                match message {
                    Message::Binary(message) => {
                        let reply = match Frame::decode(message) {
                            Ok(Frame::Open(session)) => sessions.open(session),
                            Ok(Frame::Data(session, payload)) => sessions.data(session, payload),
                            Ok(Frame::Close(session, _)) => {
                                sessions.close(session);
                                None
                            }
                            Err(error) => {
                                self.close(CloseCode::Protocol, "bad frame");
                                return Ended::Failed(format!("relay sent a bad frame: {error}"));
                            }
                        };
                        if let Some(frame) = reply {
                            if let Err(ended) = self.write(frame) {
                                return ended;
                            }
                        }
                    }
                    Message::Text(text) if text.as_str() == "pong" => last_pong = Instant::now(),
                    Message::Pong(_) => last_pong = Instant::now(),
                    Message::Close(frame) => {
                        let _ = self.socket.flush();
                        return match frame {
                            Some(frame) if u16::from(frame.code) == CLOSE_REPLACED => {
                                Ended::Replaced
                            }
                            Some(frame) => Ended::Failed(format!(
                                "relay closed the connection ({} {})",
                                u16::from(frame.code),
                                frame.reason
                            )),
                            None => Ended::Failed("relay closed the connection".into()),
                        };
                    }
                    other => debug!("guest link: ignoring relay message {other:?}"),
                }
            }
            // Sends queued frames and any control replies reading queued.
            match self.flush() {
                Ok(still_blocked) => blocked = still_blocked,
                Err(ended) => return ended,
            }

            let now = Instant::now();
            if now.duration_since(last_pong) >= timing.pong_timeout {
                return Ended::Failed("relay stopped answering pings".into());
            }
            if now >= next_ping {
                next_ping = now + timing.ping_interval;
                // Invites expire without a change notification, so re-check on
                // every ping (25 s, within the 60 s the contract allows).
                if !host.link_wanted() {
                    self.close(CloseCode::Normal, "no guests");
                    return Ended::Unwanted;
                }
                match self.write_message(Message::text("ping")) {
                    Ok(now_blocked) => blocked |= now_blocked,
                    Err(ended) => return ended,
                }
                continue;
            }

            let socket_events = if blocked {
                libc::POLLIN | libc::POLLOUT
            } else {
                libc::POLLIN
            };
            let mut fds = [
                libc::pollfd {
                    fd: self.tcp.as_raw_fd(),
                    events: socket_events,
                    revents: 0,
                },
                libc::pollfd {
                    fd: wake.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let until = next_ping.min(last_pong + timing.pong_timeout);
            if let Err(error) = poll(&mut fds, until.saturating_duration_since(now)) {
                return Ended::Failed(format!("relay socket poll: {error}"));
            }
            wake.drain();
        }
    }

    /// Queues one frame; `Ok(true)` when the socket could not take it all yet.
    fn write(&mut self, frame: Vec<u8>) -> Result<bool, Ended> {
        self.write_message(Message::Binary(frame.into()))
    }

    fn write_message(&mut self, message: Message) -> Result<bool, Ended> {
        would_block(self.socket.write(message))
    }

    fn flush(&mut self) -> Result<bool, Ended> {
        would_block(self.socket.flush())
    }

    /// Best-effort close handshake; the socket is dropped right after.
    fn close(&mut self, code: CloseCode, reason: &'static str) {
        let _ = self.socket.close(Some(CloseFrame {
            code,
            reason: reason.into(),
        }));
    }
}

fn would_block(result: tungstenite::Result<()>) -> Result<bool, Ended> {
    match result {
        Ok(()) => Ok(false),
        // The frame is queued; the rest goes out when the socket drains.
        Err(tungstenite::Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => Ok(true),
        Err(error) => Err(Ended::Failed(format!("relay connection lost: {error}"))),
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.tcp.shutdown(std::net::Shutdown::Both);
    }
}
