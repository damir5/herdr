//! The link end to end: a fake host behind the real link, against a
//! plain-WebSocket stub relay that plays the guest side of each session.

use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde_json::{json, Value};
use snow::{HandshakeState, TransportState};
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::CloseFrame;
use tungstenite::{Message, WebSocket};

use super::frame::{self, Frame};
use super::host::{Admission, GuestHost, HostInfo, LinkState};
use super::noise::tests::{initiator, public_key};
use super::noise::{MAX_MESSAGE, MAX_PLAINTEXT};
use super::relay::host_socket_url;
use super::session::MAX_SESSIONS;
use super::{Backoff, GuestLink, Timing};

const HOST_ID: &str = "AAECAwQFBgcICQoLDA0ODw";
const RELAY_SECRET: &str = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3I";
const NODE_SECRET: [u8; 32] = [0x42; 32];
const DEVICE_SECRET: [u8; 32] = [0x17; 32];
const WAIT: Duration = Duration::from_secs(10);

fn timing() -> Timing {
    Timing {
        ping_interval: Duration::from_millis(200),
        pong_timeout: Duration::from_secs(20),
        backoff_base: Duration::from_millis(50),
        backoff_cap: Duration::from_millis(400),
        handshake_timeout: Duration::from_secs(30),
    }
}

type Status = (LinkState, Option<String>);

struct FakeHost {
    relay_url: String,
    wanted: AtomicBool,
    refusal: Mutex<Option<&'static str>>,
    statuses: Mutex<Vec<Status>>,
    status_changed: Condvar,
    subscribers: Mutex<Vec<Sender<()>>>,
    hellos: Mutex<Vec<([u8; 32], Value)>>,
    served: Mutex<Sender<String>>,
}

impl FakeHost {
    fn new(relay_url: String) -> (Arc<Self>, Receiver<String>) {
        let (served, ended) = mpsc::channel();
        let host = Arc::new(Self {
            relay_url,
            wanted: AtomicBool::new(true),
            refusal: Mutex::new(None),
            statuses: Mutex::new(Vec::new()),
            status_changed: Condvar::new(),
            subscribers: Mutex::new(Vec::new()),
            hellos: Mutex::new(Vec::new()),
            served: Mutex::new(served),
        });
        (host, ended)
    }

    fn set_wanted(&self, wanted: bool) {
        self.wanted.store(wanted, Ordering::SeqCst);
        for subscriber in self.subscribers.lock().unwrap().iter() {
            let _ = subscriber.send(());
        }
    }

    /// Waits for a status matching `want`, returning it.
    fn wait_status(&self, want: impl Fn(&Status) -> bool) -> Status {
        let deadline = Instant::now() + WAIT;
        let mut statuses = self.statuses.lock().unwrap();
        loop {
            if let Some(found) = statuses.iter().find(|status| want(status)) {
                return found.clone();
            }
            let left = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_else(|| panic!("no matching status; saw {statuses:?}"));
            statuses = self.status_changed.wait_timeout(statuses, left).unwrap().0;
        }
    }

    fn last_status(&self) -> Option<Status> {
        self.statuses.lock().unwrap().last().cloned()
    }
}

impl GuestHost for FakeHost {
    type Principal = String;

    fn host_info(&self) -> std::io::Result<HostInfo> {
        Ok(HostInfo {
            host_id: HOST_ID.into(),
            relay_secret: RELAY_SECRET.into(),
            node_secret: NODE_SECRET,
            relay_url: self.relay_url.clone(),
        })
    }

    fn link_wanted(&self) -> bool {
        self.wanted.load(Ordering::SeqCst)
    }

    fn admit(&self, device_pub: [u8; 32], hello: &Value) -> Admission<String> {
        self.hellos
            .lock()
            .unwrap()
            .push((device_pub, hello.clone()));
        if let Some(code) = *self.refusal.lock().unwrap() {
            return Admission::Refused(code);
        }
        Admission::Admitted {
            principal: "plotarmordev".into(),
            reply: json!({"ok": true, "name": "plotarmordev"}),
        }
    }

    /// Echoes each line prefixed by the principal; `bye` answers and ends.
    fn serve(&self, principal: String, stream: UnixStream) {
        let mut writer = stream.try_clone().unwrap();
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { break };
            if line == "bye" {
                let _ = writeln!(writer, "bye {principal}");
                break;
            }
            if writeln!(writer, "{principal}: {line}").is_err() {
                break;
            }
        }
        let _ = self.served.lock().unwrap().send(principal);
    }

    fn set_link_status(&self, state: LinkState, last_error: Option<String>) {
        self.statuses.lock().unwrap().push((state, last_error));
        self.status_changed.notify_all();
    }

    fn subscribe_changes(&self) -> Receiver<()> {
        let (sender, receiver) = mpsc::channel();
        self.subscribers.lock().unwrap().push(sender);
        receiver
    }
}

struct StubRelay {
    listener: TcpListener,
    url: String,
}

// tungstenite's handshake `Callback` fixes the large `ErrorResponse` error type.
#[allow(clippy::result_large_err)]
impl StubRelay {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        Self { listener, url }
    }

    fn tcp(&self, within: Duration) -> Option<TcpStream> {
        let deadline = Instant::now() + within;
        loop {
            match self.listener.accept() {
                Ok((tcp, _)) => {
                    tcp.set_nonblocking(false).unwrap();
                    tcp.set_read_timeout(Some(WAIT)).unwrap();
                    return Some(tcp);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        }
    }

    /// Accepts the next host socket after checking its path and bearer.
    fn accept(&self) -> HostSocket {
        let tcp = self.tcp(WAIT).expect("the link connects");
        let check = |request: &Request, response: Response| {
            assert_eq!(request.uri().path(), format!("/v1/host/{HOST_ID}"));
            assert_eq!(
                request.headers()["authorization"],
                format!("Bearer {RELAY_SECRET}").as_str()
            );
            Ok(response)
        };
        HostSocket {
            ws: tungstenite::accept_hdr(tcp, check).unwrap(),
            auto_pong: true,
        }
    }

    /// Answers the next upgrade with an HTTP error, like a relay refusing it.
    fn refuse(&self, status: u16, body: &str) {
        let tcp = self.tcp(WAIT).expect("the link connects");
        let refuse = |_: &Request, _: Response| -> Result<Response, ErrorResponse> {
            Err(tungstenite::http::Response::builder()
                .status(status)
                .body(Some(body.to_owned()))
                .unwrap())
        };
        assert!(tungstenite::accept_hdr(tcp, refuse).is_err());
    }
}

struct HostSocket {
    ws: WebSocket<TcpStream>,
    auto_pong: bool,
}

impl HostSocket {
    fn send(&mut self, frame: Vec<u8>) {
        self.ws.send(Message::Binary(frame.into())).unwrap();
    }

    /// The next non-ping message from the link.
    fn message(&mut self) -> Message {
        loop {
            match self.ws.read().expect("relay read") {
                Message::Text(text) if text.as_str() == "ping" => {
                    if self.auto_pong {
                        self.ws.send(Message::text("pong")).unwrap();
                    }
                }
                message => return message,
            }
        }
    }

    fn frame(&mut self) -> Frame {
        match self.message() {
            Message::Binary(bytes) => Frame::decode(bytes).expect("link frames decode"),
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    fn close_code(&mut self) -> u16 {
        match self.message() {
            Message::Close(Some(frame)) => u16::from(frame.code),
            other => panic!("expected a close, got {other:?}"),
        }
    }
}

/// The guest side of one session.
struct Guest {
    session: u32,
    transport: TransportState,
    /// The last transport message sent, for replays.
    sent: Vec<u8>,
}

/// Opens `session` and runs the handshake, returning the host's reply payload.
fn handshake(
    relay: &mut HostSocket,
    session: u32,
    hello: &Value,
) -> (Value, HandshakeState, Vec<u8>) {
    relay.send(frame::open(session));
    let mut init = initiator(&DEVICE_SECRET, &public_key(&NODE_SECRET), HOST_ID, None);
    let mut message1 = vec![0; MAX_MESSAGE];
    let len = init
        .write_message(&serde_json::to_vec(hello).unwrap(), &mut message1)
        .unwrap();
    message1.truncate(len);
    relay.send(frame::data(session, &message1));
    let Frame::Data(id, message2) = relay.frame() else {
        panic!("expected message 2");
    };
    assert_eq!(id, session);
    let mut reply = vec![0; MAX_MESSAGE];
    let len = init.read_message(&message2, &mut reply).unwrap();
    (
        serde_json::from_slice(&reply[..len]).unwrap(),
        init,
        message1,
    )
}

fn admitted(relay: &mut HostSocket, session: u32) -> Guest {
    let (reply, init, _) = handshake(relay, session, &json!({"v": 1}));
    assert_eq!(reply["ok"], true);
    Guest {
        session,
        transport: init.into_transport_mode().unwrap(),
        sent: Vec::new(),
    }
}

impl Guest {
    /// Sends `plaintext` in Noise-message-sized chunks.
    fn send(&mut self, relay: &mut HostSocket, plaintext: &str) {
        for chunk in plaintext.as_bytes().chunks(MAX_PLAINTEXT) {
            let mut message = vec![0; MAX_MESSAGE];
            let len = self.transport.write_message(chunk, &mut message).unwrap();
            message.truncate(len);
            relay.send(frame::data(self.session, &message));
            self.sent = message;
        }
    }

    fn recv(&mut self, relay: &mut HostSocket) -> String {
        let Frame::Data(id, message) = relay.frame() else {
            panic!("expected data for session {}", self.session);
        };
        assert_eq!(id, self.session);
        let mut plaintext = vec![0; MAX_MESSAGE];
        let len = self
            .transport
            .read_message(&message, &mut plaintext)
            .unwrap();
        String::from_utf8(plaintext[..len].to_vec()).unwrap()
    }
}

fn start(relay: &StubRelay, timing: Timing) -> (GuestLink, Arc<FakeHost>, Receiver<String>) {
    let (host, served) = FakeHost::new(relay.url.clone());
    let link = GuestLink::start_with(Arc::clone(&host), timing).unwrap();
    (link, host, served)
}

#[test]
fn backoff_follows_the_contract_schedule_within_jitter_bounds() {
    let defaults = Timing::default();
    let secs = Duration::from_secs;
    let mut backoff = Backoff::new(defaults.backoff_base, defaults.backoff_cap);
    let schedule: Vec<_> = (0..8).map(|_| backoff.next(0)).collect();
    assert_eq!(schedule, [2, 4, 8, 16, 32, 60, 60, 60].map(secs));

    let mut entropy = 0x9e37_79b9_7f4a_7c15_u64;
    let mut backoff = Backoff::new(defaults.backoff_base, defaults.backoff_cap);
    for full in [2, 4, 8, 16, 32, 60, 60, 60, 60, 60] {
        for _ in 0..50 {
            entropy = entropy
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let mut probe = Backoff {
                attempt: backoff.attempt,
                ..Backoff::new(defaults.backoff_base, defaults.backoff_cap)
            };
            let delay = probe.next(entropy);
            assert!(
                delay <= secs(full) && delay >= secs(full) * 3 / 4,
                "{delay:?} outside the jitter window below {full}s"
            );
        }
        backoff.next(entropy);
    }

    for _ in 0..200 {
        backoff.next(u64::MAX);
    }
    assert_eq!(backoff.next(0), secs(60), "long outages stay at the cap");
    backoff.reset();
    assert_eq!(backoff.next(0), secs(2));
}

#[test]
fn host_socket_requires_tls_and_a_base64url_host_id() {
    assert_eq!(
        host_socket_url("https://guest.herdrup.themartian.app/", HOST_ID).unwrap(),
        format!("wss://guest.herdrup.themartian.app/v1/host/{HOST_ID}")
    );
    for insecure in [
        "http://guest.herdrup.themartian.app",
        "wss://relay",
        "relay",
    ] {
        assert!(host_socket_url(insecure, HOST_ID).is_err(), "{insecure}");
    }
    for bad_id in ["", "../../v1/guest/x", "a b", "a?b"] {
        assert!(
            host_socket_url("https://relay", bad_id).is_err(),
            "{bad_id}"
        );
    }
}

#[test]
fn guest_round_trip_through_the_relay() {
    let stub = StubRelay::new();
    let (link, host, served) = start(&stub, timing());
    let mut relay = stub.accept();
    host.wait_status(|(state, _)| *state == LinkState::Up);

    // Ids come from the relay and persist across reconnects: never assume 1.
    let session = u32::MAX;
    let hello = json!({"v": 1, "invite_id": "EBESExQVFhcYGRobHB0eHw", "device": "iPhone"});
    let (reply, init, _) = handshake(&mut relay, session, &hello);
    assert_eq!(reply, json!({"ok": true, "name": "plotarmordev"}));
    assert_eq!(
        host.hellos.lock().unwrap().as_slice(),
        [(public_key(&DEVICE_SECRET), hello)],
        "admission sees the guest's authenticated key and hello"
    );

    let mut guest = Guest {
        session,
        transport: init.into_transport_mode().unwrap(),
        sent: Vec::new(),
    };
    guest.send(&mut relay, "hello\n");
    assert_eq!(guest.recv(&mut relay), "plotarmordev: hello\n");

    // A response bigger than one Noise message arrives in order, in chunks.
    let big = "x".repeat(200_000);
    guest.send(&mut relay, &format!("{big}\n"));
    let mut echoed = String::new();
    while !echoed.ends_with('\n') {
        echoed += &guest.recv(&mut relay);
    }
    assert_eq!(echoed, format!("plotarmordev: {big}\n"));

    guest.send(&mut relay, "bye\n");
    assert_eq!(guest.recv(&mut relay), "bye plotarmordev\n");
    assert_eq!(relay.frame(), Frame::Close(session, String::new()));
    assert_eq!(served.recv_timeout(WAIT).unwrap(), "plotarmordev");

    drop(link);
    assert_eq!(relay.close_code(), 1001);
    host.wait_status(|(state, _)| *state == LinkState::Off);
}

#[test]
fn refused_guest_gets_the_code_then_a_close() {
    let stub = StubRelay::new();
    let (_link, host, served) = start(&stub, timing());
    *host.refusal.lock().unwrap() = Some("revoked");
    let mut relay = stub.accept();

    let (reply, _, _) = handshake(&mut relay, 5, &json!({"v": 1}));
    assert_eq!(reply, json!({"ok": false, "error": "revoked"}));
    assert_eq!(relay.frame(), Frame::Close(5, "revoked".into()));
    assert!(
        served.try_recv().is_err(),
        "a refused guest is never served"
    );
}

#[test]
fn hello_for_another_host_key_closes_without_admission() {
    let stub = StubRelay::new();
    let (_link, host, _served) = start(&stub, timing());
    let mut relay = stub.accept();

    relay.send(frame::open(1));
    let mut init = initiator(&DEVICE_SECRET, &public_key(&[9; 32]), HOST_ID, None);
    let mut message1 = vec![0; MAX_MESSAGE];
    let len = init.write_message(b"{\"v\":1}", &mut message1).unwrap();
    relay.send(frame::data(1, &message1[..len]));
    assert_eq!(relay.frame(), Frame::Close(1, "handshake_failed".into()));
    assert!(host.hellos.lock().unwrap().is_empty());
}

#[test]
fn flipped_ciphertext_bit_closes_the_session() {
    let stub = StubRelay::new();
    let (_link, _host, served) = start(&stub, timing());
    let mut relay = stub.accept();

    let mut guest = admitted(&mut relay, 1);
    let mut message = vec![0; MAX_MESSAGE];
    let len = guest
        .transport
        .write_message(b"hello\n", &mut message)
        .unwrap();
    message[len / 2] ^= 0x01;
    relay.send(frame::data(1, &message[..len]));

    assert_eq!(relay.frame(), Frame::Close(1, "decrypt_failed".into()));
    assert_eq!(
        served.recv_timeout(WAIT).unwrap(),
        "plotarmordev",
        "the API stream ends with the session"
    );
}

#[test]
fn replayed_messages_are_rejected() {
    let stub = StubRelay::new();
    let (_link, _host, _served) = start(&stub, timing());
    let mut relay = stub.accept();

    // Within a session, the nonce has moved on.
    let mut guest = admitted(&mut relay, 1);
    guest.send(&mut relay, "hello\n");
    assert_eq!(guest.recv(&mut relay), "plotarmordev: hello\n");
    let replay = guest.sent.clone();
    relay.send(frame::data(1, &replay));
    assert_eq!(relay.frame(), Frame::Close(1, "decrypt_failed".into()));

    // Replaying message 1 into a new session yields fresh responder keys, so
    // the old request does not decrypt there either.
    let (_, init, message1) = handshake(&mut relay, 2, &json!({"v": 1}));
    let mut transport = init.into_transport_mode().unwrap();
    let mut request = vec![0; MAX_MESSAGE];
    let len = transport.write_message(b"hello\n", &mut request).unwrap();
    request.truncate(len);
    relay.send(frame::open(3));
    relay.send(frame::data(3, &message1));
    assert!(matches!(relay.frame(), Frame::Data(3, _)));
    relay.send(frame::data(3, &request));
    assert_eq!(relay.frame(), Frame::Close(3, "decrypt_failed".into()));
}

#[test]
fn sessions_beyond_the_cap_are_refused_until_one_closes() {
    let stub = StubRelay::new();
    let (_link, _host, _served) = start(&stub, timing());
    let mut relay = stub.accept();

    let cap = u32::try_from(MAX_SESSIONS).unwrap();
    for session in 1..=cap {
        relay.send(frame::open(session));
    }
    relay.send(frame::open(cap + 1));
    assert_eq!(relay.frame(), Frame::Close(cap + 1, "host_busy".into()));

    relay.send(frame::data(cap + 1, b"late data for a refused session"));
    relay.send(frame::close(1, ""));
    let mut guest = admitted(&mut relay, cap + 2);
    guest.send(&mut relay, "hello\n");
    assert_eq!(guest.recv(&mut relay), "plotarmordev: hello\n");
}

#[test]
fn rejected_bearer_is_reported_and_retried() {
    let stub = StubRelay::new();
    let (_link, host, _served) = start(&stub, timing());

    stub.refuse(401, r#"{"error":"unauthorized"}"#);
    let (_, error) = host.wait_status(|(state, _)| *state == LinkState::Retrying);
    assert_eq!(error.as_deref(), Some("relay rejected host secret"));

    let _relay = stub.accept();
    host.wait_status(|(state, _)| *state == LinkState::Up);
    assert_eq!(host.last_status(), Some((LinkState::Up, None)));
}

#[test]
fn unanswered_pings_drop_the_socket_and_reconnect() {
    let stub = StubRelay::new();
    let quick = Timing {
        ping_interval: Duration::from_millis(50),
        pong_timeout: Duration::from_millis(300),
        ..timing()
    };
    let (_link, host, _served) = start(&stub, quick);
    let mut silent = stub.accept();
    silent.auto_pong = false;
    assert_eq!(silent.ws.read().unwrap(), Message::text("ping"));

    let (_, error) = host.wait_status(|(state, _)| *state == LinkState::Retrying);
    assert_eq!(error.as_deref(), Some("relay stopped answering pings"));
    let mut relay = stub.accept();
    host.wait_status(|(state, error)| *state == LinkState::Up && error.is_none());

    // Answered pings keep the new socket up well past the pong timeout.
    relay
        .ws
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let (until, mut pings) = (Instant::now() + Duration::from_secs(1), 0);
    while Instant::now() < until {
        match relay.ws.read() {
            Ok(message) => {
                assert_eq!(message, Message::text("ping"));
                relay.ws.send(Message::text("pong")).unwrap();
                pings += 1;
            }
            Err(tungstenite::Error::Io(error))
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => panic!("relay socket failed: {error}"),
        }
    }
    assert!(pings >= 10, "pings every 50 ms, saw {pings}");
    relay.ws.get_ref().set_read_timeout(Some(WAIT)).unwrap();
    let mut guest = admitted(&mut relay, 1);
    guest.send(&mut relay, "still here\n");
    assert_eq!(guest.recv(&mut relay), "plotarmordev: still here\n");
}

#[test]
fn link_runs_only_while_guests_or_invites_exist() {
    let stub = StubRelay::new();
    let (host, _served) = FakeHost::new(stub.url.clone());
    host.wanted.store(false, Ordering::SeqCst);
    let _link = GuestLink::start_with(Arc::clone(&host), timing()).unwrap();

    host.wait_status(|(state, _)| *state == LinkState::Off);
    assert!(
        stub.tcp(Duration::from_millis(300)).is_none(),
        "no socket without guests"
    );

    host.set_wanted(true);
    let mut relay = stub.accept();
    host.wait_status(|(state, _)| *state == LinkState::Up);

    host.set_wanted(false);
    assert_eq!(relay.close_code(), 1000);
    assert!(stub.tcp(Duration::from_millis(300)).is_none());
    assert_eq!(host.last_status(), Some((LinkState::Off, None)));
}

#[test]
fn replaced_socket_reconnects_only_after_backoff() {
    let stub = StubRelay::new();
    let slow = Timing {
        backoff_base: Duration::from_millis(400),
        backoff_cap: Duration::from_millis(400),
        ..timing()
    };
    let (_link, host, _served) = start(&stub, slow);
    let mut relay = stub.accept();
    host.wait_status(|(state, _)| *state == LinkState::Up);

    relay
        .ws
        .close(Some(CloseFrame {
            code: CloseCode::from(4000),
            reason: "replaced".into(),
        }))
        .unwrap();
    let replaced = Instant::now();
    let (_, error) = host.wait_status(|(state, _)| *state == LinkState::Retrying);
    assert_eq!(
        error.as_deref(),
        Some("replaced by another connection for this host")
    );

    let _relay = stub.accept();
    assert!(
        replaced.elapsed() >= Duration::from_millis(300),
        "reconnected {:?} after being replaced",
        replaced.elapsed()
    );
}

#[test]
fn malformed_relay_frame_drops_the_socket() {
    let stub = StubRelay::new();
    let (_link, host, _served) = start(&stub, timing());
    let mut relay = stub.accept();

    relay
        .ws
        .send(Message::Binary(Bytes::from_static(&[0x02, 0, 0])))
        .unwrap();
    assert_eq!(relay.close_code(), 1002);
    let (_, error) = host.wait_status(|(state, _)| *state == LinkState::Retrying);
    assert!(error.unwrap().starts_with("relay sent a bad frame"));
    let _relay = stub.accept();
}

#[test]
fn link_stops_when_the_last_invite_expires_unannounced() {
    let stub = StubRelay::new();
    let (_link, host, _served) = start(&stub, timing());
    let mut relay = stub.accept();
    host.wait_status(|(state, _)| *state == LinkState::Up);

    // Expiry changes `link_wanted` without a change notification.
    host.wanted.store(false, Ordering::SeqCst);
    assert_eq!(relay.close_code(), 1000);
    host.wait_status(|(state, _)| *state == LinkState::Off);
    assert!(stub.tcp(Duration::from_millis(300)).is_none());
}
