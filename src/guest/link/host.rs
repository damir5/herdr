//! What the link needs from the daemon: relay credentials, admission, the
//! guest API server, and link status reporting. The daemon implements this over
//! the guest store; tests implement it with fakes.

use std::io;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::Receiver;

/// Relay credentials and the node's Noise static key.
#[derive(Clone)]
pub(crate) struct HostInfo {
    /// b64url of 16 bytes (22 chars); names this host at the relay.
    pub(crate) host_id: String,
    /// Bearer secret for the host socket.
    pub(crate) relay_secret: String,
    /// X25519 static secret the Noise responder proves.
    pub(crate) node_secret: [u8; 32],
    /// Base relay URL, for example `https://guest.herdrup.themartian.app`.
    pub(crate) relay_url: String,
}

/// Outcome of checking a guest's message-1 payload.
// Built by the daemon's `GuestHost` impl, which lands with the guest store.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Admission<P> {
    /// Serve the guest as `principal`; `reply` is the message-2 payload.
    Admitted {
        principal: P,
        reply: serde_json::Value,
    },
    /// Refuse with one of the contract error codes (`unknown`, `revoked`, ...).
    Refused(&'static str),
}

/// Link state reported by `guest.list`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkState {
    Off,
    Connecting,
    Up,
    Retrying,
}

impl LinkState {
    // The `guest.list` spelling; read by the daemon's `GuestHost` impl.
    #[allow(dead_code)]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Connecting => "connecting",
            Self::Up => "up",
            Self::Retrying => "retrying",
        }
    }
}

pub(crate) trait GuestHost: Send + Sync + 'static {
    /// Authenticated guest identity handed from `admit` to `serve`.
    type Principal: Send + 'static;

    /// Relay credentials and node key, created on first use.
    fn host_info(&self) -> io::Result<HostInfo>;

    /// True while at least one active guest or unexpired, unused invite exists.
    fn link_wanted(&self) -> bool;

    /// Decides a guest's admission from its static key and message-1 payload.
    fn admit(&self, device_pub: [u8; 32], hello: &serde_json::Value) -> Admission<Self::Principal>;

    /// Runs one API connection as `principal` and returns when `stream` ends.
    fn serve(&self, principal: Self::Principal, stream: UnixStream);

    fn set_link_status(&self, state: LinkState, last_error: Option<String>);

    /// Fires whenever guests or invites change, which may flip `link_wanted`.
    fn subscribe_changes(&self) -> Receiver<()>;
}
