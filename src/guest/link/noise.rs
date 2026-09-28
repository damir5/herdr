//! Noise IK responder for guest sessions. The guest initiates knowing the
//! host's static key; message 1 carries its static key and hello, message 2
//! the admission reply. Transport messages then carry the API byte stream.

use std::fmt;
use std::sync::{Mutex, PoisonError};

use snow::{Builder, HandshakeState, TransportState};

use super::frame;

pub(super) const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
/// Largest Noise message.
pub(super) const MAX_MESSAGE: usize = 65535;
const TAG_LEN: usize = 16;
/// Largest transport plaintext, so every ciphertext fits one Noise message.
pub(super) const MAX_PLAINTEXT: usize = MAX_MESSAGE - TAG_LEN;

/// The handshake prologue binds every session to this host's relay identity.
pub(super) fn prologue(host_id: &str) -> Vec<u8> {
    format!("herdr-guest/1:{host_id}").into_bytes()
}

/// The node's static key and prologue, shared by every session of a link.
pub(super) struct ResponderKeys {
    secret: [u8; 32],
    prologue: Vec<u8>,
}

impl ResponderKeys {
    pub(super) fn new(node_secret: [u8; 32], host_id: &str) -> Self {
        Self {
            secret: node_secret,
            prologue: prologue(host_id),
        }
    }
}

#[derive(Debug)]
pub(super) enum HandshakeError {
    Noise(snow::Error),
    /// Message 1 decrypted, but its payload is not JSON.
    BadHello,
    Reply(serde_json::Error),
}

impl HandshakeError {
    /// The CLOSE reason sent to the guest.
    pub(super) fn close_reason(&self) -> &'static str {
        match self {
            Self::Noise(_) => "handshake_failed",
            Self::BadHello => "bad_hello",
            Self::Reply(_) => "internal",
        }
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Noise(error) => write!(f, "noise handshake: {error}"),
            Self::BadHello => f.write_str("hello payload is not JSON"),
            Self::Reply(error) => write!(f, "admission reply: {error}"),
        }
    }
}

impl From<snow::Error> for HandshakeError {
    fn from(error: snow::Error) -> Self {
        Self::Noise(error)
    }
}

/// What message 1 proved and asked for.
pub(super) struct Hello {
    pub(super) device_pub: [u8; 32],
    pub(super) payload: serde_json::Value,
}

pub(super) struct Responder(HandshakeState);

impl Responder {
    pub(super) fn new(keys: &ResponderKeys) -> Result<Self, snow::Error> {
        Builder::new(PATTERN.parse()?)
            .local_private_key(&keys.secret)?
            .prologue(&keys.prologue)?
            .build_responder()
            .map(Self)
    }

    /// Reads message 1: the guest's authenticated static key and its JSON hello.
    pub(super) fn read_hello(&mut self, message: &[u8]) -> Result<Hello, HandshakeError> {
        let mut payload = vec![0; MAX_MESSAGE];
        let len = self.0.read_message(message, &mut payload)?;
        let device_pub = self
            .0
            .get_remote_static()
            .and_then(|key| <[u8; 32]>::try_from(key).ok())
            .ok_or(HandshakeError::Noise(snow::Error::Input))?;
        let payload =
            serde_json::from_slice(&payload[..len]).map_err(|_| HandshakeError::BadHello)?;
        Ok(Hello {
            device_pub,
            payload,
        })
    }

    /// Writes message 2 carrying `reply` and completes the handshake.
    pub(super) fn reply(
        mut self,
        reply: &serde_json::Value,
    ) -> Result<(Vec<u8>, Transport), HandshakeError> {
        let payload = serde_json::to_vec(reply).map_err(HandshakeError::Reply)?;
        let mut message = vec![0; MAX_MESSAGE];
        let len = self.0.write_message(&payload, &mut message)?;
        message.truncate(len);
        let transport = self.0.into_transport_mode()?;
        Ok((message, Transport(Mutex::new(transport))))
    }
}

/// Transport state shared by a session's inbound and outbound pumps. Nonces
/// advance per message, so a replayed, reordered or altered message fails.
pub(super) struct Transport(Mutex<TransportState>);

impl Transport {
    /// Encrypts at most [`MAX_PLAINTEXT`] bytes straight into a DATA frame.
    pub(super) fn encrypt_frame(
        &self,
        session: u32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, snow::Error> {
        frame::data_with(session, plaintext.len() + TAG_LEN, |out| {
            self.state().write_message(plaintext, out)
        })
    }

    /// Decrypts one guest message into `out` (at least [`MAX_MESSAGE`] bytes).
    pub(super) fn decrypt(&self, message: &[u8], out: &mut [u8]) -> Result<usize, snow::Error> {
        self.state().read_message(message, out)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, TransportState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::path::PathBuf;

    use bytes::Bytes;
    use serde_json::{json, Value};
    use snow::params::DHChoice;
    use snow::resolvers::{CryptoResolver, DefaultResolver};

    use super::*;
    use crate::guest::link::frame::Frame;

    // Static and ephemeral keys from the Noise test vectors (cacophony), so a
    // Swift client can cross-check the same keys against published vectors.
    const INIT_STATIC: &str = "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";
    const INIT_EPHEMERAL: &str = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
    const RESP_STATIC: &str = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
    const RESP_EPHEMERAL: &str = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";
    const HOST_ID: &str = "AAECAwQFBgcICQoLDA0ODw";

    const HELLO: &str = r#"{"device":"iPhone","invite_id":"EBESExQVFhcYGRobHB0eHw","secret":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8","v":1}"#;
    const REPLY: &str = r#"{"agent":{"name":"llm-opt","target":"w1-1"},"guest_id":"g_QEFCQ0RFRkdISUpLTE1OTw","machine_label":"Jerry's Mac Studio","name":"plotarmordev","ok":true,"owner_name":"Jerry"}"#;
    /// Transport payloads after the handshake, alternating guest then host as
    /// in the cacophony vector format: one request line and its response.
    const TRANSPORT: [&str; 2] = [
        "{\"id\":\"1\",\"method\":\"ping\",\"params\":{}}\n",
        "{\"id\":\"1\",\"result\":{\"type\":\"pong\",\"version\":\"0.9.1\",\"protocol\":6}}\n",
    ];

    pub(in crate::guest::link) fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn key(text: &str) -> [u8; 32] {
        unhex(text).try_into().unwrap()
    }

    pub(in crate::guest::link) fn public_key(secret: &[u8; 32]) -> [u8; 32] {
        let mut dh = DefaultResolver
            .resolve_dh(&DHChoice::Curve25519)
            .expect("default resolver has X25519");
        dh.set(secret);
        dh.pubkey().try_into().unwrap()
    }

    /// A guest-side IK initiator for `host_id` and the host's `host_pub`.
    pub(in crate::guest::link) fn initiator(
        device_secret: &[u8; 32],
        host_pub: &[u8; 32],
        host_id: &str,
        ephemeral: Option<&[u8; 32]>,
    ) -> HandshakeState {
        let prologue = prologue(host_id);
        let mut builder = Builder::new(PATTERN.parse().unwrap())
            .local_private_key(device_secret)
            .unwrap()
            .remote_public_key(host_pub)
            .unwrap()
            .prologue(&prologue)
            .unwrap();
        if let Some(ephemeral) = ephemeral {
            builder = builder.fixed_ephemeral_key_for_testing_only(ephemeral);
        }
        builder.build_initiator().unwrap()
    }

    fn write(state: &mut HandshakeState, payload: &[u8]) -> Vec<u8> {
        let mut message = vec![0; MAX_MESSAGE];
        let len = state.write_message(payload, &mut message).unwrap();
        message.truncate(len);
        message
    }

    fn read(state: &mut HandshakeState, message: &[u8]) -> Vec<u8> {
        let mut payload = vec![0; MAX_MESSAGE];
        let len = state.read_message(message, &mut payload).unwrap();
        payload.truncate(len);
        payload
    }

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/guest/link/testdata/noise_ik_vector.json")
    }

    /// The transcript both sides produce with the fixed keys above.
    fn transcript() -> Value {
        let (init_static, resp_static) = (key(INIT_STATIC), key(RESP_STATIC));
        let (init_ephemeral, resp_ephemeral) = (key(INIT_EPHEMERAL), key(RESP_EPHEMERAL));
        let resp_public = public_key(&resp_static);
        let mut init = initiator(&init_static, &resp_public, HOST_ID, Some(&init_ephemeral));
        let prologue = prologue(HOST_ID);
        let mut resp = Builder::new(PATTERN.parse().unwrap())
            .local_private_key(&resp_static)
            .unwrap()
            .prologue(&prologue)
            .unwrap()
            .fixed_ephemeral_key_for_testing_only(&resp_ephemeral)
            .build_responder()
            .unwrap();

        let mut messages = Vec::new();
        let mut record = |payload: &str, ciphertext: &[u8]| {
            messages.push(json!({
                "payload": hex(payload.as_bytes()),
                "payload_text": payload,
                "ciphertext": hex(ciphertext),
            }));
        };

        let message1 = write(&mut init, HELLO.as_bytes());
        assert_eq!(read(&mut resp, &message1), HELLO.as_bytes());
        record(HELLO, &message1);
        let message2 = write(&mut resp, REPLY.as_bytes());
        assert_eq!(read(&mut init, &message2), REPLY.as_bytes());
        record(REPLY, &message2);
        let handshake_hash = init.get_handshake_hash().to_vec();
        assert_eq!(handshake_hash, resp.get_handshake_hash());

        let mut init = init.into_transport_mode().unwrap();
        let mut resp = resp.into_transport_mode().unwrap();
        for (index, payload) in TRANSPORT.into_iter().enumerate() {
            let (from, to) = if index % 2 == 0 {
                (&mut init, &mut resp)
            } else {
                (&mut resp, &mut init)
            };
            let mut ciphertext = vec![0; MAX_MESSAGE];
            let len = from
                .write_message(payload.as_bytes(), &mut ciphertext)
                .unwrap();
            ciphertext.truncate(len);
            let mut plaintext = vec![0; MAX_MESSAGE];
            let len = to.read_message(&ciphertext, &mut plaintext).unwrap();
            assert_eq!(&plaintext[..len], payload.as_bytes());
            record(payload, &ciphertext);
        }

        json!({
            "description": "Noise IK transcript for HerdrUp guest sessions in the cacophony vector format, generated with snow by `cargo test write_noise_ik_vector -- --ignored` in jerryfane/herdr. The keys are the cacophony IK test-vector keys. The initiator is the guest and the responder the host; messages alternate from the initiator, so even indexes are guest to host. Hex is lowercase; *_text and *_public keys are informational.",
            "protocol_name": PATTERN,
            "host_id": HOST_ID,
            "init_prologue": hex(&prologue),
            "init_static": INIT_STATIC,
            "init_ephemeral": INIT_EPHEMERAL,
            "init_remote_static": hex(&resp_public),
            "resp_prologue": hex(&prologue),
            "resp_static": RESP_STATIC,
            "resp_ephemeral": RESP_EPHEMERAL,
            "prologue_text": String::from_utf8(prologue).unwrap(),
            "init_static_public": hex(&public_key(&init_static)),
            "init_ephemeral_public": hex(&public_key(&init_ephemeral)),
            "resp_ephemeral_public": hex(&public_key(&resp_ephemeral)),
            "handshake_hash": hex(&handshake_hash),
            "messages": messages,
        })
    }

    fn fixture() -> Value {
        let text = std::fs::read_to_string(fixture_path()).expect("read noise_ik_vector.json");
        serde_json::from_str(&text).expect("noise_ik_vector.json is JSON")
    }

    #[test]
    #[ignore = "rewrites src/guest/link/testdata/noise_ik_vector.json"]
    fn write_noise_ik_vector() {
        let text = serde_json::to_string_pretty(&transcript()).unwrap();
        std::fs::write(fixture_path(), text + "\n").unwrap();
    }

    #[test]
    fn committed_vector_matches_the_snow_transcript() {
        assert_eq!(
            fixture(),
            transcript(),
            "regenerate with `cargo test write_noise_ik_vector -- --ignored`"
        );
    }

    #[test]
    fn responder_accepts_the_vector_initiator_and_carries_transport_both_ways() {
        let vector = fixture();
        let message1 = unhex(vector["messages"][0]["ciphertext"].as_str().unwrap());

        let keys = ResponderKeys::new(key(RESP_STATIC), HOST_ID);
        let mut responder = Responder::new(&keys).unwrap();
        let hello = responder.read_hello(&message1).unwrap();
        assert_eq!(hello.device_pub, public_key(&key(INIT_STATIC)));
        assert_eq!(hello.payload, serde_json::from_str::<Value>(HELLO).unwrap());

        // The same fixed initiator reproduces message 1, then reads a reply
        // from the production responder (whose ephemeral is random).
        let mut init = initiator(
            &key(INIT_STATIC),
            &public_key(&key(RESP_STATIC)),
            HOST_ID,
            Some(&key(INIT_EPHEMERAL)),
        );
        assert_eq!(write(&mut init, HELLO.as_bytes()), message1);
        let reply: Value = serde_json::from_str(REPLY).unwrap();
        let (message2, transport) = responder.reply(&reply).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&read(&mut init, &message2)).unwrap(),
            reply
        );
        let mut init = init.into_transport_mode().unwrap();

        let request = TRANSPORT[0].as_bytes();
        let mut ciphertext = vec![0; MAX_MESSAGE];
        let len = init.write_message(request, &mut ciphertext).unwrap();
        let mut plaintext = vec![0; MAX_MESSAGE];
        let len = transport
            .decrypt(&ciphertext[..len], &mut plaintext)
            .unwrap();
        assert_eq!(&plaintext[..len], request);

        let response = TRANSPORT[1].as_bytes();
        let frame = transport.encrypt_frame(42, response).unwrap();
        let Ok(Frame::Data(42, ciphertext)) = Frame::decode(Bytes::from(frame)) else {
            panic!("encrypt_frame builds a DATA frame for its session");
        };
        let len = init.read_message(&ciphertext, &mut plaintext).unwrap();
        assert_eq!(&plaintext[..len], response);
    }

    #[test]
    fn responder_rejects_a_hello_for_another_host() {
        let resp_static = key(RESP_STATIC);
        let host_pub = public_key(&resp_static);
        let hello = |host_id: &str, host_pub: &[u8; 32]| {
            let mut init = initiator(&key(INIT_STATIC), host_pub, host_id, None);
            write(&mut init, HELLO.as_bytes())
        };
        let keys = ResponderKeys::new(resp_static, HOST_ID);

        // A different prologue (host id) fails authentication.
        let other_host = hello("BBECAwQFBgcICQoLDA0ODw", &host_pub);
        assert!(matches!(
            Responder::new(&keys).unwrap().read_hello(&other_host),
            Err(HandshakeError::Noise(_))
        ));
        // So does a message encrypted to a different static key.
        let other_key = hello(HOST_ID, &public_key(&key(INIT_EPHEMERAL)));
        assert!(matches!(
            Responder::new(&keys).unwrap().read_hello(&other_key),
            Err(HandshakeError::Noise(_))
        ));
        assert!(Responder::new(&keys)
            .unwrap()
            .read_hello(&hello(HOST_ID, &host_pub))
            .is_ok());
    }

    #[test]
    fn plaintext_limit_fills_one_noise_message() {
        let vector_keys = ResponderKeys::new(key(RESP_STATIC), HOST_ID);
        let mut responder = Responder::new(&vector_keys).unwrap();
        let mut init = initiator(
            &key(INIT_STATIC),
            &public_key(&key(RESP_STATIC)),
            HOST_ID,
            None,
        );
        responder
            .read_hello(&write(&mut init, HELLO.as_bytes()))
            .unwrap();
        let (_, transport) = responder.reply(&json!({"ok": true})).unwrap();
        let frame = transport
            .encrypt_frame(1, &vec![b'x'; MAX_PLAINTEXT])
            .unwrap();
        assert_eq!(frame.len(), frame::HEADER_LEN + MAX_MESSAGE);
    }
}
