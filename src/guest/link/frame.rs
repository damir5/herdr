//! Host-socket frames: `type u8 | session u32 BE | payload`, one per binary
//! WebSocket message.

use std::fmt;

use bytes::Bytes;

pub(super) const HEADER_LEN: usize = 5;
/// CLOSE reasons become WebSocket close reasons on the guest side.
pub(super) const MAX_CLOSE_REASON: usize = 123;

const OPEN: u8 = 0x01;
const DATA: u8 = 0x02;
const CLOSE: u8 = 0x03;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Frame {
    /// A guest connected (relay to host only).
    Open(u32),
    /// One guest binary message: a Noise message for that session.
    Data(u32, Bytes),
    /// Either side ended the session.
    Close(u32, String),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum FrameError {
    Short(usize),
    UnknownType(u8),
    OpenWithPayload,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short(len) => write!(f, "frame of {len} bytes is shorter than its header"),
            Self::UnknownType(kind) => write!(f, "unknown frame type {kind:#04x}"),
            Self::OpenWithPayload => f.write_str("OPEN frame carries a payload"),
        }
    }
}

impl Frame {
    /// Decodes one relay message without copying the payload. A CLOSE is
    /// honoured whatever its reason bytes are, so a session never outlives it.
    pub(super) fn decode(message: Bytes) -> Result<Self, FrameError> {
        if message.len() < HEADER_LEN {
            return Err(FrameError::Short(message.len()));
        }
        let session = u32::from_be_bytes([message[1], message[2], message[3], message[4]]);
        match message[0] {
            OPEN if message.len() == HEADER_LEN => Ok(Self::Open(session)),
            OPEN => Err(FrameError::OpenWithPayload),
            DATA => Ok(Self::Data(session, message.slice(HEADER_LEN..))),
            CLOSE => Ok(Self::Close(
                session,
                String::from_utf8_lossy(&message[HEADER_LEN..]).into_owned(),
            )),
            kind => Err(FrameError::UnknownType(kind)),
        }
    }
}

fn header(kind: u8, session: u32) -> [u8; HEADER_LEN] {
    let id = session.to_be_bytes();
    [kind, id[0], id[1], id[2], id[3]]
}

/// A DATA frame whose payload `fill` writes in place into `capacity` bytes and
/// whose length it returns, so ciphertext is never copied into a frame.
pub(super) fn data_with<E>(
    session: u32,
    capacity: usize,
    fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
) -> Result<Vec<u8>, E> {
    let mut frame = vec![0; HEADER_LEN + capacity];
    frame[..HEADER_LEN].copy_from_slice(&header(DATA, session));
    let len = fill(&mut frame[HEADER_LEN..])?;
    frame.truncate(HEADER_LEN + len);
    Ok(frame)
}

pub(super) fn data(session: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&header(DATA, session));
    frame.extend_from_slice(payload);
    frame
}

/// A CLOSE frame; `reason` is cut to [`MAX_CLOSE_REASON`] bytes on a UTF-8
/// boundary.
pub(super) fn close(session: u32, reason: &str) -> Vec<u8> {
    let mut end = reason.len().min(MAX_CLOSE_REASON);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    let mut frame = Vec::with_capacity(HEADER_LEN + end);
    frame.extend_from_slice(&header(CLOSE, session));
    frame.extend_from_slice(&reason.as_bytes()[..end]);
    frame
}

#[cfg(test)]
pub(super) fn open(session: u32) -> Vec<u8> {
    header(OPEN, session).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(bytes: Vec<u8>) -> Result<Frame, FrameError> {
        Frame::decode(Bytes::from(bytes))
    }

    #[test]
    fn frames_round_trip_with_big_endian_session_ids() {
        assert_eq!(decode(open(1)), Ok(Frame::Open(1)));
        assert_eq!(
            open(0x0102_0304),
            [OPEN, 0x01, 0x02, 0x03, 0x04],
            "session ids are big-endian"
        );
        assert_eq!(
            decode(data(u32::MAX, b"ciphertext")),
            Ok(Frame::Data(u32::MAX, Bytes::from_static(b"ciphertext")))
        );
        assert_eq!(decode(data(7, b"")), Ok(Frame::Data(7, Bytes::new())));
        assert_eq!(
            decode(close(9, "revoked")),
            Ok(Frame::Close(9, "revoked".into()))
        );
        assert_eq!(decode(close(9, "")), Ok(Frame::Close(9, String::new())));
    }

    #[test]
    fn data_with_writes_the_payload_in_place() {
        let frame = data_with(3, 16, |out| {
            out[..4].copy_from_slice(b"abcd");
            Ok::<_, ()>(4)
        })
        .unwrap();
        assert_eq!(frame, data(3, b"abcd"));
        assert_eq!(
            data_with(3, 16, |_| Err::<usize, _>("fill failed")),
            Err("fill failed")
        );
    }

    #[test]
    fn close_reason_is_capped_on_a_char_boundary() {
        let long = "é".repeat(100); // 200 bytes of two-byte chars
        let frame = close(1, &long);
        let Ok(Frame::Close(1, reason)) = decode(frame.clone()) else {
            panic!("capped close frame must decode");
        };
        assert_eq!(frame.len() - HEADER_LEN, 122, "123 would split a char");
        assert_eq!(reason, "é".repeat(61));
    }

    #[test]
    fn malformed_frames_are_rejected() {
        assert_eq!(decode(Vec::new()), Err(FrameError::Short(0)));
        assert_eq!(decode(vec![DATA, 0, 0, 1]), Err(FrameError::Short(4)));
        assert_eq!(
            decode(vec![0x04, 0, 0, 0, 1]),
            Err(FrameError::UnknownType(4))
        );
        assert_eq!(
            decode(vec![0x00, 0, 0, 0, 1]),
            Err(FrameError::UnknownType(0))
        );
        assert_eq!(
            decode(vec![OPEN, 0, 0, 0, 1, 0xff]),
            Err(FrameError::OpenWithPayload)
        );
    }

    #[test]
    fn close_with_invalid_utf8_still_closes() {
        assert_eq!(
            decode(vec![CLOSE, 0, 0, 0, 2, 0xff, b'x']),
            Ok(Frame::Close(2, "\u{fffd}x".into()))
        );
    }
}
