use std::io::{self, Write};

use base64::Engine;
use serde::Serialize;

use crate::api::ApiStream;
use crate::ipc::is_connection_closed_error;

const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

// Each frame is three big-endian u32 lengths, JSON metadata, raw data, then raw history.
pub(super) fn write_frame(
    stream: &mut impl Write,
    metadata: &impl Serialize,
    data: &[u8],
    history: &[u8],
) -> io::Result<()> {
    let metadata = serde_json::to_vec(metadata)?;
    if metadata.len() > MAX_METADATA_BYTES
        || data.len().saturating_add(history.len()) > MAX_PAYLOAD_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "binary pane frame exceeds limit",
        ));
    }
    for length in [metadata.len(), data.len(), history.len()] {
        stream.write_all(&(length as u32).to_be_bytes())?;
    }
    stream.write_all(&metadata)?;
    stream.write_all(data)?;
    stream.write_all(history)?;
    stream.flush()
}

pub(super) fn write_control(stream: &mut ApiStream, line: &str, binary: bool) -> io::Result<()> {
    if binary {
        let metadata: serde_json::Value = serde_json::from_str(line)?;
        write_frame(stream, &metadata, &[], &[])
    } else {
        super::write_text_line_allow_disconnect(stream, line)
    }
}

pub(super) fn forward_json(stream: &mut ApiStream, line: &str, binary: bool) -> io::Result<bool> {
    let result = if binary {
        let mut metadata: serde_json::Value = serde_json::from_str(line)?;
        let decode = |value: Option<serde_json::Value>| -> io::Result<Vec<u8>> {
            match value {
                None => Ok(Vec::new()),
                Some(serde_json::Value::String(encoded)) => {
                    base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
                }
                Some(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid binary pane payload",
                )),
            }
        };
        let object = metadata
            .as_object_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid pane metadata"))?;
        let data = decode(object.remove("data_b64"))?;
        let history = decode(object.remove("history_b64"))?;
        write_frame(stream, &metadata, &data, &history)
    } else {
        return super::emit_line_to_client(stream, line);
    };
    match result {
        Ok(()) => Ok(true),
        Err(error) if is_connection_closed_error(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
pub(super) fn read_frame_for_test(
    reader: &mut impl std::io::Read,
) -> (serde_json::Value, Vec<u8>, Vec<u8>) {
    let mut header = [0; 12];
    reader.read_exact(&mut header).unwrap();
    let lengths: Vec<_> = header
        .chunks_exact(4)
        .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()) as usize)
        .collect();
    assert!(lengths[0] <= MAX_METADATA_BYTES);
    assert!(lengths[1].saturating_add(lengths[2]) <= MAX_PAYLOAD_BYTES);
    let mut metadata = vec![0; lengths[0]];
    let mut data = vec![0; lengths[1]];
    let mut history = vec![0; lengths[2]];
    reader.read_exact(&mut metadata).unwrap();
    reader.read_exact(&mut data).unwrap();
    reader.read_exact(&mut history).unwrap();
    (serde_json::from_slice(&metadata).unwrap(), data, history)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_arbitrary_bytes_and_history_without_base64() {
        let mut wire = Vec::new();
        let metadata = serde_json::json!({"frame":"reset","seq":7,"epoch":3,"cols":80,"rows":24});
        write_frame(&mut wire, &metadata, b"\0\n\xff", b"old\n").unwrap();
        let lengths: Vec<_> = wire[..12]
            .chunks_exact(4)
            .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()) as usize)
            .collect();
        assert_eq!(&lengths[1..], &[3, 4]);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&wire[12..12 + lengths[0]]).unwrap(),
            metadata
        );
        assert_eq!(&wire[12 + lengths[0]..], b"\0\n\xffold\n");
    }

    #[test]
    fn rejects_oversize_metadata_before_writing() {
        let mut wire = Vec::new();
        assert!(write_frame(&mut wire, &"x".repeat(MAX_METADATA_BYTES), &[], &[]).is_err());
        assert!(wire.is_empty());
    }
}
