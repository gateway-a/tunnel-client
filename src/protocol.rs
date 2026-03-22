use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

pub const HEADER_LEN: usize = 9;
pub const MAX_FRAME_PAYLOAD: usize = 64 * 1024;
pub const CONTROL_STREAM: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameFlag {
    Register = 0x01,
    RegisterAck = 0x02,
    Heartbeat = 0x03,
    HeartbeatAck = 0x04,
    RequestStart = 0x10,
    Data = 0x11,
    RequestEnd = 0x12,
    ResponseStart = 0x20,
    ResponseEnd = 0x21,
    Reset = 0xFF,
}

impl FrameFlag {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Register),
            0x02 => Some(Self::RegisterAck),
            0x03 => Some(Self::Heartbeat),
            0x04 => Some(Self::HeartbeatAck),
            0x10 => Some(Self::RequestStart),
            0x11 => Some(Self::Data),
            0x12 => Some(Self::RequestEnd),
            0x20 => Some(Self::ResponseStart),
            0x21 => Some(Self::ResponseEnd),
            0xFF => Some(Self::Reset),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub stream_id: u32,
    pub flag: FrameFlag,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(stream_id: u32, flag: FrameFlag, payload: impl Into<Bytes>) -> Self {
        Self { stream_id, flag, payload: payload.into() }
    }

    pub fn control(flag: FrameFlag, payload: impl Into<Bytes>) -> Self {
        Self::new(CONTROL_STREAM, flag, payload)
    }

    pub fn register(token: &str, name: &str) -> Self {
        let payload = format!("{}\0{}", token, name);
        Self::control(FrameFlag::Register, payload.into_bytes())
    }

    pub fn register_ack(success: bool, msg: &str) -> Self {
        let mut buf = BytesMut::with_capacity(1 + msg.len());
        buf.put_u8(if success { 1 } else { 0 });
        buf.extend_from_slice(msg.as_bytes());
        Self::control(FrameFlag::RegisterAck, buf.freeze())
    }

    pub fn heartbeat() -> Self {
        Self::control(FrameFlag::Heartbeat, Bytes::new())
    }

    pub fn heartbeat_ack() -> Self {
        Self::control(FrameFlag::HeartbeatAck, Bytes::new())
    }

    pub fn request_start(stream_id: u32, payload: Bytes) -> Self {
        Self::new(stream_id, FrameFlag::RequestStart, payload)
    }

    pub fn data(stream_id: u32, payload: Bytes) -> Self {
        Self::new(stream_id, FrameFlag::Data, payload)
    }

    pub fn request_end(stream_id: u32) -> Self {
        Self::new(stream_id, FrameFlag::RequestEnd, Bytes::new())
    }

    pub fn response_start(stream_id: u32, payload: Bytes) -> Self {
        Self::new(stream_id, FrameFlag::ResponseStart, payload)
    }

    pub fn response_end(stream_id: u32) -> Self {
        Self::new(stream_id, FrameFlag::ResponseEnd, Bytes::new())
    }

    pub fn reset(stream_id: u32) -> Self {
        Self::new(stream_id, FrameFlag::Reset, Bytes::new())
    }
}

pub struct FrameCodec;

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < HEADER_LEN {
            return Ok(None);
        }

        let stream_id = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
        let flag_byte = src[4];
        let length = u32::from_be_bytes([src[5], src[6], src[7], src[8]]) as usize;

        if length > MAX_FRAME_PAYLOAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame payload too large",
            ));
        }

        if src.len() < HEADER_LEN + length {
            src.reserve(HEADER_LEN + length - src.len());
            return Ok(None);
        }

        let flag = FrameFlag::from_u8(flag_byte).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown frame flag")
        })?;

        src.advance(HEADER_LEN);
        let payload = src.split_to(length).freeze();

        Ok(Some(Frame { stream_id, flag, payload }))
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload_len = item.payload.len();
        if payload_len > MAX_FRAME_PAYLOAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame payload too large",
            ));
        }

        dst.reserve(HEADER_LEN + payload_len);
        dst.put_u32(item.stream_id);
        dst.put_u8(item.flag as u8);
        dst.put_u32(payload_len as u32);
        dst.extend_from_slice(&item.payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_codec_roundtrip() {
        let mut codec = FrameCodec;
        let frame = Frame::new(42, FrameFlag::Data, Bytes::from_static(b"hello"));

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        assert_eq!(buf.len(), HEADER_LEN + 5);

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.flag, FrameFlag::Data);
        assert_eq!(&decoded.payload[..], b"hello");
    }

    #[test]
    fn frame_codec_partial() {
        let mut codec = FrameCodec;
        let mut buf = BytesMut::from(&[0u8; 5][..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn frame_codec_too_large() {
        let mut codec = FrameCodec;
        let mut buf = BytesMut::new();
        buf.put_u32(1);
        buf.put_u8(0x11);
        buf.put_u32(MAX_FRAME_PAYLOAD as u32 + 1);
        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn register_frame_format() {
        let frame = Frame::register("tok123", "my-app");
        assert_eq!(frame.stream_id, CONTROL_STREAM);
        assert_eq!(frame.flag, FrameFlag::Register);
        let s = String::from_utf8(frame.payload.to_vec()).unwrap();
        let parts: Vec<&str> = s.split('\0').collect();
        assert_eq!(parts, vec!["tok123", "my-app"]);
    }

    #[test]
    fn register_ack_format() {
        let frame = Frame::register_ack(true, "ok");
        assert_eq!(frame.payload[0], 1);
        assert_eq!(&frame.payload[1..], b"ok");

        let frame = Frame::register_ack(false, "denied");
        assert_eq!(frame.payload[0], 0);
        assert_eq!(&frame.payload[1..], b"denied");
    }

    #[test]
    fn heartbeat_frames() {
        let hb = Frame::heartbeat();
        assert_eq!(hb.stream_id, CONTROL_STREAM);
        assert_eq!(hb.flag, FrameFlag::Heartbeat);
        assert!(hb.payload.is_empty());

        let ack = Frame::heartbeat_ack();
        assert_eq!(ack.flag, FrameFlag::HeartbeatAck);
    }

    #[test]
    fn flag_roundtrip() {
        for v in [0x01, 0x02, 0x03, 0x04, 0x10, 0x11, 0x12, 0x20, 0x21, 0xFF] {
            let flag = FrameFlag::from_u8(v).unwrap();
            assert_eq!(flag as u8, v);
        }
        assert!(FrameFlag::from_u8(0x00).is_none());
        assert!(FrameFlag::from_u8(0x50).is_none());
    }
}
