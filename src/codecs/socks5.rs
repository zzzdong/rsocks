use bytes::{BufMut, Bytes, BytesMut};
use nom::Offset;
use tokio::codec::*;

use crate::errors::*;
use crate::parser::socks5::*;
use crate::proto::socks5::*;
use crate::proto::WriteBuf;

#[derive(Debug)]
pub struct HandshakeCodec;

impl Decoder for HandshakeCodec {
    type Item = HandshakeRequest;
    type Error = RsocksError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<HandshakeRequest>, RsocksError> {
        let (consumed, f) = match parse_handshake_request(buf) {
            Ok((i, packet)) => (buf.offset(i), packet),
            Err(e) => {
                if e.is_incomplete() {
                    return Ok(None);
                } else {
                    return Err(parser_error("parse_handshake_request"));
                }
            }
        };

        trace!("socks5 decode; frame={:?}", f);
        buf.split_to(consumed);

        Ok(Some(f))
    }
}

impl Encoder for HandshakeCodec {
    type Item = HandshakeResponse;
    type Error = RsocksError;

    fn encode(&mut self, packet: HandshakeResponse, buf: &mut BytesMut) -> Result<(), RsocksError> {
        packet.write_buf(buf);
        Ok(())
    }
}

#[derive(Debug)]
pub struct CmdCodec;

impl Decoder for CmdCodec {
    type Item = CmdRequest;
    type Error = RsocksError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<CmdRequest>, RsocksError> {
        let (consumed, f) = match parse_cmd_request(buf) {
            Ok((i, packet)) => (buf.offset(i), packet),
            Err(e) => {
                if e.is_incomplete() {
                    return Ok(None);
                } else {
                    return Err(parser_error(&format!("parse_cmd_request, {:?}", e)));
                }
            }
        };

        trace!("socks5 decode; frame={:?}", f);
        buf.split_to(consumed);

        Ok(Some(f))
    }
}

impl Encoder for CmdCodec {
    type Item = CmdResponse;
    type Error = RsocksError;

    fn encode(&mut self, packet: CmdResponse, buf: &mut BytesMut) -> Result<(), RsocksError> {
        packet.write_buf(buf);
        Ok(())
    }
}

pub enum SocksRequest {
    Handshake(HandshakeRequest),
    Cmd(CmdRequest),
    Stream(Bytes),
}

pub enum SocksResponse {
    Handshake(HandshakeResponse),
    Cmd(CmdResponse),
    Stream(Bytes),
}

impl WriteBuf for SocksResponse {
    fn write_buf(&self, buf: &mut BytesMut) {
        match self {
            SocksResponse::Handshake(h) => h.write_buf(buf),
            SocksResponse::Cmd(c) => c.write_buf(buf),
            SocksResponse::Stream(s) => {
                let len = s.len();
                if buf.remaining_mut() < len {
                    buf.reserve(len);
                }
                buf.put(s);
            }
        }
    }
}

#[derive(Debug)]
enum SocksState {
    Handshake,
    Connected,
    Streaming,
}

#[derive(Debug)]
pub struct SocksCodec {
    state: SocksState,
}

impl SocksCodec {
    pub fn new() -> SocksCodec {
        SocksCodec {
            state: SocksState::Handshake,
        }
    }

    pub fn set_connected(&mut self) {
        self.state = SocksState::Connected;
    }

    pub fn set_streaming(&mut self) {
        self.state = SocksState::Streaming;
    }
}

impl Decoder for SocksCodec {
    type Item = SocksRequest;
    type Error = RsocksError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<SocksRequest>, RsocksError> {
        match self.state {
            SocksState::Handshake => {
                let (consumed, f) = match parse_handshake_request(buf) {
                    Ok((i, packet)) => (buf.offset(i), packet),
                    Err(e) => {
                        if e.is_incomplete() {
                            return Ok(None);
                        } else {
                            return Err(parser_error("parse_handshake_request"));
                        }
                    }
                };

                trace!("socks5 decode; frame={:?}", f);
                buf.split_to(consumed);

                self.set_connected();
                Ok(Some(SocksRequest::Handshake(f)))
            }
            SocksState::Connected => {
                let (consumed, f) = match parse_cmd_request(buf) {
                    Ok((i, packet)) => (buf.offset(i), packet),
                    Err(e) => {
                        if e.is_incomplete() {
                            return Ok(None);
                        } else {
                            return Err(parser_error(&format!("parse_cmd_request, {:?}", e)));
                        }
                    }
                };
                trace!("socks5 decode; frame={:?}", f);
                buf.split_to(consumed);

                self.set_streaming();
                Ok(Some(SocksRequest::Cmd(f)))
            }
            SocksState::Streaming => {
                let len = buf.len();

                if len == 0 {
                    Ok(None)
                } else {
                    trace!("streaming got {}", len);
                    let bs = Bytes::from(buf.to_vec());
                    buf.split_to(len);
                    Ok(Some(SocksRequest::Stream(bs)))
                }
            }
        }
    }
}

impl Encoder for SocksCodec {
    type Item = SocksResponse;
    type Error = RsocksError;

    fn encode(&mut self, packet: SocksResponse, buf: &mut BytesMut) -> Result<(), RsocksError> {
        packet.write_buf(buf);
        Ok(())
    }
}
