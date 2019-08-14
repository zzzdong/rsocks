#![allow(dead_code)]

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
// use nom::Err;
// use nom::{be_u16, be_u8, count, do_parse, named, tag, IResult};

use nom::IResult;
use nom::{
    branch::alt,
    bytes::streaming::{tag, take},
    character::streaming::one_of,
    multi::count,
    number::complete::{be_u16, be_u8},
};

pub mod consts {
    pub const SOCKS5_ERROR_UNSUPPORTED_VERSION: u32 = 501;
    pub const SOCKS5_ERROR_RESERVERD: u32 = 502;
    pub const SOCKS5_ERROR_UNKNOWN_ADDRTYPE: u32 = 503;

    pub const SOCKS5_VERSION: u8 = 0x05;
    pub const SOCKS5_RESERVED: u8 = 0x00;

    pub const SOCKS5_AUTH_METHOD_NONE: u8 = 0x00;
    pub const SOCKS5_AUTH_METHOD_GSSAPI: u8 = 0x01;
    pub const SOCKS5_AUTH_METHOD_PASSWORD: u8 = 0x02;
    pub const SOCKS5_AUTH_METHOD_NOTACCEPTABLE: u8 = 0xff;

    pub const SOCKS5_CMD_TCP_CONNECT: u8 = 0x01;
    pub const SOCKS5_CMD_TCP_BIND: u8 = 0x02;
    pub const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;

    pub const SOCKS5_ADDR_IPV4: u8 = 0x01;
    pub const SOCKS5_ADDR_DOMAINNAME: u8 = 0x03;
    pub const SOCKS5_ADDR_IPV6: u8 = 0x04;

    pub const SOCKS5_REPLY_SUCCEEDED: u8 = 0x00;
    pub const SOCKS5_REPLY_GENERAL_FAILURE: u8 = 0x01;
    pub const SOCKS5_REPLY_CONNETCTION_NOT_ALLOWED: u8 = 0x02;
    pub const SOCKS5_REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
    pub const SOCKS5_REPLY_HOST_UNREACHABLE: u8 = 0x04;
    pub const SOCKS5_REPLY_CONNECTION_REFUSED: u8 = 0x05;
    pub const SOCKS5_REPLY_TTL_EXPIRED: u8 = 0x06;
    pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

pub trait WriteBuf {
    fn write_buf(&self, buf: &mut BytesMut);
}

#[derive(Clone, Debug, PartialEq)]
pub enum Version {
    V5,
    Unknown(u8),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    TCPConnect,
    TCPBind,
    UDPAssociate,
    OtherCommand(u8),
}

impl Command {
    fn from_byte(c: u8) -> Command {
        match c {
            consts::SOCKS5_CMD_TCP_CONNECT => Command::TCPConnect,
            consts::SOCKS5_CMD_TCP_BIND => Command::TCPBind,
            consts::SOCKS5_CMD_UDP_ASSOCIATE => Command::UDPAssociate,
            _ => Command::OtherCommand(c),
        }
    }

    fn as_byte(&self) -> u8 {
        match *self {
            Command::TCPConnect => consts::SOCKS5_CMD_TCP_CONNECT,
            Command::TCPBind => consts::SOCKS5_CMD_TCP_BIND,
            Command::UDPAssociate => consts::SOCKS5_CMD_UDP_ASSOCIATE,
            Command::OtherCommand(c) => c as u8,
        }
    }
}

impl From<u8> for Command {
    fn from(c: u8) -> Command {
        Command::from_byte(c)
    }
}

impl From<Command> for u8 {
    fn from(cmd: Command) -> u8 {
        cmd.as_byte()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Reply {
    Succeeded,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreadchable,
    HostUnreachable,
    ConnectionRefused,
    TTLExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    OtherReply(u8),
}

impl Reply {
    fn from_byte(r: u8) -> Reply {
        match r {
            consts::SOCKS5_REPLY_SUCCEEDED => Reply::Succeeded,
            consts::SOCKS5_REPLY_GENERAL_FAILURE => Reply::GeneralFailure,
            consts::SOCKS5_REPLY_CONNETCTION_NOT_ALLOWED => Reply::ConnectionNotAllowed,
            consts::SOCKS5_REPLY_NETWORK_UNREACHABLE => Reply::NetworkUnreadchable,
            consts::SOCKS5_REPLY_HOST_UNREACHABLE => Reply::HostUnreachable,
            consts::SOCKS5_REPLY_CONNECTION_REFUSED => Reply::ConnectionRefused,
            consts::SOCKS5_REPLY_TTL_EXPIRED => Reply::TTLExpired,
            consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED => Reply::CommandNotSupported,
            consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => Reply::AddressTypeNotSupported,
            _ => Reply::OtherReply(r),
        }
    }

    fn as_byte(&self) -> u8 {
        match *self {
            Reply::Succeeded => consts::SOCKS5_REPLY_SUCCEEDED,
            Reply::GeneralFailure => consts::SOCKS5_REPLY_GENERAL_FAILURE,
            Reply::ConnectionNotAllowed => consts::SOCKS5_REPLY_CONNETCTION_NOT_ALLOWED,
            Reply::NetworkUnreadchable => consts::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            Reply::HostUnreachable => consts::SOCKS5_REPLY_HOST_UNREACHABLE,
            Reply::ConnectionRefused => consts::SOCKS5_REPLY_CONNECTION_REFUSED,
            Reply::TTLExpired => consts::SOCKS5_REPLY_TTL_EXPIRED,
            Reply::CommandNotSupported => consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            Reply::AddressTypeNotSupported => consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
            Reply::OtherReply(r) => r,
        }
    }
}

impl From<u8> for Reply {
    fn from(r: u8) -> Reply {
        Reply::from_byte(r)
    }
}

impl From<Reply> for u8 {
    fn from(reply: Reply) -> u8 {
        reply.as_byte()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum AddressType {
    IPv4,
    IPv6,
    Domain,
    Unknown(u8),
}

impl AddressType {
    fn from_byte(b: u8) -> AddressType {
        match b {
            consts::SOCKS5_ADDR_IPV4 => AddressType::IPv4,
            consts::SOCKS5_ADDR_IPV6 => AddressType::IPv6,
            consts::SOCKS5_ADDR_DOMAINNAME => AddressType::Domain,
            _ => AddressType::Unknown(b),
        }
    }
}

impl From<u8> for AddressType {
    fn from(t: u8) -> AddressType {
        AddressType::from_byte(t)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Address {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
    DomainName(String),
    Unknown(u8),
}

impl Address {
    pub fn write_to(&self, buf: &mut BytesMut) {
        match self {
            Address::IPv4(ip) => {
                buf.extend_from_slice(&[consts::SOCKS5_ADDR_IPV4]);
                buf.extend_from_slice(&ip.octets());
            }
            Address::IPv6(ip) => {
                buf.extend_from_slice(&[consts::SOCKS5_ADDR_IPV6]);
                buf.extend_from_slice(&ip.octets());
            }
            Address::DomainName(dmname) => {
                buf.extend_from_slice(&[consts::SOCKS5_ADDR_DOMAINNAME, dmname.len() as u8]);
                buf.extend_from_slice(dmname.as_bytes());
            }
            Address::Unknown(_t) => {}
        };
    }
}

impl WriteBuf for Address {
    fn write_buf(&self, buf: &mut BytesMut) {
        self.write_to(buf);
    }
}

/// SOCKS5 handshake request packet
///
/// ```plain
/// +----+----------+----------+
/// |VER | NMETHODS | METHODS  |
/// +----+----------+----------+
/// | 5  |    1     | 1 to 255 |
/// +----+----------+----------|
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct HandshakeRequest {
    pub methods: Vec<u8>,
}

impl HandshakeRequest {
    pub fn new(methods: Vec<u8>) -> HandshakeRequest {
        HandshakeRequest { methods }
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.put_slice(&[consts::SOCKS5_VERSION, self.methods.len() as u8]);
        buf.put_slice(&self.methods);
    }
}

impl WriteBuf for HandshakeRequest {
    fn write_buf(&self, buf: &mut BytesMut) {
        self.write_to(buf);
    }
}

/// SOCKS5 handshake response packet
///
/// ```plain
/// +----+--------+
/// |VER | METHOD |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct HandshakeResponse {
    pub chosen_method: u8,
}

impl HandshakeResponse {
    pub fn new(method: u8) -> HandshakeResponse {
        HandshakeResponse {
            chosen_method: method,
        }
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.put_slice(&[consts::SOCKS5_VERSION, self.chosen_method]);
    }
}

impl WriteBuf for HandshakeResponse {
    fn write_buf(&self, buf: &mut BytesMut) {
        self.write_to(buf);
    }
}

/// TCP request header after handshake
///
/// ```plain
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct CmdRequest {
    /// SOCKS5 command
    pub command: Command,
    /// Remote address
    pub address: Address,
    /// Remot port
    pub port: u16,
}

impl CmdRequest {
    pub fn new(cmd: Command, addr: Address, port: u16) -> CmdRequest {
        CmdRequest {
            command: cmd,
            address: addr,
            port,
        }
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.put_slice(&[
            consts::SOCKS5_VERSION,
            self.command.as_byte(),
            consts::SOCKS5_RESERVED,
        ]);
        self.address.write_buf(buf);
        buf.put_u16_be(self.port);
    }
}

impl WriteBuf for CmdRequest {
    fn write_buf(&self, buf: &mut BytesMut) {
        self.write_to(buf);
    }
}

/// TCP response header
///
/// ```plain
/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct CmdResponse {
    /// SOCKS5 reply
    pub reply: Reply,
    /// Reply address
    pub address: Address,
    pub port: u16,
}

impl CmdResponse {
    pub fn new(reply: Reply, address: Address, port: u16) -> CmdResponse {
        CmdResponse {
            reply,
            address,
            port,
        }
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.put_slice(&[
            consts::SOCKS5_VERSION,
            self.reply.as_byte(),
            consts::SOCKS5_RESERVED,
        ]);
        self.address.write_buf(buf);
        buf.put_u16_be(self.port);
    }
}

impl WriteBuf for CmdResponse {
    fn write_buf(&self, buf: &mut BytesMut) {
        self.write_to(buf);
    }
}

pub(crate) fn parse_handshake_request(input: &[u8]) -> IResult<&[u8], HandshakeRequest> {
    let (i, _ver) = check_version(input)?;
    let (i, method_count) = be_u8(i)?;
    let (i, methods) = count(be_u8, method_count as usize)(i)?;

    Ok((i, HandshakeRequest { methods }))
}

pub(crate) fn parse_cmd_request(input: &[u8]) -> IResult<&[u8], CmdRequest> {
    let (i, _ver) = check_version(input)?;
    let (i, cmd) = request_cmd(i)?;
    let (i, _) = reserver_byte(i)?;
    let (i, addr) = read_addr(i)?;
    let (i, port) = be_u16(i)?;

    Ok((i, CmdRequest::new(cmd, addr, port)))
}

fn request_cmd(input: &[u8]) -> IResult<&[u8], Command> {
    let (input, cmd) = take(1usize)(input)?;
    let cmd = match cmd[0] {
        consts::SOCKS5_CMD_TCP_CONNECT => Command::TCPConnect,
        consts::SOCKS5_CMD_TCP_BIND =>  Command::TCPBind,
        consts::SOCKS5_CMD_UDP_ASSOCIATE => Command::UDPAssociate,
        c =>  Command::OtherCommand(c),
    };

    Ok((input, cmd))
}

fn read_ipv4(input: &[u8]) -> IResult<&[u8], Address> {
    let (i, raw) = take(4usize)(input)?;
    Ok((
        i,
        Address::IPv4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
    ))
}

fn read_ipv6(input: &[u8]) -> IResult<&[u8], Address> {
    let (i, raw) = count(be_u16, 8)(input)?;
    Ok((
        i,
        Address::IPv6(Ipv6Addr::new(
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        )),
    ))
}

fn read_domain(input: &[u8]) -> IResult<&[u8], Address> {
    let (i, len) = be_u8(input)?;
    let (i, s) = take(len)(i)?;
    Ok((
        i,
        Address::DomainName(String::from_utf8_lossy(s).to_string()),
    ))
}

fn read_addr_type(i: &[u8]) -> IResult<&[u8], char> {
    one_of([
        consts::SOCKS5_ADDR_IPV4,
        consts::SOCKS5_ADDR_IPV6,
        consts::SOCKS5_ADDR_DOMAINNAME,
    ])(i)
}

fn read_addr(input: &[u8]) -> IResult<&[u8], Address> {
    let (i, t) = read_addr_type(input)?;
    let t = AddressType::from_byte(t as u8);

    match t {
        AddressType::IPv4 => read_ipv4(i),
        AddressType::IPv6 => read_ipv6(i),
        AddressType::Domain => read_domain(i),
        AddressType::Unknown(t) => Ok((i, Address::Unknown(t))),
    }
}

fn check_version(input: &[u8]) -> IResult<&[u8], Version> {
    tag([consts::SOCKS5_VERSION])(input).map(|(i, _v)| (i, Version::V5))
}

fn reserver_byte(input: &[u8]) -> IResult<&[u8], u8> {
    tag([consts::SOCKS5_RESERVED])(input).map(|(i, b)| (i, b[0]))
}

fn unknow_cmd(input: &[u8]) -> IResult<&[u8], Command> {
    Ok((input, Command::OtherCommand(input[0])))
}

fn v5_version(input: &[u8]) -> IResult<&[u8], Version> {
    tag([consts::SOCKS5_VERSION])(input).map(|(i, _v)| (i, Version::V5))
}

fn unknown_version(input: &[u8]) -> IResult<&[u8], Version> {
    take(1usize)(input).map(|(i, v)| (i, Version::Unknown(v[0])))
}

fn socks_version(input: &[u8]) -> IResult<&[u8], Version> {
    alt((v5_version, unknown_version))(input)
}

#[cfg(test)]
mod test {
    use super::consts::*;
    use super::*;

    mod handshakereq {
        use super::*;

        #[test]
        fn correct() {
            let empty_buf = &vec![][..];

            let req_ok = HandshakeRequest::new(vec![SOCKS5_AUTH_METHOD_NONE]);

            // correct HandshakeRequest
            let buf = vec![0x05, 0x01, 0x00];
            let req = parse_handshake_request(&buf);
            assert_eq!(req, Ok((empty_buf, req_ok)));

            // correct HandshakeRequest
            let req_ok =
                HandshakeRequest::new(vec![SOCKS5_AUTH_METHOD_NONE, SOCKS5_AUTH_METHOD_PASSWORD]);
            let buf = vec![0x05, 0x02, 0x00, 0x02];
            let req = parse_handshake_request(&buf);
            assert_eq!(req, Ok((empty_buf, req_ok)));
        }

        #[test]
        fn incorrect_socks_verion() {
            // incorrect socks version
            let buf = vec![0x04, 0x01, 0x02];
            let req = parse_handshake_request(&buf);
            assert_eq!(
                req,
                Err(nom::Err::Error((&buf[..], nom::error::ErrorKind::Tag)))
            );
        }

        #[test]
        fn incorrect_buf_len() {
            let empty_buf = &vec![][..];

            // incorrect buf len
            let buf = vec![0x05, 0x01];
            let req = parse_handshake_request(&buf);
            assert_eq!(
                req,
                Err(nom::Err::Error((empty_buf, nom::error::ErrorKind::Eof)))
            );

            let buf = vec![0x05, 0x05, 0x01];
            let req = parse_handshake_request(&buf);
            assert_eq!(
                req,
                Err(nom::Err::Error((empty_buf, nom::error::ErrorKind::Eof)))
            );
        }
    }

    mod tcprequesthdr {
        use super::*;

        #[test]
        fn correct() {
            let empty_buf = &vec![][..];

            let req_ok = CmdRequest::new(
                Command::TCPConnect,
                Address::IPv4("127.0.0.1".parse().unwrap()),
                1080 as u16,
            );
            let buf = vec![0x05, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x04, 0x38];
            let req = parse_cmd_request(&buf);
            assert_eq!(req, Ok((empty_buf, req_ok)));

            let req_ok = CmdRequest::new(
                Command::TCPConnect,
                Address::IPv6("2001:0DB8:AC10:FE01::".parse().unwrap()),
                1080 as u16,
            );
            let buf = vec![
                0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0xac, 0x10, 0xfe, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x38,
            ];
            let req = parse_cmd_request(&buf);
            assert_eq!(req, Ok((empty_buf, req_ok)));

            let req_ok = CmdRequest::new(
                Command::TCPConnect,
                Address::DomainName("www.google.com".to_string()),
                1080 as u16,
            );
            let buf = vec![
                0x05, 0x01, 0x00, 0x03, 0x0e, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
                0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x04, 0x38,
            ];
            let req = parse_cmd_request(&buf);
            assert_eq!(req, Ok((empty_buf, req_ok)));
        }

        #[test]
        fn incorrect_addr_type() {
            let buf = vec![0x05, 0x01, 0x00, 0x02, 0x7f, 0x00, 0x00, 0x01, 0x04, 0x38];
            let req = parse_cmd_request(&buf);
            assert_eq!(
                req,
                Err(nom::Err::Error((&buf[3..], nom::error::ErrorKind::OneOf)))
            );
        }
    }
}
