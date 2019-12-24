#![allow(dead_code)]

use std::net::{Ipv4Addr, Ipv6Addr};

use nom::IResult;
use nom::{
    branch::alt,
    bytes::streaming::{tag, take},
    character::streaming::one_of,
    multi::count,
    number::complete::{be_u16, be_u8},
};

use crate::proto::socks5::*;

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
        consts::SOCKS5_CMD_TCP_BIND => Command::TCPBind,
        consts::SOCKS5_CMD_UDP_ASSOCIATE => Command::UDPAssociate,
        c => Command::OtherCommand(c),
    };

    Ok((input, cmd))
}

pub(crate) fn read_ipv4(input: &[u8]) -> IResult<&[u8], Address> {
    let (i, raw) = take(4usize)(input)?;
    Ok((
        i,
        Address::IPv4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
    ))
}

pub(crate) fn read_ipv6(input: &[u8]) -> IResult<&[u8], Address> {
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
