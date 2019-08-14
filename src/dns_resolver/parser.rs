use std::net::{Ipv4Addr, Ipv6Addr};

use nom::bits::{bits, bytes, complete::take as take_bits};
use nom::bytes::complete::take as take_bytes;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::sequence::tuple;
use nom::{Err, IResult};

use crate::dns_resolver::proto::*;
use crate::errors::RsocksError;

fn bit_flag(b: u8) -> bool {
    b != 0
}

fn take_4_bits(input: &[u8]) -> IResult<&[u8], u64> {
    bits::<_, _, (_, _), _, _>(take_bits(4usize))(input)
}

pub struct Parser<'a> {
    packet: &'a [u8],
}

impl<'a> Parser<'a> {
    pub fn new(input: &'a [u8]) -> Parser {
        Parser { packet: input }
    }

    pub fn parse(&self) -> Result<Message, RsocksError> {
        match parse_message(self.packet) {
            Ok((_, m)) => Ok(m),
            Err(e) => Err(RsocksError::ParserError {
                msg: format!("dns parser error: {:?}", e),
            }),
        }
    }
}

fn parse_flag(input: &[u8]) -> IResult<&[u8], Flag> {
    let (input, (qr, op, aa, tc, rd, ra, z, rc)) = bits::<_, _, (_, _), _, _>(tuple((
        take_bits(1usize),
        take_bits(4usize),
        take_bits(1usize),
        take_bits(1usize),
        take_bits(1usize),
        take_bits(1usize),
        take_bits(3usize),
        take_bits(4usize),
    )))(input)?;
    let _: u8 = z;

    let flag = Flag {
        qr: QR::from_byte(qr),
        op: OpCode::from_byte(op),
        aa: bit_flag(aa),
        tc: bit_flag(tc),
        rd: bit_flag(rd),
        ra: bit_flag(ra),
        rc: RCode::from_byte(rc),
    };
    Ok((input, flag))
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (i, id) = be_u16(input)?;
    let (i, flag) = parse_flag(i)?;
    let (i, qd_count) = be_u16(i)?;
    let (i, an_count) = be_u16(i)?;
    let (i, ns_count) = be_u16(i)?;
    let (i, ar_count) = be_u16(i)?;

    Ok((
        i,
        Header {
            id,
            flag,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        },
    ))
}

fn parse_question_section<'a>(input: &'a [u8], packet: &'a [u8]) -> IResult<&'a [u8], Question> {
    let (input, qname) = parse_domain_name(input, packet)?;
    let (input, qtype) = be_u16(input)?;
    let (input, qclass) = be_u16(input)?;

    Ok((
        input,
        Question::new(qname, QType::from(qtype), QClass::from(qclass)),
    ))
}

fn parse_resource_record<'a>(
    input: &'a [u8],
    packet: &'a [u8],
) -> IResult<&'a [u8], ResourceRecord> {
    let (input, name) = parse_domain_name(input, packet)?;
    let (input, type_) = be_u16(input)?;
    let (input, class) = be_u16(input)?;
    let (input, ttl) = be_u32(input)?;
    let (input, rdlen) = be_u16(input)?;
    let (input, rdata) = take_bytes(rdlen as usize)(input)?;

    let type_ = QType::from(type_);
    let class = QClass::from(class);

    let rdata = match type_ {
        QType::A => {
            let (_, buf) = take_bytes(4usize)(rdata)?;
            let mut ip: [u8; 4] = Default::default();
            ip.copy_from_slice(buf);
            RDATA::A(Ipv4Addr::from(ip))
        }
        QType::AAA => {
            let (_, buf) = take_bytes(16usize)(rdata)?;
            let mut ip: [u8; 16] = Default::default();
            ip.copy_from_slice(buf);
            RDATA::AAA(Ipv6Addr::from(ip))
        }
        QType::CNAME => {
            let (_, name) = parse_domain_name(rdata, packet)?;
            RDATA::CNAME(name)
        }
        QType::NS => {
            let (_, name) = parse_domain_name(rdata, packet)?;
            RDATA::NS(name)
        }
        _ => RDATA::Unknown(rdata.to_vec()),
    };

    let rr = ResourceRecord {
        name,
        type_,
        class,
        ttl,
        rdlen,
        rdata,
    };

    Ok((input, rr))
}

fn parse_domain_name_labels<'a>(
    input: &'a [u8],
    packet: &'a [u8],
) -> IResult<&'a [u8], Vec<&'a [u8]>> {
    let mut rest = input;
    let mut parts = Vec::new();

    loop {
        let (i, len) = be_u8(rest)?;
        if len == 0 {
            rest = i;
            break;
        } else if len & 0xC0 == 0xC0 {
            // domain compress
            let (input, offset) = be_u16(rest)?;
            let offset = (offset - 49152) as usize;
            let (_, labels) = parse_domain_name_labels(&packet[offset..], packet)?;
            rest = input;
            parts.extend(labels);
            break;
        } else {
            let (input, len) = be_u8(rest)?;
            let (input, label) = take_bytes(len)(input)?;
            parts.push(label);
            rest = input;
        }
    }

    Ok((rest, parts))
}

fn parse_domain_name<'a>(input: &'a [u8], packet: &'a [u8]) -> IResult<&'a [u8], String> {
    let (input, labels) = parse_domain_name_labels(input, packet)?;

    let labels: Vec<std::borrow::Cow<'_, str>> =
        labels.iter().map(|l| String::from_utf8_lossy(l)).collect();

    let domain = labels.join(".");

    Ok((input, domain))
}

fn parse_message(input: &[u8]) -> IResult<&[u8], Message> {
    let packet = input;
    let mut rest: &[u8];

    let (input, header) = parse_header(packet).unwrap();

    rest = input;

    let mut qds = Vec::new();
    for _ in 0..header.qd_count {
        let (input, qd) = parse_question_section(rest, packet).unwrap();
        rest = input;
        qds.push(qd);
    }

    let mut ans = Vec::new();
    for _ in 0..header.an_count {
        let (input, an) = parse_resource_record(rest, packet).unwrap();
        rest = input;
        ans.push(an);
    }

    let mut nss = Vec::new();
    for _ in 0..header.ns_count {
        let (input, ns) = parse_resource_record(rest, packet).unwrap();
        rest = input;
        nss.push(ns);
    }

    let mut ars = Vec::new();
    for _ in 0..header.ar_count {
        let (input, ar) = parse_resource_record(rest, packet).unwrap();
        rest = input;
        ars.push(ar);
    }

    Ok((
        rest,
        Message {
            header,
            question: qds,
            answer: ans,
            authority: nss,
            additional: ars,
        },
    ))
}

mod test {
    use super::*;

    #[test]
    fn test_parse_query() {
        let packet: Vec<u8> = vec![
            0x89, 0x60, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x78,
            0x78, 0x78, 0x67, 0x6f, 0x02, 0x63, 0x63, 0x00, 0x00, 0x01, 0x00, 01,
        ];

        let (input, header) = parse_header(&packet).unwrap();
        let (input, question) = parse_question_section(input, &packet).unwrap();

        let question_ok = Question::new("xxxgo.cc".to_string(), QType::A, QClass::IN);

        assert_eq!(header.qd_count, 1);
        assert_eq!(question, question_ok);
    }

    #[test]
    fn test_parse_reply() {
        let mut rest: &[u8];
        let packet: Vec<u8> = vec![
            0x54, 0xe8, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x78,
            0x78, 0x78, 0x67, 0x6f, 0x02, 0x63, 0x63, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0xa7, 0xb3, 0x69, 0xda,
        ];

        let (input, header) = parse_header(&packet).unwrap();

        dbg!(&header);

        rest = input;

        for _ in 0..header.qd_count {
            let (input, qd) = parse_question_section(rest, &packet).unwrap();
            rest = input;
            dbg!(&qd);
            let question_ok = Question::new("xxxgo.cc".to_string(), QType::A, QClass::IN);

            assert_eq!(qd, question_ok);
        }

        for _ in 0..header.an_count {
            let (input, an) = parse_resource_record(rest, &packet).unwrap();
            rest = input;
            dbg!(&an);
        }

        for _ in 0..header.ns_count {
            let (input, ns) = parse_resource_record(rest, &packet).unwrap();
            rest = input;
            dbg!(&ns);
        }

        for _ in 0..header.ar_count {
            let (input, ar) = parse_resource_record(rest, &packet).unwrap();
            rest = input;
            dbg!(&ar);
        }
    }

    #[test]
    fn test_parse_reply2() {
        let mut rest: &[u8];
        let packet: Vec<u8> = vec![
            0x00, 0x72, 0x80, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x08, 0x03, 0x77,
            0x77, 0x77, 0x05, 0x78, 0x78, 0x78, 0x67, 0x6f, 0x02, 0x63, 0x63, 0x00, 0x00, 0x01,
            0x00, 0x01, 0xc0, 0x16, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0c, 0xd2, 0x00, 0x0f,
            0x03, 0x61, 0x63, 0x31, 0x05, 0x6e, 0x73, 0x74, 0x6c, 0x64, 0x03, 0x63, 0x6f, 0x6d,
            0x00, 0xc0, 0x16, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0c, 0xd2, 0x00, 0x06, 0x03,
            0x61, 0x63, 0x34, 0xc0, 0x2e, 0xc0, 0x16, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0c,
            0xd2, 0x00, 0x06, 0x03, 0x61, 0x63, 0x33, 0xc0, 0x2e, 0xc0, 0x16, 0x00, 0x02, 0x00,
            0x01, 0x00, 0x00, 0x0c, 0xd2, 0x00, 0x06, 0x03, 0x61, 0x63, 0x32, 0xc0, 0x2e, 0xc0,
            0x2a, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x04, 0xc0, 0x2a, 0xad,
            0x1e, 0xc0, 0x69, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x04, 0xc0,
            0x2a, 0xae, 0x1e, 0xc0, 0x57, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7a, 0x00,
            0x04, 0xc0, 0x2a, 0xaf, 0x1e, 0xc0, 0x45, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x25, 0x00, 0x04, 0xc0, 0x2a, 0xb0, 0x1e, 0xc0, 0x2a, 0x00, 0x1c, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x25, 0x00, 0x10, 0x20, 0x01, 0x05, 0x00, 0x01, 0x20, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0, 0x69, 0x00, 0x1c, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x25, 0x00, 0x10, 0x20, 0x01, 0x05, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0, 0x57, 0x00, 0x1c, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x7a, 0x00, 0x10, 0x20, 0x01, 0x05, 0x00, 0x01, 0x22, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0, 0x45, 0x00, 0x1c, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x27, 0x00, 0x10, 0x20, 0x01, 0x05, 0x00, 0x01, 0x23, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
        ];

        let (input, header) = parse_header(&packet).unwrap();

        dbg!(&header);

        rest = input;

        for _ in 0..header.qd_count {
            let (input, qd) = parse_question_section(rest, &packet).unwrap();
            rest = input;
            dbg!(&qd);
            let question_ok = Question::new("www.xxxgo.cc".to_string(), QType::A, QClass::IN);

            assert_eq!(qd, question_ok);
        }

        for _ in 0..header.an_count {
            let (input, an) = parse_resource_record(rest, &packet).unwrap();
            rest = input;
            dbg!(&an);
        }

        for _ in 0..header.ns_count {
            let (input, ns) = parse_resource_record(rest, &packet).unwrap();
            rest = input;
            dbg!(&ns);
        }

        for _ in 0..header.ar_count {
            let (input, ar) = parse_resource_record(rest, &packet).unwrap();
            rest = input;
            dbg!(&ar);
        }
    }
}
