#![allow(dead_code)]

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};

use crate::proto::WriteBuf;

pub mod consts {
    pub const DNS_QR_QUERY: u8 = 0;
    pub const DNS_QR_REPLY: u8 = 1;

    pub const DNS_OP_QUERY: u8 = 0;
    pub const DNS_OP_IQUERY: u8 = 1;
    pub const DNS_OP_STATUS: u8 = 2;

    pub const DNS_RCODE_NO_ERROR: u8 = 0;
    pub const DNS_RCODE_FORMAT_ERROR: u8 = 1;
    pub const DNS_RCODE_SERVER_FAILURE: u8 = 2;
    pub const DNS_RCODE_NAME_ERROR: u8 = 3;
    pub const DNS_RCODE_NOT_IMPLEMENTED: u8 = 4;
    pub const DNS_RCODE_REFUSED: u8 = 5;

    pub const DNS_QTYPE_A: u16 = 1;
    pub const DNS_QTYPE_NS: u16 = 2;
    pub const DNS_QTYPE_MD: u16 = 3;
    pub const DNS_QTYPE_MF: u16 = 4;
    pub const DNS_QTYPE_CNAME: u16 = 5;
    pub const DNS_QTYPE_SOA: u16 = 6;
    pub const DNS_QTYPE_MB: u16 = 7;
    pub const DNS_QTYPE_MG: u16 = 8;
    pub const DNS_QTYPE_MR: u16 = 9;
    pub const DNS_QTYPE_NULL: u16 = 10;
    pub const DNS_QTYPE_WKS: u16 = 11;
    pub const DNS_QTYPE_PTR: u16 = 12;
    pub const DNS_QTYPE_HINFO: u16 = 13;
    pub const DNS_QTYPE_MINFO: u16 = 14;
    pub const DNS_QTYPE_MX: u16 = 15;
    pub const DNS_QTYPE_TXT: u16 = 16;
    pub const DNS_QTYPE_AXFR: u16 = 252;
    pub const DNS_QTYPE_MAILB: u16 = 253;
    pub const DNS_QTYPE_MAILA: u16 = 254;
    pub const DNS_QTYPE_ALL: u16 = 255;

    pub const DNS_QCLASS_IN: u16 = 1;
    pub const DNS_QCLASS_CS: u16 = 2;
    pub const DNS_QCLASS_CH: u16 = 3;
    pub const DNS_QCLASS_HS: u16 = 4;
    pub const DNS_QCLASS_ANY: u16 = 255;
}

const QTYPE_TABLE_1: [QType; 17] = [
    QType::Unknown(0),
    QType::A,
    QType::NS,
    QType::MD,
    QType::MF,
    QType::CNAME,
    QType::SOA,
    QType::MB,
    QType::MG,
    QType::MR,
    QType::NULL,
    QType::WKS,
    QType::PTR,
    QType::HINFO,
    QType::MINFO,
    QType::MX,
    QType::TXT,
];

const QTYPE_TABLE_2: [QType; 4] = [QType::AXFR, QType::MAILB, QType::MAILA, QType::ALL];

const QTYPE_U16_TABLE__1: [QType; 17] = [
    QType::Unknown(0),
    QType::A,
    QType::NS,
    QType::MD,
    QType::MF,
    QType::CNAME,
    QType::SOA,
    QType::MB,
    QType::MG,
    QType::MR,
    QType::NULL,
    QType::WKS,
    QType::PTR,
    QType::HINFO,
    QType::MINFO,
    QType::MX,
    QType::TXT,
];

const QCLASS_TABLE_1: [QClass; 5] = [
    QClass::Unknown(0),
    QClass::IN,
    QClass::CS,
    QClass::CH,
    QClass::HS,
];

#[derive(Clone, Debug)]
pub struct Message {
    pub header: Header,
    pub question: Vec<Question>,
    pub answer: Vec<ResourceRecord>,
    pub authority: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

impl Message {
    pub fn new_query(id: u16, domain: impl ToString) -> Message {
        let question = Question {
            qname: domain.to_string(),
            qtype: QType::A,
            qclass: QClass::IN,
        };

        let mut header = Header::new_query(id);
        header.qd_count = 1;

        Message {
            header,
            question: vec![question],
            answer: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put(self.header.to_bytes());

        for q in &self.question {
            q.write_buf(buf);
        }
    }
}

impl WriteBuf for Message {
    fn write_buf(&self, buf: &mut BytesMut) {
        self.write_to(buf);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    pub id: u16,
    pub flag: Flag,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl Header {
    pub fn new_query(id: u16) -> Header {
        Header {
            id,
            flag: Flag {
                qr: QR::Query,
                op: OpCode::Query,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                rc: RCode::NoError,
            },
            qd_count: 0,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }
    pub fn to_bytes(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(12);

        buf.put_u16(self.id);
        buf.put(&self.flag.to_bytes()[..]);
        buf.put_u16(self.qd_count);
        buf.put_u16(self.an_count);
        buf.put_u16(self.ns_count);
        buf.put_u16(self.ar_count);

        buf
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Flag {
    pub qr: QR,
    pub op: OpCode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rc: RCode,
}

impl Flag {
    pub fn to_bytes(&self) -> [u8; 2] {
        let mut flag: [u8; 2] = [0x00, 0x00];

        flag[0] |= match self.qr {
            QR::Query => 0x00,
            QR::Reply => 0x80,
            _ => 0x00,
        };
        flag[0] |= match self.op {
            OpCode::Query => 0x00,
            OpCode::IQuery => 0x08,
            OpCode::Status => 0x18,
            _ => 0x00,
        };
        if self.aa {
            flag[0] |= 0x04;
        }
        if self.tc {
            flag[0] |= 0x02;
        }
        if self.rd {
            flag[0] |= 0x01;
        }
        if self.ra {
            flag[1] |= 0x80;
        }
        flag[1] |= match self.rc {
            RCode::NoError => 0x00,
            RCode::FormatError => 0x01,
            RCode::ServerFail => 0x02,
            RCode::NameError => 0x03,
            RCode::NotImplemented => 0x04,
            RCode::Refused => 0x05,
            RCode::Unknown(u) => u,
        };

        flag
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum QR {
    Query,
    Reply,
    Unknown(u8),
}

impl QR {
    pub fn from_byte(b: u8) -> QR {
        use consts::*;

        match b {
            DNS_QR_QUERY => QR::Query,
            DNS_QR_REPLY => QR::Reply,
            _ => QR::Unknown(b),
        }
    }
}

impl From<u8> for QR {
    fn from(b: u8) -> Self {
        QR::from_byte(b)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum OpCode {
    Query,
    IQuery,
    Status,
    Unknown(u8),
}

impl OpCode {
    pub fn from_byte(b: u8) -> OpCode {
        use consts::*;

        match b {
            DNS_OP_QUERY => OpCode::Query,
            DNS_OP_IQUERY => OpCode::IQuery,
            DNS_OP_STATUS => OpCode::Status,
            _ => OpCode::Unknown(b),
        }
    }
}

impl From<u8> for OpCode {
    fn from(b: u8) -> Self {
        OpCode::from_byte(b)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum RCode {
    NoError,
    FormatError,
    ServerFail,
    NameError,
    NotImplemented,
    Refused,
    Unknown(u8),
}

impl RCode {
    pub fn from_byte(b: u8) -> RCode {
        use consts::*;

        match b {
            DNS_RCODE_NO_ERROR => RCode::NoError,
            DNS_RCODE_FORMAT_ERROR => RCode::FormatError,
            DNS_RCODE_SERVER_FAILURE => RCode::ServerFail,
            DNS_RCODE_NAME_ERROR => RCode::NameError,
            DNS_RCODE_NOT_IMPLEMENTED => RCode::NotImplemented,
            DNS_RCODE_REFUSED => RCode::Refused,
            _ => RCode::Unknown(b),
        }
    }
}

impl From<u8> for RCode {
    fn from(b: u8) -> Self {
        RCode::from_byte(b)
    }
}

/// Question Section
#[derive(Clone, Debug, PartialEq)]
pub struct Question {
    pub qname: String,
    pub qtype: QType,
    pub qclass: QClass,
}

impl Question {
    pub fn new(qname: String, qtype: QType, qclass: QClass) -> Question {
        Question {
            qname,
            qtype,
            qclass,
        }
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        write_domain_name(buf, &self.qname);
        buf.put_u16(u16::from(self.qtype));
        buf.put_u16(u16::from(self.qclass));
    }
}

impl WriteBuf for Question {
    fn write_buf(&self, buf: &mut BytesMut) {
        self.write_to(buf);
    }
}

pub fn write_domain_name(buf: &mut BytesMut, domain: &str) {
    let parts = domain.split('.');

    for p in parts {
        buf.put_u8(p.as_bytes().len() as u8);
        buf.put(p.as_bytes());
    }

    buf.put_u8(0u8);
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum QType {
    A,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
    AXFR,
    MAILB,
    MAILA,
    ALL,
    AAAA, // 28, IPv6
    Unknown(u16),
}

impl QType {
    pub fn from_u16(t: u16) -> QType {
        match t {
            1..=16 => QTYPE_TABLE_1[t as usize],
            28 => QType::AAAA,
            252..=255 => QTYPE_TABLE_2[(t - 252) as usize],
            _ => QType::Unknown(t),
        }
    }
}

impl From<u16> for QType {
    fn from(t: u16) -> Self {
        QType::from_u16(t)
    }
}

impl From<QType> for u16 {
    fn from(t: QType) -> Self {
        match t {
            QType::A => 1,
            QType::NS => 2,
            QType::MD => 3,
            QType::MF => 4,
            QType::CNAME => 5,
            QType::SOA => 6,
            QType::MB => 7,
            QType::MG => 8,
            QType::MR => 9,
            QType::NULL => 10,
            QType::WKS => 11,
            QType::PTR => 12,
            QType::HINFO => 13,
            QType::MINFO => 14,
            QType::MX => 15,
            QType::TXT => 16,
            QType::AXFR => 252,
            QType::MAILB => 253,
            QType::MAILA => 254,
            QType::ALL => 255,
            QType::AAAA => 28, // 28, IPv6
            QType::Unknown(code) => code,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum QClass {
    IN,
    CS,
    CH,
    HS,
    ANY,
    Unknown(u16),
}

impl QClass {
    pub fn from_u16(c: u16) -> QClass {
        match c {
            1..=4 => QCLASS_TABLE_1[c as usize],
            consts::DNS_QCLASS_ANY => QClass::ANY,
            _ => QClass::Unknown(c),
        }
    }
}

impl From<u16> for QClass {
    fn from(c: u16) -> Self {
        QClass::from_u16(c)
    }
}

impl From<QClass> for u16 {
    fn from(c: QClass) -> Self {
        match c {
            QClass::IN => 1,
            QClass::CS => 2,
            QClass::CH => 3,
            QClass::HS => 4,
            QClass::ANY => 5,
            QClass::Unknown(code) => code,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResourceRecord {
    pub name: String,
    pub type_: QType,
    pub class: QClass,
    pub ttl: u32,
    pub rdlen: u16,
    pub rdata: RDATA,
}

#[derive(Clone, Debug)]
pub enum RDATA {
    CNAME(String),
    HINFO(String, String),
    MB(String),
    MD(String),
    MF(String),
    MG(String),
    MINFO(String, String),
    MR(String),
    MX(u16, String),
    NULL(Vec<u8>),
    NS(String),
    PTR(String),
    SOA(String, String, u32, u32, u32, u32, u32),
    TXT(Vec<String>),
    A(Ipv4Addr),
    AAA(Ipv6Addr),
    WKS(Ipv4Addr, u8, Vec<u8>),
    Unknown(Vec<u8>),
}
