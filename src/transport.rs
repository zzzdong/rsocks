pub mod rsocks {
    tonic::include_proto!("rsocks");

    use crate::proto::socks5::*;
    use bytes::Bytes;

    impl From<CmdRequest> for RsocksReq {
        fn from(req: CmdRequest) -> Self {
            let addr = match req.address {
                Address::IPv4(ip) => rsocks_req::connect::Addr::Ip(ip.octets().to_vec()),
                Address::IPv6(ip) => rsocks_req::connect::Addr::Ip(ip.octets().to_vec()),
                Address::DomainName(domain) => rsocks_req::connect::Addr::Domain(domain),
                Address::Unknown(u) => rsocks_req::connect::Addr::Ip(vec![u]),
            };

            RsocksReq {
                inner: Some(rsocks_req::Inner::Connect(rsocks_req::Connect {
                    port: req.port as u32,
                    addr: Some(addr),
                })),
            }
        }
    }

    impl From<Bytes> for RsocksReq {
        fn from(req: Bytes) -> Self {
            RsocksReq {
                inner: Some(rsocks_req::Inner::Streaming(rsocks_req::Streaming {
                    data: req.to_vec(),
                })),
            }
        }
    }

    impl From<rsocks_resp::connect::Addr> for Address {
        fn from(addr: rsocks_resp::connect::Addr) -> Self {
            match addr {
                rsocks_resp::connect::Addr::Ip(ip) => {
                    if ip.len() == 4 {
                        let (_, a) = crate::parser::socks5::read_ipv4(&ip).unwrap();
                        a
                    } else if ip.len() == 16 {
                        let (_, a) = crate::parser::socks5::read_ipv6(&ip).unwrap();
                        a
                    } else {
                        Address::Unknown(0)
                    }
                }
                rsocks_resp::connect::Addr::Domain(domain) => Address::DomainName(domain),
            }
        }
    }

    impl From<rsocks_resp::Connect> for CmdResponse {
        fn from(c: rsocks_resp::Connect) -> Self {
            CmdResponse::new(
                (c.reply as u8).into(),
                c.addr.unwrap().into(),
                c.port as u16,
            )
        }
    }

    impl From<rsocks_resp::Streaming> for Bytes {
        fn from(s: rsocks_resp::Streaming) -> Self {
            Bytes::from(s.data)
        }
    }
}

use tonic::transport::Channel;

pub use rsocks::client::RsocksClient;
