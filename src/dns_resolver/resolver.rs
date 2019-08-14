
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

use tokio::prelude::*;
use std::time::Duration;
use tokio::net::UdpSocket;

use crate::dns_resolver::proto::*;
use crate::dns_resolver::parser;
use crate::errors::RsocksError;

const MAX_DATAGRAM_SIZE: usize = 65_507;

use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

static GLOBAL_DNS_QUERY_COUNT: AtomicU16 = AtomicU16::new(0);

pub async fn dns_query(domain: &str) -> Result<IpAddr, RsocksError> {
    let remote_addr: SocketAddr = "114.114.114.114:53".parse().unwrap();
    // let remote_addr: SocketAddr = "182.254.116.116:53".parse().unwrap();
    // let remote_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
    // let remote_addr: SocketAddr = "1.1.1.1:53".parse().unwrap();
    let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

    let mut socket = UdpSocket::bind(&local_addr).unwrap();

    let curr_query_count = GLOBAL_DNS_QUERY_COUNT.fetch_add(1, Ordering::SeqCst);

    socket.connect(&remote_addr).unwrap();

    let msg = Message::new_query(curr_query_count, domain);

    let data = msg.to_bytes().freeze();

    socket.send(&data).timeout(Duration::from_secs(3)).await.unwrap().unwrap();

    let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];

    let len = socket.recv(&mut buf).await.unwrap();



    let msg = parser::Parser::new(&buf[..len]).parse()?;
    for record in &msg.answer {
        if record.type_ == QType::A && record.class == QClass::IN {
            if let RDATA::A(addr) = record.rdata {
                return Ok(IpAddr::V4(addr))
            }
        }
        
    }

    Err(RsocksError::DNSError{msg: "dns failed".to_string()})
}