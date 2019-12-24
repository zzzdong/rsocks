use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use tokio::net::UdpFramed;
use tokio::net::UdpSocket;
use tokio::prelude::*;

use crate::codecs::dns::*;
use crate::errors::RsocksError;
use crate::proto::dns::*;

// const MAX_DATAGRAM_SIZE: usize = 65_507;
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

static GLOBAL_DNS_QUERY_COUNT: AtomicU16 = AtomicU16::new(0);

pub async fn dns_query(domain: &str) -> Result<IpAddr, RsocksError> {
    let remote_addr: SocketAddr = "114.114.114.114:53".parse().unwrap();
    // let remote_addr: SocketAddr = "182.254.116.116:53".parse().unwrap();
    // let remote_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
    // let remote_addr: SocketAddr = "1.1.1.1:53".parse().unwrap();
    let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

    let socket = UdpSocket::bind(&local_addr).await?;
    socket.connect(&remote_addr).await?;

    // build query message
    let curr_query_count = GLOBAL_DNS_QUERY_COUNT.fetch_add(1, Ordering::SeqCst);
    let msg = Message::new_query(curr_query_count, domain);

    // user framed to send
    let mut framed = UdpFramed::new(socket, MessageCodec);

    framed
        .send((msg, remote_addr))
        .timeout(QUERY_TIMEOUT)
        .await??;

    let (msg, _) = framed
        .next()
        .map(|e| e.unwrap())
        .timeout(QUERY_TIMEOUT)
        .await??;

    for record in &msg.answer {
        if record.type_ == QType::A && record.class == QClass::IN {
            if let RDATA::A(addr) = record.rdata {
                return Ok(IpAddr::V4(addr));
            }
        }
    }

    Err(RsocksError::DNSError {
        msg: "dns failed".to_string(),
    })
}
