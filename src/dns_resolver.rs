use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use futures_util::future::FutureExt;
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tokio_util::udp::UdpFramed;

use crate::codecs::dns::*;
use crate::errors::{dns_error, RsocksError};
use crate::proto::dns::*;

// const MAX_DATAGRAM_SIZE: usize = 65_507;
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

static GLOBAL_DNS_QUERY_COUNT: AtomicU16 = AtomicU16::new(0);

const DNS_SEVER_ADDR_DROPBOX: &str = "1.1.1.1:53";
const DNS_SEVER_ADDR_GOOGLE: &str = "8.8.8.8:53";
const DNS_SEVER_ADDR_114: &str = "114.114.114.114:53";

pub async fn dns_query(domain: &str) -> Result<IpAddr, RsocksError> {
    let remote_addr: SocketAddr = DNS_SEVER_ADDR_GOOGLE.parse().unwrap();
    let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

    let socket = UdpSocket::bind(&local_addr).await?;
    socket.connect(&remote_addr).await?;

    // build query message
    let curr_query_count = GLOBAL_DNS_QUERY_COUNT.fetch_add(1, Ordering::SeqCst);
    let msg = Message::new_query(curr_query_count, domain);

    // use framed to send
    let mut framed = UdpFramed::new(socket, MessageCodec);

    timeout(QUERY_TIMEOUT, framed.send((msg, remote_addr))).await??;

    let (msg, _) = timeout(QUERY_TIMEOUT, framed.next().map(|e| e.unwrap())).await??;

    for record in &msg.answer {
        if record.type_ == QType::A && record.class == QClass::IN {
            if let RDATA::A(addr) = record.rdata {
                return Ok(IpAddr::V4(addr));
            }
        }
    }

    Err(dns_error("dns lookup failed"))
}
