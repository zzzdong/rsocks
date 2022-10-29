#![recursion_limit = "128"]

use std::io;
use std::net::{IpAddr, SocketAddr};

use clap::Parser;
use futures::{future, Sink, Stream};
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{BytesCodec, Framed};
use tracing::{debug, error, info, trace, Instrument};
use tracing_subscriber::util::SubscriberInitExt;

mod codecs;
mod dns_resolver;
mod errors;
mod parser;
mod proto;

use crate::codecs::socks5::*;
use crate::errors::*;
use crate::proto::socks5::consts::*;
use crate::proto::socks5::*;

type BytesFramed = Framed<TcpStream, BytesCodec>;
type CmdFramed = Framed<TcpStream, CmdCodec>;

// const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

async fn socks5_handshake(socket: TcpStream) -> Result<CmdFramed, RsocksError> {
    let mut stream = Framed::new(socket, HandshakeCodec);

    let req = stream
        .next()
        .await
        .ok_or_else(|| socks_error("read handshake failed"))??;

    let resp = HandshakeResponse::new(SOCKS5_AUTH_METHOD_NONE);
    stream.send(resp).await?;

    if !req.methods.contains(&SOCKS5_AUTH_METHOD_NONE) {
        return Err(socks_error("method not support"));
    }

    let stream = stream.map_codec(|_| CmdCodec);

    Ok(stream)
}

async fn socks5_cmd(mut stream: CmdFramed) -> Result<(BytesFramed, BytesFramed), RsocksError> {
    let req = stream
        .next()
        .await
        .ok_or_else(|| socks_error("read request failed"))??;

    debug!("cmd request: {:?}", req);

    let CmdRequest { address, port, .. } = req.clone();

    // only support TCPConnect
    let (stream, outside) = match req.command {
        Command::TCPConnect => socks_connect(stream, req).await?,
        _ => {
            let resp = CmdResponse::new(Reply::CommandNotSupported, address, port);
            stream.send(resp).await?;
            return Err(socks_error("command not support"));
        }
    };

    let local = stream.map_codec(|_| BytesCodec::new());
    let remote = Framed::new(outside, BytesCodec::new());

    Ok((local, remote))
}

async fn socks_connect(
    mut local: CmdFramed,
    req: CmdRequest,
) -> Result<(CmdFramed, TcpStream), RsocksError> {
    let addr = resolve_addr(&req).await?;

    let addr = SocketAddr::new(addr, req.port);
    trace!("try connect to {}({:?})", addr, &req.address);

    let socket = TcpStream::connect(&addr).await;
    match socket {
        Ok(s) => {
            trace!("connected {:?}", req.address);
            let CmdRequest { address, port, .. } = req.clone();
            let resp = CmdResponse::new(Reply::Succeeded, address, port);
            local.send(resp).await?;
            Ok((local, s))
        }
        Err(e) => {
            let CmdRequest { address, port, .. } = req.clone();
            let reply = match e.kind() {
                io::ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                io::ErrorKind::TimedOut => Reply::HostUnreachable,
                _ => Reply::CommandNotSupported,
            };
            let resp = CmdResponse::new(reply, address, port);
            local.send(resp).await?;
            Err(socks_error(format!(
                "connect {:?} failed, {:?}",
                req.address, e
            )))
        }
    }
}

async fn resolve_addr(req: &CmdRequest) -> Result<IpAddr, RsocksError> {
    let req = req.clone();
    match req.address {
        Address::IPv4(ip) => Ok(IpAddr::V4(ip)),
        Address::IPv6(ip) => Ok(IpAddr::V6(ip)),
        Address::DomainName(ref dn) => dns_resolver::dns_query(dn).await,
        Address::Unknown(_t) => Err(socks_error("bad address")),
    }
}

async fn socks_streaming(local: BytesFramed, remote: BytesFramed) -> Result<(), RsocksError> {
    let (l_sink, l_stream) = local.split();
    let (r_sink, r_stream) = remote.split();

    trace!("streaming...");

    future::try_join(
        forward_data(l_stream, r_sink),
        forward_data(r_stream, l_sink),
    )
    .await?;

    Ok(())
}

async fn forward_data(
    mut reader: impl Stream<Item = Result<bytes::BytesMut, io::Error>> + Unpin,
    mut writer: impl Sink<bytes::Bytes, Error = io::Error> + Unpin,
) -> Result<(), io::Error> {
    while let Some(item) = reader.next().await {
        let buf = item?;
        writer.send(buf.freeze()).await?;
    }

    Ok(())
}

async fn socks_proxy(socket: TcpStream) -> Result<(), RsocksError> {
    let handshaked = socks5_handshake(socket).await?;
    let (s1, s2) = socks5_cmd(handshaked).await?;
    socks_streaming(s1, s2).await?;

    Ok(())
}

#[derive(Parser, Debug)]
struct Args {
    // The number of occurences of the `v/verbose` flag
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[arg(short, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Host to listen on
    #[arg(long, default_value = "localhost:1080")]
    host: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let opt = Args::parse();

    let addr: SocketAddr = opt.host.parse().expect("can not parse host");

    let level = match opt.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(format!("rsocks={}", level))
        .finish()
        .init();

    let listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("can not bind {}, {:?}", addr, e));

    info!("listening on {}", addr);

    loop {
        let (socket, remote_addr) = listener.accept().await.expect("accpet failed");

        tokio::spawn(
            async {
                match socks_proxy(socket).await {
                    Ok(_) => {}
                    Err(e) => error!("socks5 proxy error, {:?}", e),
                }
            }
            .instrument(tracing::info_span!("conn", %remote_addr)),
        );
    }
}
