#![recursion_limit = "128"]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;

use std::io;
use std::net::{IpAddr, SocketAddr};
// use std::time::Duration;

use bytes::Bytes;
use futures::{future, Sink, Stream};
use log::LevelFilter;
use structopt::StructOpt;
use tokio::codec::{BytesCodec, Framed, FramedParts};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tonic::transport::Channel;

mod codecs;
mod dns_resolver;
mod errors;
mod parser;
mod proto;
mod transport;

use crate::codecs::socks5::*;
use crate::errors::*;
use crate::proto::socks5::consts::*;
use crate::proto::socks5::*;
use crate::transport::*;

type BytesFramed = Framed<TcpStream, BytesCodec>;
type CmdFramed = Framed<TcpStream, CmdCodec>;

// const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

async fn socks5_handshake(socket: TcpStream) -> Result<CmdFramed, RsocksError> {
    let (framed, mut stream) = Framed::new(socket, HandshakeCodec).into_future().await;
    let req = match framed {
        Some(req) => req,
        None => return Err(socks_error("read request failed")),
    }?;

    if req.methods.contains(&SOCKS5_AUTH_METHOD_NONE) {
        let resp = HandshakeResponse::new(SOCKS5_AUTH_METHOD_NONE);
        stream.send(resp).await?;
    } else {
        let resp = HandshakeResponse::new(SOCKS5_AUTH_METHOD_NONE);
        stream.send(resp).await?;
        return Err(socks_error("method not support"));
    }

    let FramedParts {
        io,
        read_buf,
        write_buf,
        ..
    } = stream.into_parts();

    let mut new_parts = FramedParts::new(io, CmdCodec);

    new_parts.write_buf = write_buf;
    new_parts.read_buf = read_buf;

    let cmd = Framed::from_parts(new_parts);

    Ok(cmd)
}

async fn socks5_cmd(stream: CmdFramed) -> Result<(BytesFramed, BytesFramed), RsocksError> {
    let (framed, mut stream) = stream.into_future().await;

    let req = match framed {
        Some(req) => req,
        None => return Err(socks_error("read request failed")),
    }?;

    debug!("cmd request: {:?} from {:?}", req, stream);
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

    let FramedParts {
        io,
        read_buf,
        write_buf,
        ..
    } = stream.into_parts();

    let mut new_parts = FramedParts::new(io, BytesCodec::new());

    new_parts.write_buf = write_buf;
    new_parts.read_buf = read_buf;

    let local = Framed::from_parts(new_parts);
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
        Address::DomainName(ref dn) => dns_resolver::dns_query(&dn).await,
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

async fn socks_proxy2(socket: TcpStream, channel: Channel) -> Result<(), RsocksError> {
    use transport::rsocks::rsocks_resp;
    use transport::rsocks::RsocksReq;

    trace!("got connect from {:?}", socket.peer_addr());

    let (framed, mut local_stream) = Framed::new(socket, SocksCodec::new()).into_future().await;

    debug!("got first frame {:?}", local_stream);

    let req = match framed {
        Some(Ok(SocksRequest::Handshake(h))) => h,
        Some(Err(e)) => panic!("read handshake error, {:?}", e),
        None => return Err(socks_error("read handshake request failed")),
        _ => unreachable!(),
    };

    if req.methods.contains(&SOCKS5_AUTH_METHOD_NONE) {
        let resp = SocksResponse::Handshake(HandshakeResponse::new(SOCKS5_AUTH_METHOD_NONE));
        local_stream.send(resp).await?;
    } else {
        let resp = SocksResponse::Handshake(HandshakeResponse::new(SOCKS5_AUTH_METHOD_NONE));
        local_stream.send(resp).await?;
        return Err(socks_error("method not support"));
    }

    let (mut l_sink, l_stream) = local_stream.split();

    let request = tonic::Request::new(l_stream.map(|r| {
        trace!("output streaming...");
        match r {
            Ok(SocksRequest::Handshake(c)) => unreachable!(),
            Ok(SocksRequest::Cmd(c)) => RsocksReq::from(c),
            Ok(SocksRequest::Stream(s)) => {
                trace!("output streaming len={}", s.len());
                RsocksReq::from(s)
            }
            Err(e) => {
                panic!("l_stream read error: {:?}", e);
                // error!("l_stream read error: {:?}", e);
                // RsocksReq::from(Bytes::with_capacity(0))
            }
        }
    }));

    let mut stream = RsocksClient::new(channel);

    let response = stream.rsock_stream(request).await.unwrap();

    let mut inbound = response.into_inner();

    let mut total_len: usize = 0;

    while let Some(msg) = inbound
        .message()
        .await
        .map_err(|e| socks_error(format!("read grpc failed, {:?}", e)))?
    {
        if let Some(inner) = msg.inner {
            trace!("input streaming, total_len={}", total_len);

            let resp = match inner {
                rsocks_resp::Inner::Connect(c) => {
                    trace!("input connect=> {:?}", c);
                    SocksResponse::Cmd(c.into())
                }
                rsocks_resp::Inner::Streaming(s) => {
                    total_len += s.data.len();
                    trace!(
                        "input streaming=> len={:?}, total={}",
                        s.data.len(),
                        total_len
                    );
                    SocksResponse::Stream(s.into())
                }
            };

            l_sink.send(resp).await.unwrap();
            l_sink.flush().await.unwrap()
        }
    }

    Ok(())
}

#[derive(StructOpt, Debug)]
struct Opt {
    // The number of occurences of the `v/verbose` flag
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    verbose: u8,
    /// Host to listen on
    #[structopt(long = "host", default_value = "0.0.0.0:1080")]
    host: String,
}

#[tokio::main]
async fn main() -> Result<(), failure::Error> {
    let opt = Opt::from_args();

    let mut builder = env_logger::Builder::new();

    let level = match opt.verbose {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    builder.filter_module("rsocks", level);

    builder.init();

    let addr: SocketAddr = opt.host.parse().expect("can not parse host");

    let mut listener = TcpListener::bind(&addr)
        .await
        .expect(&format!("can not bind {}", addr));

    info!("listening on {}", addr);

    let channel = Channel::from_static("http://localhost:1089")
        .connect()
        .await?;

    loop {
        let (socket, _) = listener.accept().await.expect("accpet failed");

        let channel_cloned = channel.clone();
        tokio::spawn(async move {
            match socks_proxy2(socket, channel_cloned).await {
                Ok(_) => {}
                Err(e) => error!("socks5 proxy error, {:?}", e),
            }
        });
    }
}
