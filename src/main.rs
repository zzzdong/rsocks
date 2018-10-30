#![feature(await_macro, async_await, futures_api)]
#![recursion_limit = "128"]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;

use std::io;
use std::net::{IpAddr, SocketAddr};

use env_logger::Builder;
use futures::future::Either;
use log::LevelFilter;

use structopt::StructOpt;

use tokio::codec::{BytesCodec, Framed, FramedParts};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

use trust_dns_resolver::config::*;
use trust_dns_resolver::AsyncResolver;

mod codecs;
mod errors;
mod proto;

use crate::codecs::socks5::*;
use crate::errors::*;
use crate::proto::socks5::consts::*;
use crate::proto::socks5::*;

type BytesFramed = Framed<TcpStream, BytesCodec>;
type CmdFramed = Framed<TcpStream, CmdCodec>;

fn socks5_handshake(socket: TcpStream) -> impl Future<Item = CmdFramed, Error = RsocksError> {
    Framed::new(socket, HandshakeCodec)
        .into_future()
        .map_err(|(e, _s)| e)
        .and_then(|(r, s)| match r {
            Some(req) => {
                if req.methods.contains(&SOCKS5_AUTH_METHOD_NONE) {
                    let resp = HandshakeResponse::new(SOCKS5_AUTH_METHOD_NONE);
                    future::ok(s.send(resp))
                } else {
                    let resp = HandshakeResponse::new(SOCKS5_AUTH_METHOD_NONE);
                    let f = s.send(resp).and_then(|_s| Ok(())).map_err(|_| ());
                    tokio::spawn(f);
                    future::err(socks_error("method not support"))
                }
            }
            None => future::err(socks_error("read request failed")),
        })
        .and_then(|f| f)
        .and_then(move |s| {
            let FramedParts {
                io,
                read_buf,
                write_buf,
                ..
            } = s.into_parts();

            let mut new_parts = FramedParts::new(io, CmdCodec);

            new_parts.write_buf = write_buf;
            new_parts.read_buf = read_buf;

            let cmd = Framed::from_parts(new_parts);
            Ok(cmd)
        })
}

fn socks5_cmd(
    stream: CmdFramed,
) -> impl Future<Item = (CmdFramed, TcpStream), Error = RsocksError> {
    stream
        .into_future()
        .map_err(|(e, _s)| e)
        .and_then(|(r, s)| match r {
            Some(req) => {
                debug!("cmd request: {:?} from {:?}", req, s);
                let CmdRequest { address, port, .. } = req.clone();
                // only support TCPConnect
                if req.command == Command::TCPConnect {
                    future::ok(socks_connect(s, req))
                } else {
                    let resp = CmdResponse::new(Reply::CommandNotSupported, address, port);
                    let f = s.send(resp).and_then(|_s| Ok(())).map_err(|_| ());
                    tokio::spawn(f);
                    future::err(socks_error("command not support"))
                }
            }
            None => future::err(socks_error("read request failed")),
        })
        .and_then(|s| s)
        .and_then(move |(s, c, r)| s.send(r).map(|s| (s, c)))
}

fn socks_connect(
    stream: CmdFramed,
    req: CmdRequest,
) -> impl Future<Item = (CmdFramed, TcpStream, CmdResponse), Error = RsocksError> {
    resolve_addr(&req).and_then(move |a| {
        let addr = SocketAddr::new(a, req.port);
        trace!("try connect to {}", addr);
        TcpStream::connect(&addr).then(move |r| match r {
            Ok(c) => {
                trace!("connected {}", addr);
                let CmdRequest { address, port, .. } = req.clone();
                let resp = CmdResponse::new(Reply::Succeeded, address, port);
                Ok((stream, c, resp))
            }
            Err(e) => {
                let CmdRequest { address, port, .. } = req.clone();
                let reply = match e.kind() {
                    io::ErrorKind::ConnectionRefused => Reply::ConnectionRefused,

                    _ => Reply::CommandNotSupported,
                };
                let resp = CmdResponse::new(reply, address, port);
                let f = stream.send(resp).and_then(|_s| Ok(())).map_err(|_| ());
                tokio::spawn(f);
                Err(socks_error(format!("connect failed, {:?}", e)))
            }
        })
    })
}

fn dns_resolve(domain: &str) -> impl Future<Item = IpAddr, Error = RsocksError> {
    // FIXME: use global resolver instead of init every time
    let (resolver, background) =
        AsyncResolver::new(ResolverConfig::default(), ResolverOpts::default());

    tokio::spawn(background);
    resolver
        .lookup_ip(domain)
        .map_err(RsocksError::from)
        .and_then(|r| match r.iter().next() {
            Some(a) => Ok(a),
            None => Err(socks_error("dns lookup failed.")),
        })
}

fn resolve_addr(req: &CmdRequest) -> impl Future<Item = IpAddr, Error = RsocksError> {
    let req = req.clone();
    match req.address {
        Address::IPv4(ip) => Either::A(future::ok(IpAddr::V4(ip))),
        Address::IPv6(ip) => Either::A(future::ok(IpAddr::V6(ip))),
        Address::DomainName(ref dn) => Either::B(dns_resolve(dn.as_str())),
    }
}

fn into_socks_streaming(
    s: Framed<TcpStream, CmdCodec>,
    c: TcpStream,
) -> (BytesFramed, BytesFramed) {
    let FramedParts {
        io,
        read_buf,
        write_buf,
        ..
    } = s.into_parts();

    let mut new_parts = FramedParts::new(io, BytesCodec::new());

    new_parts.write_buf = write_buf;
    new_parts.read_buf = read_buf;

    let s1 = Framed::from_parts(new_parts);

    let s2 = Framed::new(c, BytesCodec::new());

    (s1, s2)
}

fn socks_streaming(s1: BytesFramed, s2: BytesFramed) {
    let (a_sink, a_stream) = s1.split();
    let (b_sink, b_stream) = s2.split();

    let f1 = b_stream
        .map(|b| b.freeze())
        .forward(a_sink)
        .map(|_| ())
        .map_err(|e| error!("streaming error: {:?}", e));

    let f2 = a_stream
        .map(|b| b.freeze())
        .forward(b_sink)
        .map(|_| ())
        .map_err(|e| error!("streaming error: {:?}", e));

    tokio::spawn(f1);
    tokio::spawn(f2);
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

fn main() {
    let opt = Opt::from_args();

    let mut builder = Builder::new();

    let level = match opt.verbose {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    builder.filter_module("rsocks", level);

    builder.init();

    let addr = opt.host.parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();

    info!("listening on {}", addr);

    let server = listener
        .incoming()
        .for_each(|socket| {
            info!("accepted socket from {:?}", socket.peer_addr().unwrap());

            let f = socks5_handshake(socket)
                .and_then(socks5_cmd)
                .and_then(|(s, c)| {
                    let (s1, s2) = into_socks_streaming(s, c);
                    socks_streaming(s1, s2);
                    Ok(())
                })
                .map(|_| ())
                .map_err(|e| error!("error = {:?}", e));
            tokio::spawn(f);
            Ok(())
        })
        .map_err(|err| {
            error!("accept error = {:?}", err);
        });

    tokio::run(server);
}
