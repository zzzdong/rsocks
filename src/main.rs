#![feature(async_await)]
#![feature(async_closure)]
#![recursion_limit = "128"]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;

use futures::executor::block_on;
use log::LevelFilter;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, Once};

use futures::compat::Executor01CompatExt;
use futures::compat::Future01CompatExt;
use futures::future::Either;
use futures::task::SpawnExt;


use structopt::StructOpt;

use tokio::codec::{BytesCodec, Framed, FramedParts};
use tokio::net::{TcpListener, TcpStream};
// use tokio::prelude::*;

use trust_dns_resolver::AsyncResolver;

// use tokio_io::AsyncRead;
// use futures01::future::Future;

use futures::future::Future;
use futures::future::FutureExt;
use futures::future::TryFutureExt;
use futures::sink::SinkExt;
use futures::stream::StreamExt;



mod codecs;
mod errors;
mod proto;
mod dns_resolver;

use crate::codecs::socks5::*;
use crate::errors::*;
use crate::proto::socks5::consts::*;
use crate::proto::socks5::*;

type BytesFramed = Framed<TcpStream, BytesCodec>;
type CmdFramed = Framed<TcpStream, CmdCodec>;

static mut DNS_RESOLVER: Option<AsyncResolver> = None;

lazy_static! {
    // borrow from https://github.com/bluejekyll/trust-dns/blob/master/crates/resolver/examples/global_resolver.rs
    // First we need to setup the global Resolver
    static ref GLOBAL_DNS_RESOLVER: AsyncResolver = {
        use std::sync::{Arc, Mutex, Condvar};
        use std::thread;

        // We'll be using this condvar to get the Resolver from the thread...
        let pair = Arc::new((Mutex::new(None::<AsyncResolver>), Condvar::new()));
        let pair2 = pair.clone();

        // let mut runtime = tokio::runtime::current_thread::Runtime::new().expect("failed to launch Runtime");
        // let handle = runtime.handle();
        // Spawn the runtime to a new thread...
        //
        // This thread will manage the actual resolution runtime
        thread::spawn(move || {
            // A runtime for this new thread
            let mut runtime = tokio::runtime::current_thread::Runtime::new().expect("failed to launch Runtime");
            // let mut runtime = tokio::runtime::Runtime::new().expect("");

            // our platform independent future, result, see next blocks
            let (resolver, bg) = {

                // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
                #[cfg(any(unix, windows))]
                {
                    // use the system resolver configuration
                    AsyncResolver::from_system_conf().expect("Failed to create AsyncResolver")
                }

                // For other operating systems, we can use one of the preconfigured definitions
                #[cfg(not(any(unix, windows)))]
                {
                    // Directly reference the config types
                    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

                    // Get a new resolver with the google nameservers as the upstream recursive resolvers
                    AsyncResolver::new(ResolverConfig::google(), ResolverOpts::default())
                }
            };

            let &(ref lock, ref cvar) = &*pair2;
            let mut started = lock.lock().unwrap();
            *started = Some(resolver);
            cvar.notify_one();
            drop(started);

            debug!("run global dns resolver");

            runtime.block_on(bg.compat()).expect("Failed to create DNS resolver");

            // tokio::runtime::current_thread::block_on_all(bg.compat());

            debug!("exist...");

            // runtime.run().unwrap();
            // runtime.block_on(futures::future::lazy(|_| {
            //             // tokio::runtime::current_thread::spawn(bg.compat().map(|_|{}));
            //             bg.compat()
            //             // debug!("exist...");
            //             // futures::future::ok(())
            //             // let ret: Result<(), RsocksError> = Ok(());
            //             // ret
            //         })
            // ).await;

            // tokio::spawn(async move {
            //     bg.compat().await.unwrap();
            //     debug!("exist...");
            // });
        });

        // Wait for the thread to start up.
        let &(ref lock, ref cvar) = &*pair;
        let mut resolver = lock.lock().unwrap();
        while resolver.is_none() {
            resolver = cvar.wait(resolver).unwrap();
            debug!("wait.......");
        }

        // take the started resolver
        let resolver = std::mem::replace(&mut *resolver, None);

        // set the global resolver
        resolver.expect("resolver should not be none")


        // let (resolver, bg) = {
        //     // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
        //     #[cfg(any(unix, windows))]
        //     {
        //         // use the system resolver configuration
        //         AsyncResolver::from_system_conf().expect("Failed to create AsyncResolver")
        //     }

        //     // For other operating systems, we can use one of the preconfigured definitions
        //     #[cfg(not(any(unix, windows)))]
        //     {
        //         // Directly reference the config types
        //         use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

        //         // Get a new resolver with the google nameservers as the upstream recursive resolvers
        //         AsyncResolver::new(ResolverConfig::google(), ResolverOpts::default())
        //     }
        // };


        // tokio::spawn(async move {
        //     bg.compat().await.unwrap();
        // });

        // // let ref resolver = resolver;

        // resolver
    };
}

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

    // let inside = stream.into_inner();

    let FramedParts {
        io,
        read_buf,
        write_buf,
        ..
    } = stream.into_parts();

    let mut new_parts = FramedParts::new(io, BytesCodec::new());

    new_parts.write_buf = write_buf;
    new_parts.read_buf = read_buf;

    let s1 = Framed::from_parts(new_parts);

    let s2 = Framed::new(outside, BytesCodec::new());

    Ok((s1, s2))
}

async fn socks_connect(
    mut stream: CmdFramed,
    req: CmdRequest,
) -> Result<(CmdFramed, TcpStream), RsocksError> {
    let addr = resolve_addr(&req).await?;

    let addr = SocketAddr::new(addr, req.port);
    trace!("try connect to {}", addr);

    let socket = TcpStream::connect(&addr).await;
    match socket {
        Ok(s) => {
            trace!("connected {:?}", req.address);
            let CmdRequest { address, port, .. } = req.clone();
            let resp = CmdResponse::new(Reply::Succeeded, address, port);
            stream.send(resp).await?;
            Ok((stream, s))
        }
        Err(e) => {
            let CmdRequest { address, port, .. } = req.clone();
            let reply = match e.kind() {
                io::ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                _ => Reply::CommandNotSupported,
            };
            let resp = CmdResponse::new(reply, address, port);
            stream.send(resp).await?;
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
        Address::DomainName(ref dn) => dns_resolver::resolver::dns_query(&dn).await,
        Address::Unknown(_t) => Err(socks_error("bad address")),
    }
}

// async fn dns_resolve(domain: &str) -> Result<IpAddr, RsocksError> {
//     // let ips = GLOBAL_DNS_RESOLVER.lookup_ip(domain).compat().await?;

//     // match ips.iter().next() {
//     //     Some(a) => Ok(a),
//     //     None => Err(socks_error("dns lookup failed.")),
//     // }
// }

// fn into_socks_streaming(
//     s: Framed<TcpStream, CmdCodec>,
//     c: TcpStream,
// ) -> (BytesFramed, BytesFramed) {
//     let FramedParts {
//         io,
//         read_buf,
//         write_buf,
//         ..
//     } = s.into_parts();

//     let mut new_parts = FramedParts::new(io, BytesCodec::new());

//     new_parts.write_buf = write_buf;
//     new_parts.read_buf = read_buf;

//     let s1 = Framed::from_parts(new_parts);

//     let s2 = Framed::new(c, BytesCodec::new());

//     (s1, s2)
// }

async fn socks_streaming(s1: BytesFramed, s2: BytesFramed) -> Result<(), RsocksError> {
    // let (mut a_sink, mut a_stream) = s1.split();
    // let (mut b_sink, mut b_stream) = s2.split();

    

    // b_stream.map(|b| b.unwrap().freeze()).forward();

    // let data = a_sink.read().await?;

    // tokio::io::copy(&mut a_stream, &mut b_sink);

    // a_sink.send_all(&mut b_stream).await.unwrap();
    // a_sink.copy(b_stream).await.unwrap();

    // let f1 = a_sink.send_all(&mut b_stream);
    // let f2 = b_sink.send_all(&mut a_stream);
    // let f1 = b_stream
    //     .map(|b| b.unwrap().freeze())
    //     .forward(a_sink.unwrap())
    //     .map_err(|e| error!("remote->local streaming error: {:?}", e));

    // let f2 = a_stream
    //     .map(|b| b.freeze())
    //     .forward(b_sink)
    //     .map_err(|e| error!("local->remotes streaming error: {:?}", e));

    // tokio::spawn(f1.join(f2).map(|_| ()));

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

    let addr = opt.host.parse().unwrap();

    let mut listener = TcpListener::bind(&addr).unwrap();

    info!("listening on {}", addr);

    loop {
        let (socket, _) = listener.accept().await.expect("accpet failed");

        tokio::spawn(async move {
            let handshaked = socks5_handshake(socket).await.unwrap();
            let (s1, s2) = socks5_cmd(handshaked).await.unwrap();
            socks_streaming(s1, s2).await.unwrap();
        });
    }
}
