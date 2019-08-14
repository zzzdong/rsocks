#[derive(Debug, Fail)]
pub enum RsocksError {
    #[fail(display = "Parse error: {}", msg)]
    ParserError { msg: String },
    #[fail(display = "IO error: {}", error)]
    IoError { error: std::io::Error },
    #[fail(display = "Socks error: {}", msg)]
    SocksError { msg: String },
    #[fail(display = "Resolve error: {}", error)]
    ResolveError {
        error: trust_dns_resolver::error::ResolveError,
    },
    #[fail(display = "DNS resolve error: {}", msg)]
    DNSError {
         msg: String ,
    },
}

pub fn parser_error(msg: impl ToString) -> RsocksError {
    RsocksError::ParserError {
        msg: msg.to_string(),
    }
}

pub fn socks_error(msg: impl ToString) -> RsocksError {
    RsocksError::SocksError {
        msg: msg.to_string(),
    }
}

impl From<std::io::Error> for RsocksError {
    fn from(err: std::io::Error) -> RsocksError {
        RsocksError::IoError { error: err }
    }
}

impl From<trust_dns_resolver::error::ResolveError> for RsocksError {
    fn from(err: trust_dns_resolver::error::ResolveError) -> RsocksError {
        RsocksError::ResolveError { error: err }
    }
}
