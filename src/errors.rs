use thiserror::Error;

#[derive(Debug, Error)]
pub enum RsocksError {
    #[error("Parse error: {}", msg)]
    ParserError { msg: String },
    #[error("IO error: {}", 0)]
    IoError(#[from] std::io::Error),
    #[error("Socks error: {}", msg)]
    SocksError { msg: String },
    #[error("Timeout error: {}", 0)]
    TimeoutError(#[from] tokio::time::error::Elapsed),
    #[error("DNS resolve error: {}", msg)]
    DNSError { msg: String },
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

pub fn dns_error(msg: impl ToString) -> RsocksError {
    RsocksError::DNSError {
        msg: msg.to_string(),
    }
}
