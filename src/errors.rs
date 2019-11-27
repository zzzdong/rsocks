#[derive(Debug, Fail)]
pub enum RsocksError {
    #[fail(display = "Parse error: {}", msg)]
    ParserError { msg: String },
    #[fail(display = "IO error: {}", error)]
    IoError { error: std::io::Error },
    #[fail(display = "Socks error: {}", msg)]
    SocksError { msg: String },
    #[fail(display = "Timeout error: {}", error)]
    TimeoutError { error: tokio::time::Elapsed },
    #[fail(display = "DNS resolve error: {}", msg)]
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

impl From<std::io::Error> for RsocksError {
    fn from(err: std::io::Error) -> RsocksError {
        RsocksError::IoError { error: err }
    }
}

impl From<tokio::time::Elapsed> for RsocksError {
    fn from(err: tokio::time::Elapsed) -> RsocksError {
        RsocksError::TimeoutError { error: err }
    }
}
