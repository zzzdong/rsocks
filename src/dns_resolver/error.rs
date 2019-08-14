use snafu::{Snafu, ResultExt, Backtrace, ErrorCompat, ensure};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("parse error, {}", msg))]
    ParserFail{ msg: String },
}

