use core::fmt;
use serde_json;

#[derive(Debug, Clone)]
pub struct Error {
    pub err: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PolySign Error: {}", self.err)
    }
}
impl std::convert::From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error { err: format!("{}", error)}
    }
}

impl Error {
    pub fn new(err: &str) -> Error {
        Error {
            err: err.to_string(),
        }
    }
}
