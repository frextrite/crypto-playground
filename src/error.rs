use ring::error::Unspecified;

#[derive(Debug)]
pub(crate) enum Error {
    Crypto,
    Io(std::io::Error),
    Utf8(std::str::Utf8Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Crypto => write!(f, "Cryptographic error"),
            Error::Io(err) => write!(f, "I/O error: {}", err),
            Error::Utf8(err) => write!(f, "UTF-8 error: {}", err),
        }
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(_err: ring::error::Unspecified) -> Self {
        Self::Crypto
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::Utf8(err)
    }
}

pub(crate) type CryptoResult<T> = Result<T, Unspecified>;
