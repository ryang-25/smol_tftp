use smoltcp::socket::udp::{BindError, SendError, RecvError};

#[cfg(feature = "std")]
use std::io::Error as IoError;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Bind(BindError),
    Send(SendError),
    Recv(RecvError),
    #[cfg(feature = "std")]
    Io(IoError),
}

impl From<BindError> for Error {
    fn from(value: BindError) -> Self {
        Self::Bind(value)
    }
}

impl From<RecvError> for Error {
    fn from(value: RecvError) -> Self {
        Self::Recv(value)
    }
}

impl From<SendError> for Error {
    fn from(value: SendError) -> Self {
        Self::Send(value)
    }
}

#[cfg(feature = "std")]
impl From<IoError> for Error {
    fn from(value: IoError) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = core::result::Result<T, Error>;
