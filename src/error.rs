use smoltcp::{
    socket::udp::{BindError, RecvError, SendError},
    wire::IpEndpoint,
};

#[cfg(feature = "std")]
use std::{ffi::NulError, io::Error as IoError, net::SocketAddr};

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Bind(BindError),
    Send(SendError),
    Recv(RecvError),
    /// An invalid TID.
    InvalidAddr(IpEndpoint),
    /// An erroneous nul byte was in the filename.
    #[cfg(all(feature = "std", unix))]
    Nul(NulError),
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

#[cfg(all(feature = "std", unix))]
impl From<NulError> for Error {
    fn from(value: NulError) -> Self {
        Self::Nul(value)
    }
}

#[cfg(feature = "std")]
impl From<IoError> for Error {
    fn from(value: IoError) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = core::result::Result<T, Error>;
