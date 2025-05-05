use crate::error::Result;

use smoltcp::socket::{
    AnySocket,
    Socket as SmolSocket,
    udp::PacketBuffer,
    udp::Socket as UdpSocket
};
use smoltcp::wire::IpListenEndpoint;

#[repr(transparent)]
pub struct Socket<'a>(UdpSocket<'a>);

impl<'a> Socket<'a> {
    pub fn new(rx_buffer: PacketBuffer<'a>, tx_buffer: PacketBuffer<'a>) -> Self {
        Socket(UdpSocket::new(rx_buffer, tx_buffer))
    }

    pub fn recv(&mut self) -> Result<()> {
        self.0.recv()
    }

    pub fn bind<T: Into<IpListenEndpoint>>(&mut self, endpoint: T) -> Result<()> {
        Ok(self.0.bind(endpoint)?)
    }
}

impl<'a> AsRef<Socket<'a>> for UdpSocket<'a> {
    fn as_ref(&self) -> &Socket<'a> {
        unsafe { core::mem::transmute(self) }
    }
}

impl<'a> AsMut<Socket<'a>> for UdpSocket<'a> {
    fn as_mut(&mut self) -> &mut Socket<'a> {
        unsafe { core::mem::transmute(self) }
    }
}


impl<'a> AnySocket<'a> for Socket<'a> {
    fn upcast(self) -> SmolSocket<'a> {
        SmolSocket::Udp(self.0)
    }

    fn downcast<'c>(socket: &'c SmolSocket<'a>) -> Option<&'c Self>
    where
        Self: Sized {
        match socket {
            SmolSocket::Udp(socket) => Some(socket.as_ref()),
        }
    }

    fn downcast_mut<'c>(socket: &'c mut SmolSocket<'a>) -> Option<&'c mut Self>
    where
        Self: Sized {
        match socket {
            SmolSocket::Udp(socket) => Some(socket.as_mut()),
        }
    }
}
