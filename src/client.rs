use crate::{
    error::{Error, Result},
    packet::{DATA_SIZE, META_SIZE, Packet, Type, netascii_from_u8},
};

use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket, UdpMetadata};

#[cfg(feature = "std")]
use std::{
    fs::File,
    io::Error as IoError,
    io::ErrorKind as IoErrorKind,
    io::Read,
    net::SocketAddr,
    path::Path,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

pub struct Client<'a> {
    /// The server address with destination port.
    server_addr: SocketAddr,
    socket: Socket<'a>,
    /// Current transfer ID (TID), or source port.
    transfer_id: u16,
    // // Optional: Filename for reading or writing.
    // filename: Option<String>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl<'a> Client<'a> {
    pub fn new(address: SocketAddr, server_addr: SocketAddr) -> Result<Self> {
        let rx_buffer = PacketBuffer::new(
            vec![PacketMetadata::EMPTY, PacketMetadata::EMPTY],
            vec![0u8; 65535],
        );
        let tx_buffer = PacketBuffer::new(
            vec![PacketMetadata::EMPTY, PacketMetadata::EMPTY],
            vec![0u8; 65535],
        );
        let mut socket = Socket::new(rx_buffer, tx_buffer);
        socket.bind(address)?;

        Ok(Self {
            server_addr,
            socket,
            transfer_id: 69,
            read_timeout: None,
            write_timeout: None,
        })
    }

    /// Receive a packet from the socket.
    fn recv_packet_unchecked(&mut self) -> Result<(Packet<&[u8]>, UdpMetadata)> {
        let (buf, meta) = self.socket.recv()?;
        let packet = Packet::new_checked(buf)?;
        Ok((packet, meta))
    }

    /// Receive a packet from the socket, validating the TID.
    pub fn recv_packet(&mut self) -> Result<(Packet<&[u8]>, UdpMetadata)> {
        let tid = self.transfer_id;
        let (packet, meta) = self.recv_packet_unchecked()?;
        if meta.endpoint.port != tid {
            todo!()
        }
        Ok((packet, meta))
    }

    #[cfg(unix)]
    /// Send a file.
    pub fn send_file(&mut self, path: &Path) -> Result<()> {
        // Filenames are chars on Unix systems and wide chars on Windows systems.
        // Rust makes this distinction apparent, but filenames are allowed to be non UTF-8.
        let file_name = path
            .file_name()
            .ok_or_else(|| {
                Error::Io(IoError::new(
                    IoErrorKind::IsADirectory,
                    "a filename was expected!",
                ))
            })?
            .as_bytes();
        // Validate that it is in fact netascii.
        let ascii_file_name = netascii_from_u8(file_name)?;
        let mut f = File::open(path)?;

        todo!(); // send WRQ packet.

        // The block number.
        let mut block = 0;
        loop {
            let mut packet = unsafe { Packet::new_unchecked([0; META_SIZE + DATA_SIZE]) };
            // Set metadata.
            packet.set_type(Type::Data.into());
            packet.set_block(block);
            match f.read(packet.data_mut()) {
                Ok(n) if n < 512 => {
                    // Resize the packet if too large.
                    let resized = &packet.as_ref()[..META_SIZE + n];
                    self.socket.send_slice(resized, self.server_addr)?;
                    break;
                }
                Ok(_) => self.socket.send_slice(packet.as_ref(), self.server_addr)?,
                Err(_) => todo!(),
            }
            block += 1;
        }
        todo!()
    }

    pub fn receive_file(&mut self, file_name: &str, data: &mut [u8]) -> Result<()> {
        let ascii_file_name = netascii_from_u8(file_name.as_bytes())?;
        todo!()
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }
}
