//! The client module provides TFTP client implementations that can be used to send and receive data.
#[cfg(feature = "std")]
use crate::device::UdpSocketDevice;
use crate::{
    error::{Error, Result},
    // file::PacketChunks,
    packet::{DATA_SIZE, META_SIZE, PACKET_SIZE, Packet, Type},
};

use core::ffi::CStr;
use managed::ManagedSlice;
use smoltcp::{
    iface::{
        Config, Interface, PollIngressSingleResult, PollResult, SocketHandle, SocketSet,
        SocketStorage,
    },
    phy::Device,
    socket::udp::{Socket as UdpSocket, UdpMetadata},
    storage::PacketBuffer,
    time::Instant,
    wire::IpEndpoint,
};

#[cfg(all(feature = "std", unix))]
use std::os::unix::ffi::OsStrExt;
#[cfg(feature = "std")]
use std::{
    ffi::CString, fs::File, io::Error as IoError, io::ErrorKind as IoErrorKind, io::Read,
    io::Write, net::SocketAddr, path::Path,
};

#[cfg(feature = "std")]
pub struct StdClient<'a>(Client<'a, UdpSocketDevice>);

#[cfg(feature = "std")]
impl<'a> StdClient<'a> {
    /// hello!
    pub fn new(addr: SocketAddr, server_addr: SocketAddr) -> Result<Self> {
        use smoltcp::socket::udp::PacketMetadata;

        let (device, bound_addr) = UdpSocketDevice::new(addr)?;
        let rx_buffer = PacketBuffer::new(
            vec![PacketMetadata::EMPTY, PacketMetadata::EMPTY],
            vec![0u8; 65535],
        );
        let tx_buffer = PacketBuffer::new(
            vec![PacketMetadata::EMPTY, PacketMetadata::EMPTY],
            vec![0u8; 65535],
        );
        let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        let sockets = [SocketStorage::EMPTY; 1];

        Ok(Self(Client::new(
            bound_addr.into(),
            server_addr.into(),
            rx_buffer,
            tx_buffer,
            sockets,
            config,
            device,
            Instant::now(),
        )?))
    }

    #[cfg(unix)]
    pub fn send_file(&'a mut self, path: &Path, mode: &CStr) -> Result<()> {
        // Filenames are chars on Unix systems and wide chars on Windows systems.
        // Rust makes this distinction apparent, but real filenames can be non UTF-8,
        // while TFTP does not allow this.
        let file_name = path.file_name().ok_or_else(|| {
            Error::Io(IoError::new(
                IoErrorKind::IsADirectory,
                "a filename was expected!",
            ))
        })?;
        let file_name = CString::new(file_name.as_bytes())?;
        let mut f = File::open(path)?;

        // Scratch buffer
        let mut buf = vec![0; META_SIZE + file_name.count_bytes() + mode.count_bytes()];
        // Start the write connection.
        let mut conn = self.0.start_write(&file_name, mode, &mut buf)?;
        f.read_to_end(&mut buf)?;
        conn.write_file(&buf)
    }

    pub fn receive_file<W: Write>(
        &'a mut self,
        file_name: &CStr,
        mode: &CStr,
        writer: &mut W,
    ) -> Result<()> {
        let mut buf = vec![0; META_SIZE + file_name.count_bytes() + mode.count_bytes()];
        self.0
            .start_read(file_name, mode, &mut buf)?
            .read_file_io(writer)
    }
}

/// A client that wraps smoltcp primitives.
pub struct Client<'a, T: Device> {
    /// The server address with TID.
    server_addr: IpEndpoint,
    /// Our socket storage
    sockets: SocketSet<'a>,
    /// Our UDP socket handle
    handle: SocketHandle,
    /// The device interface
    iface: Interface,
    /// Our device for RX/TX.
    device: T,
}

impl<'a, T: Device> Client<'a, T> {
    /// Create a new client from a device.
    pub fn new<U>(
        addr: IpEndpoint,
        server_addr: IpEndpoint,
        rx_buffer: PacketBuffer<'a, UdpMetadata>,
        tx_buffer: PacketBuffer<'a, UdpMetadata>,
        sockets: U,
        config: Config,
        mut device: T,
        now: Instant,
    ) -> Result<Self>
    where
        U: Into<ManagedSlice<'a, SocketStorage<'a>>>,
    {
        let mut socket = UdpSocket::new(rx_buffer, tx_buffer);
        socket.bind(addr)?;
        // [SocketStorage::EMPTY; 1]
        let mut sockets = SocketSet::new(sockets);
        let handle = sockets.add(socket);
        let iface = Interface::new(config, &mut device, now);
        Ok(Self {
            server_addr,
            sockets,
            handle,
            iface,
            device,
        })
    }

    /// Receive a packet on the socket from any source.
    pub fn recv_packet_from(&mut self) -> Result<(Packet<&[u8]>, UdpMetadata)> {
        let (buf, meta) = self.sockets.get_mut::<UdpSocket>(self.handle).recv()?;
        let packet = Packet::new_checked(buf)?;
        Ok((packet, meta))
    }

    /// Receive a packet, validating the source and TID.
    pub fn recv_packet(&mut self) -> Result<Packet<&[u8]>> {
        let (buf, meta) = self.sockets.get_mut::<UdpSocket>(self.handle).recv()?;
        let endpoint = meta.endpoint;
        if endpoint != self.server_addr {
            return Err(Error::InvalidAddr(endpoint));
        }
        Packet::new_checked(buf)
    }

    /// Send a packet to our server address.
    pub fn send_packet<U: AsRef<[u8]>>(&mut self, packet: Packet<U>) -> Result<()> {
        self.sockets
            .get_mut::<UdpSocket>(self.handle)
            .send_slice(packet.as_ref(), self.server_addr)?;
        Ok(())
    }

    /// Open a read connection with file_name and the specified mode.
    pub fn start_read(
        &'a mut self,
        file_name: &CStr,
        mode: &CStr,
        buffer: &mut [u8],
    ) -> Result<ReadConnection<'a, T>> {
        // Construct our RRQ packet.
        if buffer.len() < META_SIZE + file_name.count_bytes() + mode.count_bytes() {
            todo!("buffer is too small!")
        }

        // SAFETY: buffer length is validated immediately before
        let mut rrq_packet = unsafe { Packet::new_unchecked(buffer) };
        rrq_packet.set_type(Type::Rrq.into());
        rrq_packet.set_file_name(file_name);
        rrq_packet.set_mode(mode);

        // Send the packet.
        self.send_packet(rrq_packet)?;
        self.iface
            .poll_egress(Instant::ZERO, &mut self.device, &mut self.sockets);

        // Wait for our first DATA packet, which originates from the server's TID.
        loop {
            while let PollIngressSingleResult::None =
                self.iface
                    .poll_ingress_single(Instant::ZERO, &mut self.device, &mut self.sockets)
            {
            }
            // Allocate space for the first packet.
            let mut first = [0; PACKET_SIZE];
            // Obtain the packet size from the network to resize too-small packets.
            let (size, meta) = self
                .sockets
                .get_mut::<UdpSocket>(self.handle)
                .recv_slice(&mut first)?;
            let packet = Packet::new_checked(first)?;
            if packet.type_() != Type::Data {
                todo!();
            }
            self.server_addr = meta.endpoint;
            return Ok(ReadConnection {
                client: self,
                packet,
                size,
            });
        }
    }

    /// Start a write connection with the given file_name and mode.
    pub fn start_write(
        &'a mut self,
        file_name: &CStr,
        mode: &CStr,
        buffer: &mut [u8],
    ) -> Result<WriteConnection<'a, T>> {
        // Craft the WRQ packet.
        if buffer.len() < META_SIZE + file_name.count_bytes() + mode.count_bytes() {
            todo!("buffer is too small!")
        }

        let mut wrq_packet = unsafe { Packet::new_unchecked(buffer) };
        wrq_packet.set_type(Type::Wrq.into());
        wrq_packet.set_file_name(file_name);
        wrq_packet.set_mode(mode);

        // Send the packet.
        self.send_packet(wrq_packet)?;

        // Wait for our first ACK packet.
        loop {
            while let PollResult::None =
                self.iface
                    .poll(Instant::ZERO, &mut self.device, &mut self.sockets)
            {}
            let (ack, meta) = self.sockets.get_mut::<UdpSocket>(self.handle).recv()?;
            let ack_packet = Packet::new_checked(ack)?;
            if ack_packet.type_() != Type::Ack {
                todo!();
            }
            self.server_addr = meta.endpoint;
            return Ok(WriteConnection { client: self });
        }
    }
}

/// An opaque struct that represents an established read connection.
pub struct ReadConnection<'a, T: Device> {
    // An internal client wrapper
    client: &'a mut Client<'a, T>,
    // The size of the first packet, used for resizing.
    size: usize,
    // A buffer to hold the first data packet.
    packet: Packet<[u8; PACKET_SIZE]>,
}

impl<'a, T: Device> ReadConnection<'a, T> {
    /// A read connection reads a file from the socket. Panics if the buffer is smaller than the data received.
    pub fn read_file(&mut self, buf: &mut [u8]) -> Result<()> {
        let size = self.size - META_SIZE;
        // Copy the first data packet into the buffer.
        buf[0..size].copy_from_slice(self.packet.data());
        if size < DATA_SIZE {
            return Ok(()); // leave if less than one packet is transferred
        }

        let mut start = size;
        loop {
            let client = &mut self.client;
            // Spin if there's no work to be done
            while let PollIngressSingleResult::None = client.iface.poll_ingress_single(
                Instant::ZERO,
                &mut client.device,
                &mut client.sockets,
            ) {
                // should we sleep between polls?
            }
            let (pkt, meta) = client.sockets.get_mut::<UdpSocket>(client.handle).recv()?;
            if meta.endpoint != client.server_addr {
                todo!("send an error packet if tid validation fails!");
            }
            let packet = Packet::new_checked(pkt)?;
            if packet.type_() != Type::Data {
                todo!();
            }
            let len = packet.data().len();
            buf[start..start + len].copy_from_slice(packet.data());
            if len < DATA_SIZE {
                return Ok(());
            }
            // Advance to next
            start += len;
        }
    }

    /// A read connection reads a file from the socket, writing it with a writer.
    #[cfg(feature = "std")]
    pub fn read_file_io<W: Write>(&mut self, writer: &mut W) -> Result<()> {
        let size = self.size - META_SIZE;
        writer.write(self.packet.data())?;
        if size < DATA_SIZE {
            return Ok(()); // leave if less than one packet is transferred
        }

        loop {
            let client = &mut self.client;
            // Spin if there's no work to be done
            while let PollIngressSingleResult::None = client.iface.poll_ingress_single(
                Instant::ZERO,
                &mut client.device,
                &mut client.sockets,
            ) {
                // should we sleep between polls?
                println!("hellooo");
            }
            let (pkt, meta) = client.sockets.get_mut::<UdpSocket>(client.handle).recv()?;
            if meta.endpoint != client.server_addr {
                todo!("send an error packet if tid validation fails!");
            }
            let packet = Packet::new_checked(pkt)?;
            if packet.type_() != Type::Data {
                todo!();
            }
            writer.write(packet.data())?;
            let len = packet.data().len();
            if len < DATA_SIZE {
                return Ok(());
            }
        }
    }
}

pub struct WriteConnection<'a, T: Device> {
    client: &'a mut Client<'a, T>,
}

impl<'a, T: Device> WriteConnection<'a, T> {
    /// Start writing a file by splitting it into chunks and sending one by one.
    pub fn write_file(&mut self, data: &[u8]) -> Result<()> {
        let client = &mut self.client;
        let mut chunks = data.chunks(DATA_SIZE);
        let mut block = 0;
        while let Some(chunk) = chunks.next() {
            // SAFETY: buffer is statically sized.
            let mut packet = unsafe { Packet::new_unchecked([0; PACKET_SIZE]) };
            packet.set_type(Type::Data.into());
            packet.set_block(block);
            packet.data_mut().copy_from_slice(chunk);

            // Send the packet.
            client
                .sockets
                .get_mut::<UdpSocket>(client.handle)
                .send_slice(packet.as_ref(), client.server_addr)?;

            while let PollResult::None =
                client
                    .iface
                    .poll(Instant::ZERO, &mut client.device, &mut client.sockets)
            {}
            // TODO: handle erroneous packets
            block += 1;
        }
        Ok(())
    }
}
