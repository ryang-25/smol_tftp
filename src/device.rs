/// A device built around the stdlib's UdpSocket.
use smoltcp::{
    phy::{DeviceCapabilities, Medium},
    time::Instant,
    wire::{IpAddress, IpEndpoint, Ipv4Packet, Ipv6Packet, UdpPacket},
};

use std::{
    io::{ErrorKind, Result},
    net::{IpAddr, SocketAddr, UdpSocket},
    time::Duration,
};

pub struct RxToken(Vec<u8>);
impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

pub struct TxToken<'a>(&'a UdpSocket);
impl<'a> smoltcp::phy::TxToken for TxToken<'a> {
    /// Consume a raw IP packet and send it over the socket.
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        let (payload, addr) = strip_ip_packet(&buffer);
        self.0.send_to(&payload, addr).unwrap();
        result
    }
}

/// Set basic UDP headers on a packet.
fn set_udp_headers<T: AsRef<[u8]> + AsMut<[u8]>>(
    src_addr: &IpEndpoint,
    dst_addr: &IpEndpoint,
    packet: &mut UdpPacket<T>,
    payload: &[u8],
) {
    packet.set_src_port(src_addr.port);
    packet.set_dst_port(dst_addr.port);
    packet.set_len((packet.as_ref().len()) as u16);
    packet.payload_mut().copy_from_slice(payload);
    packet.fill_checksum(&src_addr.addr, &dst_addr.addr);
}

/// Craft a minimal raw packet given a source and a destination
fn craft_raw_packet(src_addr: &IpEndpoint, dst_addr: &IpEndpoint, packet: &[u8]) -> Vec<u8> {
    let pkt_len = packet.len();
    match (src_addr.addr, dst_addr.addr) {
        (IpAddress::Ipv4(src), IpAddress::Ipv4(dst)) => {
            let mut buffer = vec![0; pkt_len + 20 + 8];
            let mut udp_packet = UdpPacket::new_unchecked(&mut buffer[20..]);
            set_udp_headers(src_addr, dst_addr, &mut udp_packet, packet);

            // Set IPv4 headers.
            let mut ip_packet = Ipv4Packet::new_unchecked(&mut buffer);
            ip_packet.set_version(4);
            ip_packet.set_next_header(smoltcp::wire::IpProtocol::Udp);
            ip_packet.set_dont_frag(true);
            ip_packet.set_hop_limit(64);
            ip_packet.set_total_len(ip_packet.as_ref().len() as u16);
            ip_packet.set_src_addr(src);
            ip_packet.set_dst_addr(dst);
            ip_packet.set_header_len(20);
            ip_packet.fill_checksum();

            buffer
        }
        (IpAddress::Ipv6(src), IpAddress::Ipv6(dst)) => {
            let mut buffer = vec![0; pkt_len + 40 + 8];
            let mut udp_packet = UdpPacket::new_unchecked(&mut buffer[40..]);
            let udp_len = udp_packet.as_ref().len();
            set_udp_headers(src_addr, dst_addr, &mut udp_packet, packet);

            // Set IPv6 headers.
            let mut ip_packet = Ipv6Packet::new_unchecked(&mut buffer);
            ip_packet.set_version(6); // always 6
            ip_packet.set_next_header(smoltcp::wire::IpProtocol::Udp);
            ip_packet.set_payload_len(udp_len as u16);
            ip_packet.set_hop_limit(64);
            ip_packet.set_src_addr(src);
            ip_packet.set_dst_addr(dst);

            buffer
        }
        _ => panic!("expected both source and destination to be same version!"),
    }
}

fn strip_ip_packet(packet: &[u8]) -> (&[u8], SocketAddr) {
    let version = packet[0] >> 4;
    if version == 4 {
        let ip_packet = Ipv4Packet::new_unchecked(packet);
        let udp_packet = UdpPacket::new_unchecked(ip_packet.payload());
        let addr = SocketAddr::new(ip_packet.dst_addr().into(), udp_packet.dst_port());
        (udp_packet.payload(), addr)
    } else {
        let ip_packet = Ipv6Packet::new_unchecked(packet);
        let udp_packet = UdpPacket::new_unchecked(ip_packet.payload());
        let addr = SocketAddr::new(ip_packet.dst_addr().into(), udp_packet.dst_port());
        (udp_packet.payload(), addr)
    }
}

// smoltcp expects a device. We'll try make something with a regular UdpSocket to avoid TUN/TAP.
pub struct UdpSocketDevice {
    socket: UdpSocket,
    src_addr: IpEndpoint,
}

impl UdpSocketDevice {
    // We create a socket "device" by wrapping a UdpSocket from std.
    pub fn new(src_addr: SocketAddr) -> Result<(Self, SocketAddr)> {
        let socket = UdpSocket::bind(src_addr)?;
        // If we bind to an ephemeral port the OS selects one for us, so the port that was bound may differ from the original.
        let bound_addr = socket.local_addr()?;
        // Set timeouts so that we don't block indefinitely.
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        socket.set_write_timeout(Some(Duration::from_millis(500)))?;
        Ok((
            Self {
                socket,
                src_addr: bound_addr.into(),
            },
            bound_addr,
        ))
    }

    /// Calls underlying connect method on the socket.
    pub fn connect(&mut self, dst_addr: &IpEndpoint) -> Result<()> {
        let addr: IpAddr = dst_addr.addr.into();
        let port = dst_addr.port;
        self.socket.connect((addr, port))
    }
}

/// This is a hack! We don't have raw access to IP headers, but we pretend like we do.
impl smoltcp::phy::Device for UdpSocketDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut buffer = vec![0; 1500];
        match self.socket.recv_from(&mut buffer) {
            Ok((size, dst_addr)) => {
                buffer.resize(size, 0);
                // swap source and destination when receiving.
                let raw = craft_raw_packet(&dst_addr.into(), &self.src_addr, &buffer);
                let rx = RxToken(raw);
                let tx = TxToken(&self.socket);
                Some((rx, tx))
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => None,
            Err(e) => panic!("{e}"),
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken(&self.socket))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        // TODO: figure out the hardcoding here...
        capabilities.max_transmission_unit = 1500;
        capabilities
    }
}
