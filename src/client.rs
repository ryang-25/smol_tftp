use std::net::{SocketAddr, UdpSocket};

pub struct Client {
    server_address: SocketAddr,
    socket: UdpSocket,
    // Current transfer ID (TID)
    transfer_id: u16,
    // Optional: Local file path for writing or reading
    local_file_path: Option<String>,
}
