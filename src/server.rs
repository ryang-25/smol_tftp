use std::collections::HashMap;
use std::fs::File;
use std::net::{SocketAddr, UdpSocket};

pub struct Server {
    socket: UdpSocket,
    // Store active transfers: (client_address, transfer_id) -> File
    active_transfers: HashMap<(SocketAddr, u16), File>,
    // Root directory for file access
    root_dir: String,
    // The next available transfer ID
    next_tid: u16,
}
