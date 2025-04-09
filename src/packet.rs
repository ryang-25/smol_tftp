//! TFTP Protocol (Revision 2)
//! from https://datatracker.ietf.org/doc/html/rfc1350
//!

use core::ffi::CStr;
use core::str::from_utf8_unchecked;

use crate::error::Result;

/// The max number of bytes sent at a time.
pub const DATA_SIZE: usize = 512;

pub const META_SIZE: usize = 4;

enum_with_unknown! {
    /// The five TFTP packet types. 2 bytes in length.
    pub enum Type(u16) {
        /// Read request (RRQ)
        Rrq = 0x1,
        /// Write request (WRQ)
        Wrq = 0x2,
        /// Data (DATA)
        Data = 0x3,
        /// Acknowledgement (ACK)
        Ack = 0x4,
        /// Error (ERROR)
        Error = 0x5
    }
}

mod field {
    use core::ops::{Range, RangeFrom};

    pub(crate) const TYPE: Range<usize> = 0..1;
    pub const FILENAME: RangeFrom<usize> = 2..;
    pub const BLOCK: Range<usize> = 2..3;
    pub const CODE: Range<usize> = 2..3;
    pub const MSG: RangeFrom<usize> = 3..;
}

/// A TFTP packet.
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Construct a new TFTP packet.
    pub const unsafe fn new_unchecked(buffer: T) -> Self {
        Packet { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = unsafe { Self::new_unchecked(buffer) };
        packet.check_len()?;
        Ok(packet)
    }

    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < 2 {
            todo!();
        }
        match self.type_() {
            Type::Data if len >= 4 => Ok(()),
            Type::Ack if len == 4 => Ok(()),
            _ => todo!(),
        }
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }


    /// Return the type of the packet.
    pub fn type_(&self) -> Type {
        unsafe { read_be_u16(&self.buffer.as_ref()[field::TYPE]).into() }
    }

    ///
    ///
    /// or if the filename is not
    /// encoded in netascii.
    pub fn filename(&self) -> Result<&str> {
        match self.type_() {
            Type::Rrq | Type::Wrq => netascii_from_u8(&self.buffer.as_ref()[field::FILENAME]),
            _ => Err(todo!()),
        }

        // netascii_from_u8(&self.buffer.as_ref()[FILENAME])
    }

    /// Reads the block number of the packet. Panics if the packet is missing
    /// a block number.
    pub fn block(&self) -> u16 {
        let b = &self.buffer.as_ref()[field::BLOCK];
        if b.len() < 2 {
            todo!()
        }
        unsafe { read_be_u16(b) }
    }

    pub fn data(&self) -> &[u8] {
        todo!()
    }

    fn mode(&self) -> &str {
        todo!()
    }

    fn error_code() {}

    fn error_msg() {}
}

impl<T> Packet<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Set the type of the packet.
    pub fn set_type(&mut self, type_: u16) {
        self.buffer.as_mut()[field::TYPE].copy_from_slice(&type_.to_be_bytes());
    }

    pub fn set_block(&mut self, block: u16) {
        self.buffer.as_mut()[field::BLOCK].copy_from_slice(&block.to_be_bytes());
    }

    pub fn set_code(&mut self, code: u16) {
        self.buffer.as_mut()[field::CODE].copy_from_slice(&code.to_be_bytes());
    }

    pub fn set_msg(&mut self, msg: &CStr) {
        self.buffer.as_mut()[field::MSG].copy_from_slice(msg.to_bytes_with_nul());
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        todo!()
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}


pub enum Repr<'a> {
    // data field of data may only be 512 bytes in length.
    Rrq { filename: &'a str, mode: &'a str },
    Wrq { filename: &'a str, mode: &'a str },
    Data { block: u16, data: &'a [u8] },
    Ack { block: u16 },
    Error { code: u16, msg: &'a str },
}

impl<'a> Repr<'a> {
    pub fn parse<T>(packet: &'a Packet<T>) -> Result<Self>
    where
        T: AsRef<[u8]>,
    {
        packet.check_len()?;
        match packet.type_() {
            Type::Data => Ok(Repr::Data {
                block: packet.block(),
                data: packet.data(),
            }),
            _ => todo!(),
        }

        // todo!()
    }

    pub fn emit<T>(&self, packet: &mut Packet<T>)
    where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        match *self {
            Repr::Data { block, data } => {
                packet.set_type(Type::Data.into());
                packet.set_block(block);
                packet.data_mut()[..data.len()].copy_from_slice(data);
            }
            Repr::Ack { block } => {
                packet.set_type(Type::Ack.into());
                packet.set_block(block);
            }
            Repr::Error { code, msg } => {
                packet.set_type(Type::Error.into());
                packet.set_code(code);
                let cstr = CStr::from_bytes_until_nul(msg.as_bytes()).unwrap();
                packet.set_msg(cstr);
            }
            _ => todo!(),
        }
    }
}

struct Header {}

/// Read a slice of exactly two bytes as a big endian u16.
///
/// # Safety
///`buf` must be a slice of length `>= 2`.
unsafe fn read_be_u16(buf: &[u8]) -> u16 {
    let ptr: &[u8; 2] = unsafe { &*buf.as_ptr().cast() };
    u16::from_be_bytes(*ptr)
}

fn validate_netascii(s: &str) -> bool {
    todo!()
}

/// Converts a slice of bytes into a netascii string slice.
///
/// netascii, as defined in RFC 764, is a 8 bit extension of the printable
/// ascii characters and eight other control characters.
///
/// This will likely be a lot slower than the internal UTF-8 validation.
pub fn netascii_from_u8(v: &[u8]) -> Result<&str> {
    let mut r = false;
    for i in 0..v.len() {
        match v[i] {
            b' '..=b'~' | b'\x07'..b'\r' if !r => continue,
            b'\n' if r => r = false,
            b'\r' if !r => r = true,
            b'\0' if i == v.len() - 1 => break,
            _ => return Err(todo!()),
        }
    }
    unsafe { Ok(from_utf8_unchecked(v)) }
}

fn memchr<T>(buf: &[T], needle: T) -> Option<usize>
where
    T: core::cmp::PartialEq + core::marker::Copy,
{
    buf.iter().position(|&b| b == needle)
}
