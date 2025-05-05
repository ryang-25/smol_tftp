#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[macro_use]
mod macros;

pub mod error;
pub mod packet;

#[cfg(feature = "std")]
pub mod device;

pub mod client;
#[cfg(feature = "std")]
mod server;
