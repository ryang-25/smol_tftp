#[macro_use]
mod macros;

mod error;
pub mod packet;
// mod socket;

#[cfg(feature = "std")]
mod client;
#[cfg(feature = "std")]
mod server;
