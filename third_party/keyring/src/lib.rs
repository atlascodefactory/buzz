//! Buzz-local v1 facade of keyring 4.2.0; see ../README.buzz.md.
#[cfg(not(feature = "v1"))]
compile_error!("The Buzz keyring patch requires v1");
#[cfg(feature = "v1")]
pub mod v1;
#[cfg(feature = "v1")]
pub use v1::*;
