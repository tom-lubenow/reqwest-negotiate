//! HTTP Negotiate authentication using native Kerberos or a pure Rust cache client.
//!
//! The default `native` feature exposes `NegotiateAuthExt` and the original
//! system GSSAPI/SSPI integration. For file-backed tickets without system
//! Kerberos libraries, disable default features and enable `pure-rust`.
//! See `pure_rust` for the async cache client (requires `pure-rust`).

#[cfg(feature = "native")]
mod native;
#[cfg(feature = "native")]
pub use native::*;

#[cfg(feature = "pure-rust")]
pub mod pure_rust;
