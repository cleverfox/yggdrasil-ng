//! Low-level stream adapters for the optional QUIC and WebSocket transports.
//!
//! These modules provide only the connection primitives (an `AsyncRead +
//! AsyncWrite` adapter plus dial/listen helpers). All orchestration —
//! reconnect loops, backoff, ban checking — stays in `links.rs`, the same way
//! the built-in TCP/TLS transports are driven.

pub(crate) mod quic;
pub(crate) mod ws;
