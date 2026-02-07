//! RainbowKV zero-copy lookup engine.
//!
//! The on-disk format is documented in `docs/rainbowkv-format.md`.
//! This crate exposes mmap-backed, zero-allocation lookup APIs.

pub mod error;
pub mod format;
mod md4;
pub mod reduction;
pub mod table;

pub use crate::table::{LookupHit, LookupResult, Table};
