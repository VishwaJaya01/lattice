//! Draft layout constants for the RainbowKV table format.
//!
//! See `docs/rainbowkv-format.md` for the full spec.

/// Magic header for RainbowKV tables.
pub const MAGIC: &[u8; 8] = b"LATRKV01";

/// Current on-disk format version.
pub const VERSION: u32 = 1;

/// Hash algorithm IDs.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u32)]
pub enum HashAlg {
    Ntlm = 1,
}

/// Fixed-size index entry (draft shape).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct IndexEntry {
    pub end_hash: [u8; 16],
    pub chain_index: u32,
}
