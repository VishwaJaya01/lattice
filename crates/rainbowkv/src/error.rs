use thiserror::Error;

#[derive(Debug, Error)]
pub enum TableError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("file too small: {0} bytes")]
    FileTooSmall(usize),
    #[error("invalid magic")]
    InvalidMagic,
    #[error("unsupported version {0}")]
    UnsupportedVersion(u32),
    #[error("unsupported hash algorithm {0}")]
    UnsupportedHashAlg(u32),
    #[error("unsupported charset id {0}")]
    UnsupportedCharset(u8),
    #[error("unsupported password length {0}")]
    UnsupportedPasswordLen(u8),
    #[error("password space overflow")]
    SpaceOverflow,
    #[error("start_bits too large: {0}")]
    StartBitsTooLarge(u16),
    #[error("start_bits too small (expected {expected}, got {actual})")]
    StartBitsTooSmall { expected: u16, actual: u16 },
    #[error("chain count exceeds password space")]
    ChainCountTooLarge,
    #[error("index section out of bounds")]
    IndexOutOfBounds,
    #[error("starts section out of bounds")]
    StartsOutOfBounds,
    #[error("index length not multiple of entry size")]
    IndexMisaligned,
    #[error("index offset not aligned to entry size")]
    IndexOffsetMisaligned,
    #[error("chain index out of range")]
    ChainIndexOutOfRange,
    #[error("output buffer too small (needed {needed}, got {actual})")]
    OutputBufferTooSmall { needed: usize, actual: usize },
}

pub type Result<T> = std::result::Result<T, TableError>;
