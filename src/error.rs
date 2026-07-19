//! The dig-message error taxonomy — stable, catalogued variants a scripted client can key off (§6.2).
//! WU1 owns the encoding/framing/compression failures; the seal/signature/replay variants arrive with
//! WU2/WU4.

use thiserror::Error;

/// Every fail-cleanly outcome of encoding, framing, or (de)compressing a dig-message (SPEC §1, §1.1,
/// §2). A receiver MUST reject — never panic — on any of these.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MessageError {
    /// The on-wire frame exceeds [`crate::MAX_ENVELOPE_BYTES`] (SPEC §1).
    #[error("envelope is {size} bytes, exceeds the {max}-byte cap")]
    EnvelopeTooLarge { size: usize, max: usize },

    /// The frame ended before a complete envelope could be decoded (SPEC §1).
    #[error("truncated envelope: {0}")]
    Truncated(String),

    /// The envelope declares a version this reader does not support (SPEC §2 field 1).
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),

    /// The compression algorithm id is not recognized (SPEC §1.1). Never mis-decode with a wrong codec.
    #[error("unsupported compression id {0}")]
    UnsupportedCompression(u8),

    /// The declared uncompressed length exceeds the bomb-guard cap (SPEC §1.1).
    #[error("declared uncompressed length {declared} exceeds the {max}-byte cap")]
    DecompressionBomb { declared: usize, max: usize },

    /// The decoded output length did not match the declared `uncompressed_len` (SPEC §1.1).
    #[error("decompressed length mismatch: expected {expected}, got {actual}")]
    DecompressedLengthMismatch { expected: usize, actual: usize },

    /// A payload's uncompressed length does not fit the `u32` wire field (SPEC §5.2).
    #[error("payload is {0} bytes, exceeds the u32 uncompressed_len field")]
    PayloadTooLarge(usize),

    /// A Streamable (de)serialization or codec-level failure with the underlying detail (SPEC §1).
    #[error("codec error: {0}")]
    Codec(String),
}

/// The crate result alias.
pub type Result<T> = std::result::Result<T, MessageError>;
