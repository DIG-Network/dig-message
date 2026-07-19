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

    /// The `message_type` is not registered (SPEC §4). Returned when the dispatch shape is a request or
    /// stream frame so the caller can reply UNSUPPORTED_TYPE; an unknown one-shot/response is instead
    /// silently dropped (never surfaced as an error — the forward-compat property).
    #[error("unsupported message type {0:#010x}")]
    UnsupportedType(u32),

    /// A [`crate::MessageType`] was registered twice (SPEC §4 additive-only: an id, once assigned, is
    /// never renumbered or repurposed). A duplicate registration is a caller bug, reported — never
    /// silently overwriting the existing handler.
    #[error("message type {0:#010x} is already registered")]
    DuplicateType(u32),

    // --- WU2: the seal / signature / replay / expiry pipeline (SPEC §5) ---
    /// A received G1 point (the `kem_enc` encapsulation or the resolved sender key) failed the
    /// mandatory prime-order subgroup / non-identity check BEFORE any DH (SPEC §5.1). Fail-closed:
    /// blocks small-subgroup / invalid-curve key-recovery attacks.
    #[error("G1 subgroup / non-identity check failed on the seal key material")]
    InvalidPoint,

    /// The sender DID could not be resolved to a BLS G1 identity key at the claimed epoch (SPEC §5.2).
    /// An unknown/unresolvable sender means the seal cannot be authenticated — fail-closed.
    #[error("sender DID could not be resolved to an identity key")]
    UnresolvableSender,

    /// Sealing failed to produce ciphertext (an AEAD encrypt or ephemeral-key error, SPEC §5.1).
    #[error("seal failed: {0}")]
    SealFailed(String),

    /// The AEAD open failed — a wrong recipient key, wrong sender key, tampered ciphertext, or
    /// tampered AAD header all land here (SPEC §5.1/§5.2). Fail-closed, no plaintext is revealed.
    #[error("seal open failed (wrong key or tampered ciphertext/header)")]
    OpenFailed,

    /// The mandatory BLS G2 sender signature was absent, malformed, or did not verify against the
    /// resolved sender key over `SIG_DOMAIN || transcript` (SPEC §5.1). Fail-closed REJECT.
    #[error("BLS sender signature verification failed")]
    BadSignature,

    /// The sealed inner `message_type`/`correlation_id` did not equal the cleartext header — an
    /// anti type-confusion / anti-splice REJECT (SPEC §5.2 step b).
    #[error("sealed inner header does not match the cleartext header (type-confusion / splice)")]
    HeaderMismatch,

    /// The message is a replay or is stale: a duplicate counter, a counter below the sliding window,
    /// or a `timestamp_ms` outside the freshness window (SPEC §5.6). Fail-closed DROP.
    #[error("anti-replay check failed (duplicate, stale, or outside the freshness window)")]
    Replay,

    /// The message is past its sender-controlled `expires_at` TTL and is DISCARDED with no side
    /// effect (SPEC §5.6b).
    #[error("message expired (now > expires_at)")]
    Expired,

    /// `expires_at` exceeds `timestamp_ms + MAX_MESSAGE_TTL_MS` — a near-infinite validity claim,
    /// REJECTED (never clamped, since clamping would alter signed content) (SPEC §5.6b).
    #[error("expires_at exceeds the maximum message TTL")]
    TtlTooLong,
}

/// The crate result alias.
pub type Result<T> = std::result::Result<T, MessageError>;
