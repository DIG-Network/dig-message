//! # dig-message — the DIG Network generic base message protocol
//!
//! ONE structured, typed, streamable, e2e-sealed envelope that every DIRECTED (1:1 / group) peer-to-
//! peer message rides (chat, email, video signaling, presence, directed data requests, peer-RPC, and
//! authenticated local IPC). Consensus BROADCAST (blocks/transactions/attestations) is the SPEC §5.4
//! exemption and stays mTLS-authenticated + signed, not dig-message-sealed.
//!
//! ## What WU1 (this milestone) provides — the crypto-free foundation
//! - [`DigMessageEnvelope`] + [`InnerMessage`] + [`StreamHeader`] + [`SealedPayload`] — the byte-
//!   deterministic Chia-Streamable wire shapes (SPEC §2, §5.2).
//! - [`encode_envelope`] / [`decode_envelope`] — the length-framed, size-bounded codec (SPEC §1).
//! - [`compress_payload`] / [`decompress_payload`] — the additive compression layer (raw + zstd) with
//!   the decompression-bomb guard (SPEC §1.1).
//! - The pinned protocol [`constants`] and the [`MessageError`] taxonomy.
//!
//! ## What WU2 (this milestone) adds — the e2e SEAL pipeline (SPEC §5)
//! - [`seal_message`] / [`open_message`] — the full compress → BLS-G2 sign → G1-DHKEM auth-seal (send)
//!   and unseal → verify → replay → expiry → decompress (receive) pipeline, fail-closed at each step.
//! - [`SealParams`] / [`OpenedMessage`] — the seal inputs + the opened, verified result.
//! - [`ReplayGuard`] — the SPEC §5.6 anti-replay state machine (freshness window + bounded
//!   sliding-window dedup + LRU sender cap).
//! - [`TranscriptFields`] — the domain-separated signed transcript (SPEC §5.1 / §5.1a).
//! - The seal uses `dig-identity`'s ONE BLS12-381 keypair (G2 sign + G1 DH); NO X25519, NO Ed25519.
//!
//! ## What later WUs add (the FIELDS are already final here)
//! - **WU4** drives the SPEC §3 streaming state machine over [`StreamHeader`].
//! - **WU5** adds the wasm/JS surface + the Rust↔wasm byte-agreement KAT.
//!
//! ## What WU3 (this milestone) adds — the extensible type registry (crypto-free, SPEC §4)
//! - [`MessageBand`] + [`MessageType::band`] — the reserved id-band allocation + classification.
//! - [`MessageKind`] — the compile-time seam a downstream type declares (id + typed payload).
//! - [`MessageRegistry`] — the runtime register/lookup/route table, additive-only, with the SPEC §4
//!   unknown-type rule (UNSUPPORTED_TYPE for request/stream, silent [`Dispatch::Dropped`] otherwise;
//!   never a panic).

pub mod compression;
pub mod constants;
pub mod envelope;
pub mod error;
pub mod registry;
pub mod replay;
pub mod seal;
pub mod transcript;

pub use compression::{
    compress_payload, decompress_payload, CompressedPayload, COMPRESSION_NONE, COMPRESSION_ZSTD,
};
pub use constants::*;
pub use envelope::{
    decode_envelope, encode_envelope, DigMessageEnvelope, InnerMessage, InteractionShape,
    MessageType, SealedPayload, StreamFrame, StreamHeader, FLAG_SEALED, FLAG_SHAPE_MASK,
};
pub use error::{MessageError, Result};
pub use registry::{
    Dispatch, MessageBand, MessageKind, MessageRegistry, BAND_CORE, BAND_DIG_CHAT, BAND_DIG_EMAIL,
    BAND_DIG_VIDEO, BAND_EXPERIMENTAL, BAND_IPC, BAND_PEER_RPC, BAND_PRESENCE,
};
pub use replay::ReplayGuard;
pub use seal::{open_message, seal_message, seal_with_ephemeral, OpenedMessage, SealParams};
pub use transcript::TranscriptFields;
