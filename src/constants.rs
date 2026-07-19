//! Protocol constants — the pinned, normative values every conforming implementation shares (SPEC §1,
//! §1.1, §2, §5.6, §5.6b). These are the byte-level contract; a second implementation MUST match them.

/// Current envelope format version (SPEC §2 field 1). A newer reader accepts older versions; an
/// unknown newer version is rejected `UnsupportedVersion`.
pub const ENVELOPE_VERSION: u8 = 1;

/// Hard cap on the on-wire compressed+sealed frame (SPEC §1). A receiver rejects an over-cap or
/// truncated envelope before decoding.
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Hard cap on the declared + actual decompressed size of a single message (SPEC §1.1 bomb guard).
pub const MAX_DECOMPRESSED_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Per-stream-chunk on-wire cap (SPEC §3).
pub const MAX_CHUNK_BYTES: usize = 1024 * 1024; // 1 MiB

/// Per-stream-chunk decompressed cap (SPEC §1.1 / §3). Equal to [`MAX_CHUNK_BYTES`].
pub const MAX_CHUNK_DECOMPRESSED_BYTES: usize = MAX_CHUNK_BYTES;

/// Below this size (or when compression does not shrink), a sender MUST use the raw codec (SPEC §1.1).
pub const MIN_COMPRESS_BYTES: usize = 64;

/// Pinned zstd level (SPEC §1.1: level 3, zstd default, no dictionary, single-frame — deterministic
/// across the Rust and wasm/JS targets).
pub const ZSTD_LEVEL: i32 = 3;

/// Anti-replay freshness window in milliseconds (±5 min) (SPEC §5.6). Enforcement is WU4.
pub const FRESHNESS_WINDOW_MS: u64 = 300_000;

/// Anti-replay sliding-window width in bits (SPEC §5.6). Enforcement is WU4.
pub const REPLAY_WINDOW: usize = 1024;

/// LRU cap on tracked senders for the anti-replay table (SPEC §5.6). Enforcement is WU4.
pub const MAX_TRACKED_SENDERS: usize = 100_000;

/// Maximum sender-controlled message TTL in milliseconds (30 days) (SPEC §5.6b). Enforcement is WU4.
pub const MAX_MESSAGE_TTL_MS: u64 = 2_592_000_000;

/// BLS signature domain tag — keeps a dig-message signature un-confusable with a Chia spend signature
/// (SPEC §5.1a). The signing itself is WU2; the tag lives here as the shared constant.
pub const SIG_DOMAIN: &[u8] = b"DIGNET-MSG:dig-message/v1";

/// Per-peer cap on concurrently-OPEN streams (SPEC §3, WU4 gate item DIG-Network/dig_ecosystem#1162).
///
/// Each open stream backs a bounded transport reassembler (dig-gossip: 256 chunks / 4 MiB per stream),
/// so without a per-peer cap a peer could open unbounded concurrent streams for an `N × 4 MiB` memory
/// DoS. `64` bounds the aggregate per-peer reassembly buffer to ~256 MiB while comfortably serving real
/// multiplexing. A new OPEN beyond this is rejected [`MessageError::StreamLimit`] (the peer RESETs).
pub const MAX_CONCURRENT_STREAMS: usize = 64;
