//! The compression layer (SPEC §1.1) — the crypto-free codec that runs BEFORE the seal (WU2). A
//! payload is compressed in its OWN fresh context (never a shared running context — the §5.5 CRIME/
//! BREACH boundary), then WU2 seals the compressed bytes.
//!
//! Two codecs ship in WU1: raw/identity (id 0, mandatory) and zstd level-3 (id 1, recommended). The
//! reserved id bands (2..=63 standard, 64..=255 experimental) are rejected cleanly, never mis-decoded.

use crate::constants::{MAX_DECOMPRESSED_BYTES, MIN_COMPRESS_BYTES, ZSTD_LEVEL};
use crate::error::{MessageError, Result};

/// Raw / identity codec: the payload bytes verbatim. Mandatory (SPEC §1.1).
pub const COMPRESSION_NONE: u8 = 0;

/// zstd codec, pinned to level 3, single-frame, no dictionary (SPEC §1.1/§1.2).
pub const COMPRESSION_ZSTD: u8 = 1;

/// A compressed payload ready to be sealed: the algorithm id, the compressed bytes, and the declared
/// original length (the bomb-guard bound carried in the sealed `InnerMessage`, SPEC §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedPayload {
    /// The algorithm id ([`COMPRESSION_NONE`] or [`COMPRESSION_ZSTD`]).
    pub compression: u8,
    /// The on-wire compressed bytes (identical to the input for the raw codec).
    pub bytes: Vec<u8>,
    /// The original uncompressed length — the receiver's decompression-bomb bound.
    pub uncompressed_len: u32,
}

/// Compress a payload for sealing, choosing the codec per the SPEC §1.1 raw threshold.
///
/// Uses zstd (id 1) only when the payload is at least [`MIN_COMPRESS_BYTES`] AND zstd actually shrinks
/// it; otherwise falls back to raw (id 0) so small or incompressible payloads never pay a header/
/// expansion penalty.
///
/// # Errors
/// [`MessageError::PayloadTooLarge`] if the payload does not fit the `u32` length field;
/// [`MessageError::Codec`] on a zstd encoder failure.
pub fn compress_payload(payload: &[u8]) -> Result<CompressedPayload> {
    let uncompressed_len =
        u32::try_from(payload.len()).map_err(|_| MessageError::PayloadTooLarge(payload.len()))?;

    if payload.len() < MIN_COMPRESS_BYTES {
        return Ok(raw(payload, uncompressed_len));
    }

    let compressed = zstd::bulk::compress(payload, ZSTD_LEVEL)
        .map_err(|e| MessageError::Codec(e.to_string()))?;

    // Fall back to raw when zstd does not shrink (already-compressed / incompressible data), so we
    // never emit a larger frame than the plaintext (SPEC §1.1).
    if compressed.len() >= payload.len() {
        return Ok(raw(payload, uncompressed_len));
    }

    Ok(CompressedPayload {
        compression: COMPRESSION_ZSTD,
        bytes: compressed,
        uncompressed_len,
    })
}

/// Decompress a sealed payload under the SPEC §1.1 bomb guard.
///
/// Rejects a declared length over [`MAX_DECOMPRESSED_BYTES`] BEFORE decoding, bounds the decoder
/// output to that cap DURING, and rejects on any length mismatch — a hostile peer cannot OOM the host.
///
/// # Errors
/// [`MessageError::DecompressionBomb`] if `uncompressed_len` exceeds the cap;
/// [`MessageError::UnsupportedCompression`] for an unknown id;
/// [`MessageError::DecompressedLengthMismatch`] on an overrun or a decoded-length disagreement;
/// [`MessageError::Codec`] on a zstd decoder failure.
pub fn decompress_payload(compression: u8, data: &[u8], uncompressed_len: u32) -> Result<Vec<u8>> {
    let declared = uncompressed_len as usize;
    if declared > MAX_DECOMPRESSED_BYTES {
        return Err(MessageError::DecompressionBomb {
            declared,
            max: MAX_DECOMPRESSED_BYTES,
        });
    }

    match compression {
        COMPRESSION_NONE => {
            if data.len() != declared {
                return Err(MessageError::DecompressedLengthMismatch {
                    expected: declared,
                    actual: data.len(),
                });
            }
            Ok(data.to_vec())
        }
        COMPRESSION_ZSTD => {
            // `capacity = declared` bounds the allocation to the (already-capped) declared size; zstd
            // errors if the frame decodes to more, defeating a bomb that under-declares its output.
            let decoded = zstd::bulk::decompress(data, declared)
                .map_err(|e| MessageError::Codec(e.to_string()))?;
            if decoded.len() != declared {
                return Err(MessageError::DecompressedLengthMismatch {
                    expected: declared,
                    actual: decoded.len(),
                });
            }
            Ok(decoded)
        }
        other => Err(MessageError::UnsupportedCompression(other)),
    }
}

/// The raw/identity result: the payload verbatim under [`COMPRESSION_NONE`].
fn raw(payload: &[u8], uncompressed_len: u32) -> CompressedPayload {
    CompressedPayload {
        compression: COMPRESSION_NONE,
        bytes: payload.to_vec(),
        uncompressed_len,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic, compressible test bytes derived from a seed — never a hard-coded literal (CodeQL).
    fn compressible(len: usize) -> Vec<u8> {
        // A repeating low-entropy pattern zstd shrinks well.
        (0..len).map(|i| (i % 7) as u8).collect()
    }

    #[test]
    fn small_payload_stays_raw() {
        let payload = compressible(MIN_COMPRESS_BYTES - 1);
        let out = compress_payload(&payload).unwrap();
        assert_eq!(out.compression, COMPRESSION_NONE);
        assert_eq!(out.bytes, payload);
        assert_eq!(out.uncompressed_len as usize, payload.len());
    }

    #[test]
    fn large_compressible_payload_uses_zstd_and_round_trips() {
        let payload = compressible(4096);
        let out = compress_payload(&payload).unwrap();
        assert_eq!(out.compression, COMPRESSION_ZSTD);
        assert!(
            out.bytes.len() < payload.len(),
            "zstd should shrink a low-entropy payload"
        );
        let restored =
            decompress_payload(out.compression, &out.bytes, out.uncompressed_len).unwrap();
        assert_eq!(restored, payload);
    }

    #[test]
    fn raw_round_trips() {
        let payload = compressible(16);
        let out = compress_payload(&payload).unwrap();
        let restored =
            decompress_payload(out.compression, &out.bytes, out.uncompressed_len).unwrap();
        assert_eq!(restored, payload);
    }

    #[test]
    fn incompressible_payload_falls_back_to_raw() {
        // High-entropy (SHA-derived) bytes zstd cannot shrink -> the codec MUST fall back to raw
        // (SPEC §1.1). Derived from a hashed seed, never a hard-coded literal (CodeQL).
        use sha2::{Digest, Sha256};
        let mut payload = Vec::new();
        let mut ctr = 0u64;
        while payload.len() < 1024 {
            let mut h = Sha256::new();
            h.update(b"incompressible");
            h.update(ctr.to_le_bytes());
            payload.extend_from_slice(&h.finalize());
            ctr += 1;
        }
        let out = compress_payload(&payload).unwrap();
        assert_eq!(out.compression, COMPRESSION_NONE);
        assert_eq!(out.bytes, payload);
    }

    #[test]
    fn compression_is_deterministic() {
        let payload = compressible(2048);
        assert_eq!(
            compress_payload(&payload).unwrap(),
            compress_payload(&payload).unwrap()
        );
    }

    #[test]
    fn unknown_compression_id_is_rejected() {
        let err = decompress_payload(2, &[1, 2, 3], 3).unwrap_err();
        assert_eq!(err, MessageError::UnsupportedCompression(2));
    }

    #[test]
    fn declared_length_over_cap_is_a_bomb() {
        let declared = (MAX_DECOMPRESSED_BYTES + 1) as u32;
        // A u32 cannot exceed 64 MiB+1? 64 MiB = 67_108_864 which fits u32. Good.
        let err = decompress_payload(COMPRESSION_ZSTD, &[], declared).unwrap_err();
        assert_eq!(
            err,
            MessageError::DecompressionBomb {
                declared: declared as usize,
                max: MAX_DECOMPRESSED_BYTES
            }
        );
    }

    #[test]
    fn zstd_bomb_that_underdeclares_output_is_rejected() {
        // Compress a large payload, then claim a tiny uncompressed_len: the decoder is bounded to the
        // (small) declared capacity and MUST reject the overrun (SPEC §1.1).
        let payload = compressible(8192);
        let out = compress_payload(&payload).unwrap();
        assert_eq!(out.compression, COMPRESSION_ZSTD);
        let err = decompress_payload(out.compression, &out.bytes, 16).unwrap_err();
        // Either an overrun (Codec) or a length mismatch — both are a clean reject, never a panic/OOM.
        assert!(matches!(
            err,
            MessageError::Codec(_) | MessageError::DecompressedLengthMismatch { .. }
        ));
    }

    #[test]
    fn raw_length_mismatch_is_rejected() {
        let err = decompress_payload(COMPRESSION_NONE, &[1, 2, 3], 4).unwrap_err();
        assert_eq!(
            err,
            MessageError::DecompressedLengthMismatch {
                expected: 4,
                actual: 3
            }
        );
    }
}
