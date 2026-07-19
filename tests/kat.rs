//! Known-Answer-Test (KAT) harness for dig-message — the golden-vector infrastructure that pins the
//! byte-level wire contract (SPEC §2, §7). WU1 fills the crypto-free vectors: the envelope encodings
//! for every interaction shape and the compression round-trips. The seal / signature / replay /
//! streaming vectors are the clearly-marked WU2/WU4 placeholders at the bottom.
//!
//! Golden values are committed as SHA-256 digests of the deterministic on-wire bytes: a digest change
//! means the wire format drifted (a byte-determinism regression), which MUST be an intentional,
//! reviewed SemVer event — never an accident. All test material is DERIVED from a hashed seed (never a
//! hard-coded literal — CodeQL).

use chia_protocol::{Bytes32, Bytes48};
use dig_message::*;
use sha2::{Digest, Sha256};

/// Deterministic pseudo-random bytes for a labeled field — SHA-256(tag || counter) chained to `n`
/// bytes. Reproducible across runs and machines, so a golden digest is stable.
fn seeded(tag: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 0u64;
    while out.len() < n {
        let mut hasher = Sha256::new();
        hasher.update(tag);
        hasher.update(counter.to_le_bytes());
        out.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    out.truncate(n);
    out
}

fn b32(tag: &[u8]) -> Bytes32 {
    Bytes32::new(seeded(tag, 32).try_into().unwrap())
}

/// Lowercase-hex SHA-256 of the on-wire bytes — the committed golden form.
fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The canonical golden envelope for a shape, built from seeded field material.
fn golden_envelope(shape: InteractionShape, stream: Option<StreamHeader>) -> DigMessageEnvelope {
    DigMessageEnvelope {
        version: ENVELOPE_VERSION,
        message_type: 0x0000_0201,
        flags: shape.as_bits() | FLAG_SEALED,
        correlation_id: b32(b"corr"),
        sender: b32(b"sender"),
        recipient: b32(b"recip"),
        sender_epoch: 3,
        stream,
        sealed: SealedPayload {
            kem_enc: Bytes48::new(seeded(b"kem", 48).try_into().unwrap()),
            ciphertext: seeded(b"ct", 24),
        },
    }
}

// ── Envelope golden vectors (SPEC §2) — byte-determinism is the wire contract. ──

#[test]
fn kat_envelope_oneshot() {
    let bytes = encode_envelope(&golden_envelope(InteractionShape::OneShot, None)).unwrap();
    assert_eq!(bytes.len(), 183);
    assert_eq!(
        digest(&bytes),
        "02e5acc39f11b32336d373d3334f3017f44e45e3df2212ff1caf5158f41f9bab"
    );
}

#[test]
fn kat_envelope_request() {
    let bytes = encode_envelope(&golden_envelope(InteractionShape::Request, None)).unwrap();
    assert_eq!(
        digest(&bytes),
        "eea426a86ded1df366d5a98d45285c82568f4eb0feacc5f62e63ead69b909c8a"
    );
}

#[test]
fn kat_envelope_response() {
    let bytes = encode_envelope(&golden_envelope(InteractionShape::Response, None)).unwrap();
    assert_eq!(
        digest(&bytes),
        "5a29d5c66105ba33c17ae53934af22fade4a3e61c6609044003f2ce0bdb05530"
    );
}

#[test]
fn kat_envelope_stream_frame() {
    let stream = Some(StreamHeader {
        frame: StreamFrame::Data as u8,
        seq: 42,
        window: 8,
    });
    let bytes = encode_envelope(&golden_envelope(InteractionShape::StreamFrame, stream)).unwrap();
    assert_eq!(bytes.len(), 196);
    assert_eq!(
        digest(&bytes),
        "ee409a0eb016f42280dfeea71d9fe8b4cdfb280f8e072e9391cbd161d6754ee3"
    );
}

#[test]
fn kat_every_shape_round_trips() {
    let cases = [
        golden_envelope(InteractionShape::OneShot, None),
        golden_envelope(InteractionShape::Request, None),
        golden_envelope(InteractionShape::Response, None),
        golden_envelope(
            InteractionShape::StreamFrame,
            Some(StreamHeader {
                frame: StreamFrame::Open as u8,
                seq: 0,
                window: 16,
            }),
        ),
    ];
    for env in cases {
        let decoded = decode_envelope(&encode_envelope(&env).unwrap()).unwrap();
        assert_eq!(env, decoded);
    }
}

// ── Compression golden vectors (SPEC §1.1). ──

#[test]
fn kat_compression_zstd_round_trip() {
    // A low-entropy payload zstd compresses deterministically (level 3, single-frame, no dictionary).
    let payload: Vec<u8> = (0..4096usize).map(|i| (i % 7) as u8).collect();
    let compressed = compress_payload(&payload).unwrap();
    assert_eq!(compressed.compression, COMPRESSION_ZSTD);
    assert_eq!(
        compressed.bytes.len(),
        24,
        "pinned zstd params -> pinned compressed length"
    );
    assert_eq!(
        digest(&compressed.bytes),
        "3a2ad06d6906a2fdd9353e52f386d097eac0fadb9529fb9a3289eae782b49e70",
        "compressed bytes are the cross-target byte-agreement contract (SPEC §1.2)"
    );
    let restored = decompress_payload(
        compressed.compression,
        &compressed.bytes,
        compressed.uncompressed_len,
    )
    .unwrap();
    assert_eq!(restored, payload);
}

#[test]
fn kat_compression_raw_round_trip() {
    let payload = seeded(b"raw-kat", 40); // below MIN_COMPRESS_BYTES -> raw
    let compressed = compress_payload(&payload).unwrap();
    assert_eq!(compressed.compression, COMPRESSION_NONE);
    assert_eq!(compressed.bytes, payload);
    let restored = decompress_payload(
        compressed.compression,
        &compressed.bytes,
        compressed.uncompressed_len,
    )
    .unwrap();
    assert_eq!(restored, payload);
}

#[test]
fn kat_unknown_compression_id_rejected() {
    assert_eq!(
        decompress_payload(63, &seeded(b"x", 8), 8).unwrap_err(),
        MessageError::UnsupportedCompression(63)
    );
}

#[test]
fn kat_decompression_bomb_rejected() {
    let over = (MAX_DECOMPRESSED_BYTES + 1) as u32;
    assert!(matches!(
        decompress_payload(COMPRESSION_ZSTD, &[], over).unwrap_err(),
        MessageError::DecompressionBomb { .. }
    ));
}

// ── WU2 KATs (seal + BLS signature + replay/expiry, SPEC §5) — implemented in #1160. ──
//
// These integration KATs exercise the PUBLIC seal API end-to-end (the same contract a second
// implementation is built against). All key/nonce material is DERIVED from a hashed seed (never a
// hard-coded literal — CodeQL). Fine-grained unit KATs live beside the code in `src/{seal,replay,
// transcript}.rs`; the vectors here pin the integration-level behavior.

use dig_identity::bls::SecretKey;
use dig_identity::{derive_identity_sk, master_secret_key_from_seed, public_key_bytes};

const KAT_NOW: u64 = 1_700_000_000_000;

/// A deterministic identity key from a label (reproducible across implementations).
fn kat_sk(label: &str) -> SecretKey {
    let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    derive_identity_sk(&master_secret_key_from_seed(&seed))
}

// ── WU2 deterministic-ephemeral KATs moved to src/seal.rs unit tests ──
// These moved to access pub(crate) seal_with_ephemeral. Non-seal KATs remain here.

#[test]
fn kat_bls_domain_separation_vs_chain_agg_sig() {
    // SPEC §5.1a: the signed bytes are SIG_DOMAIN || transcript, so a dig-message signature can never
    // be confused with an un-prefixed chain AGG_SIG message. The signature verifies over the
    // domain-prefixed bytes and does NOT verify over the transcript with the domain stripped.
    let alice = kat_sk("kat/dom/a");
    let a_pub = public_key_bytes(&alice);
    let kem = [7u8; 48];
    let transcript = TranscriptFields {
        version: 1,
        message_type: BAND_DIG_CHAT,
        flags: InteractionShape::OneShot.as_bits() | FLAG_SEALED,
        correlation_id: b32(b"kat/dom/corr"),
        sender: b32(b"kat/dom/s"),
        recipient: b32(b"kat/dom/r"),
        sender_epoch: 0,
        counter: 0,
        timestamp_ms: KAT_NOW,
        expires_at: 0,
        stream: None,
        kem_enc: &kem,
        compression: COMPRESSION_NONE,
        uncompressed_len: 1,
        compressed_payload: b"z",
    };
    let signing = transcript.signing_bytes();
    assert!(
        signing.starts_with(SIG_DOMAIN),
        "the domain tag prefixes the signed bytes"
    );

    let sig = transcript.sign(&alice);
    assert!(transcript.verify(&a_pub, &sig));

    // Strip the domain tag: an AGG_SIG-style raw message must NOT verify under this signature.
    use dig_identity::verify_signature;
    let stripped = &signing[SIG_DOMAIN.len()..];
    assert!(
        !verify_signature(&a_pub, stripped, &sig),
        "domain-stripped message must not verify"
    );
}

// ── WU4 placeholders (streaming + replay/expiry, SPEC §3 / §5.6 / §5.6b) — implemented in #1162. ──
//
//   - streaming round-trip; CANCEL/RESET; backpressure; cross-session frame-replay reject
//   - replayed message rejected; stale (old-counter/out-of-freshness) rejected
//   - within-expires accepted; past-expires DISCARDED; expires_at > cap REJECTED; expires_at==0 no-op
