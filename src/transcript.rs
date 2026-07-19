//! The signed transcript (SPEC §5.1 / §5.1a) — the domain-separated byte string the sender BLS-signs
//! and the recipient verifies, binding EVERY security-relevant field so nothing is malleable.
//!
//! The signed message is `SIG_DOMAIN || transcript` where `SIG_DOMAIN = "DIGNET-MSG:dig-message/v1"`
//! (SPEC §5.1a) — a fixed ASCII augmentation that keeps a dig-message signature un-confusable with a
//! Chia spend signature (AGG_SIG_ME / AGG_SIG_UNSAFE). The transcript itself is a fixed-width,
//! big-endian, byte-deterministic serialization so the Rust and wasm/JS targets agree byte-for-byte.
//!
//! Field order + widths (NORMATIVE, SPEC §5.1):
//! `version:u8 ‖ message_type:u32 ‖ flags:u8 ‖ correlation_id:32 ‖ sender:32 ‖ recipient:32 ‖
//! sender_epoch:u32 ‖ counter:u64 ‖ timestamp_ms:u64 ‖ expires_at:u64 ‖ stream_frame:u8 ‖
//! stream_seq:u64 ‖ kem_enc:48 ‖ compression:u8 ‖ uncompressed_len:u32 ‖ compressed_payload_hash:32`
//! (all integers big-endian; `stream_frame`/`stream_seq` are 0 for a non-stream message;
//! `compressed_payload_hash` is the SHA-256 of the on-wire compressed payload bytes).

use chia_protocol::Bytes32;
use sha2::{Digest, Sha256};

use crate::constants::SIG_DOMAIN;
use crate::envelope::StreamHeader;
use dig_identity::bls::SecretKey;
use dig_identity::{sign_message, verify_signature};

/// The exact byte length of a transcript (the sum of the fixed-width fields above).
const TRANSCRIPT_LEN: usize = 1 + 4 + 1 + 32 + 32 + 32 + 4 + 8 + 8 + 8 + 1 + 8 + 48 + 1 + 4 + 32;

/// Every field the sender signature binds (SPEC §5.1). Assembled by the seal (send) and reconstructed
/// from the opened envelope + inner message (receive), so both sides compute the identical transcript.
#[derive(Debug, Clone)]
pub struct TranscriptFields<'a> {
    pub version: u8,
    pub message_type: u32,
    pub flags: u8,
    pub correlation_id: Bytes32,
    pub sender: Bytes32,
    pub recipient: Bytes32,
    pub sender_epoch: u32,
    pub counter: u64,
    pub timestamp_ms: u64,
    pub expires_at: u64,
    /// The stream frame kind + seq (SPEC §3); `None` for a non-stream message (encoded as 0/0).
    pub stream: Option<StreamHeader>,
    /// The ephemeral G1 encapsulation (SPEC §5.1) — binds the seal to this KEM so it cannot be reused.
    pub kem_enc: &'a [u8; 48],
    pub compression: u8,
    pub uncompressed_len: u32,
    /// The on-wire COMPRESSED payload bytes; the transcript binds their SHA-256, not the bytes.
    pub compressed_payload: &'a [u8],
}

impl TranscriptFields<'_> {
    /// The domain-separated bytes to sign/verify: `SIG_DOMAIN || transcript` (SPEC §5.1 / §5.1a).
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIG_DOMAIN.len() + TRANSCRIPT_LEN);
        out.extend_from_slice(SIG_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.message_type.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(self.correlation_id.as_ref());
        out.extend_from_slice(self.sender.as_ref());
        out.extend_from_slice(self.recipient.as_ref());
        out.extend_from_slice(&self.sender_epoch.to_be_bytes());
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        let (frame, seq) = self.stream.map_or((0u8, 0u64), |s| (s.frame, s.seq));
        out.extend_from_slice(&frame.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(self.kem_enc);
        out.extend_from_slice(&self.compression.to_be_bytes());
        out.extend_from_slice(&self.uncompressed_len.to_be_bytes());
        let hash: [u8; 32] = Sha256::digest(self.compressed_payload).into();
        out.extend_from_slice(&hash);
        out
    }

    /// BLS-G2 sign the transcript with the sender identity key (AugScheme), returning the 96-byte
    /// signature (SPEC §5.1). Signs ONLY through the dig-identity helper — never a wallet spend path.
    #[must_use]
    pub fn sign(&self, sender_sk: &SecretKey) -> [u8; 96] {
        sign_message(sender_sk, &self.signing_bytes())
    }

    /// Verify a 96-byte BLS-G2 signature against the resolved sender G1 key (SPEC §5.1). Fail-closed:
    /// any malformed key/sig or non-verifying signature returns `false`.
    #[must_use]
    pub fn verify(&self, sender_pub: &[u8; 48], sig: &[u8; 96]) -> bool {
        verify_signature(sender_pub, &self.signing_bytes(), sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_identity::{derive_identity_sk, master_secret_key_from_seed, public_key_bytes};

    fn sk(label: &str) -> SecretKey {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        derive_identity_sk(&master_secret_key_from_seed(&seed))
    }

    fn fields<'a>(kem_enc: &'a [u8; 48], payload: &'a [u8]) -> TranscriptFields<'a> {
        TranscriptFields {
            version: 1,
            message_type: 0x0000_0201,
            flags: 0b0000_0100,
            correlation_id: Bytes32::new([1u8; 32]),
            sender: Bytes32::new([2u8; 32]),
            recipient: Bytes32::new([3u8; 32]),
            sender_epoch: 7,
            counter: 42,
            timestamp_ms: 1_700_000_000_000,
            expires_at: 0,
            stream: None,
            kem_enc,
            compression: 0,
            uncompressed_len: payload.len() as u32,
            compressed_payload: payload,
        }
    }

    #[test]
    fn signing_bytes_are_fixed_width_and_domain_prefixed() {
        let kem = [4u8; 48];
        let f = fields(&kem, b"hello");
        let bytes = f.signing_bytes();
        assert_eq!(bytes.len(), SIG_DOMAIN.len() + TRANSCRIPT_LEN);
        assert!(bytes.starts_with(SIG_DOMAIN));
    }

    #[test]
    fn signing_bytes_are_deterministic() {
        let kem = [4u8; 48];
        assert_eq!(
            fields(&kem, b"abc").signing_bytes(),
            fields(&kem, b"abc").signing_bytes()
        );
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let sk = sk("transcript/sign");
        let pk = public_key_bytes(&sk);
        let kem = [9u8; 48];
        let f = fields(&kem, b"payload-bytes");
        let sig = f.sign(&sk);
        assert!(f.verify(&pk, &sig));
    }

    #[test]
    fn any_field_change_breaks_the_signature() {
        let sk = sk("transcript/tamper");
        let pk = public_key_bytes(&sk);
        let kem = [9u8; 48];
        let f = fields(&kem, b"payload-bytes");
        let sig = f.sign(&sk);

        let mut tampered = fields(&kem, b"payload-bytes");
        tampered.counter = 43;
        assert!(
            !tampered.verify(&pk, &sig),
            "changing counter must break the sig"
        );

        let mut tampered_exp = fields(&kem, b"payload-bytes");
        tampered_exp.expires_at = 999;
        assert!(
            !tampered_exp.verify(&pk, &sig),
            "changing expires_at must break the sig"
        );

        // The untampered fields still verify (control).
        assert!(f.verify(&pk, &sig));
    }

    #[test]
    fn wrong_key_does_not_verify() {
        let signer = sk("transcript/wrong-a");
        let kem = [9u8; 48];
        let f = fields(&kem, b"x");
        let sig = f.sign(&signer);
        let other = public_key_bytes(&sk("transcript/wrong-b"));
        assert!(!f.verify(&other, &sig));
    }

    #[test]
    fn payload_hash_is_bound_not_the_bytes() {
        // A different compressed payload yields a different transcript (the hash changes).
        let kem = [9u8; 48];
        assert_ne!(
            fields(&kem, b"one").signing_bytes(),
            fields(&kem, b"two").signing_bytes()
        );
    }

    #[test]
    fn stream_fields_are_bound() {
        let kem = [9u8; 48];
        let mut a = fields(&kem, b"x");
        a.stream = Some(StreamHeader {
            frame: 2,
            seq: 5,
            window: 0,
        });
        let mut b = fields(&kem, b"x");
        b.stream = Some(StreamHeader {
            frame: 2,
            seq: 6,
            window: 0,
        });
        assert_ne!(a.signing_bytes(), b.signing_bytes(), "stream_seq is bound");
    }
}
