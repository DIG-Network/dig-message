//! The base envelope + inner message — the byte-deterministic Chia-Streamable wire shapes (SPEC §2,
//! §5.2) and the length-framed, size-bounded codec (SPEC §1).
//!
//! The envelope header (fields 1-8) is cleartext so a relay can route on `recipient` and multiplex on
//! `correlation_id`/`stream`; ALL content lives in the sealed region (field 9). WU1 defines the shapes
//! and the framing; the seal (`SealedPayload.kem_enc` + `ciphertext`) and the signature
//! (`InnerMessage.sender_sig`) are populated by WU2 — their FIELDS are final here.

use chia_protocol::{Bytes32, Bytes48, Bytes96};
use chia_streamable_macro::Streamable;
use chia_traits::Streamable as StreamableTrait;

use crate::constants::{ENVELOPE_VERSION, MAX_ENVELOPE_BYTES};
use crate::error::{MessageError, Result};

/// Extensible message-type id (SPEC §4). Additive-only: an id, once assigned, is never renumbered or
/// repurposed. The runtime registry that dispatches on it is WU3; the wire newtype is defined here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Streamable)]
pub struct MessageType(pub u32);

/// The interaction shape carried in `flags` bits 0-1 (SPEC §2 field 3 / §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionShape {
    /// Fire-and-forget: a single envelope, no response expected.
    OneShot = 0,
    /// A correlated request awaiting a response.
    Request = 1,
    /// A correlated response echoing a request's `correlation_id`.
    Response = 2,
    /// A frame of a stream (SPEC §3).
    StreamFrame = 3,
}

/// `flags` bitmask: bits 0-1 are the [`InteractionShape`] (SPEC §2 field 3).
pub const FLAG_SHAPE_MASK: u8 = 0b0000_0011;
/// `flags` bit 2: the sealed bit — MUST be 1 for directed messages (SPEC §2 field 3).
pub const FLAG_SEALED: u8 = 0b0000_0100;

impl InteractionShape {
    /// The shape encoded in a `flags` byte (bits 0-1). Unknown reserved values map to `None`.
    #[must_use]
    pub fn from_flags(flags: u8) -> Option<Self> {
        match flags & FLAG_SHAPE_MASK {
            0 => Some(Self::OneShot),
            1 => Some(Self::Request),
            2 => Some(Self::Response),
            3 => Some(Self::StreamFrame),
            _ => None,
        }
    }

    /// This shape as its `flags` bits (0-1).
    #[must_use]
    pub fn as_bits(self) -> u8 {
        self as u8
    }
}

/// A stream frame's control header (SPEC §3), present iff the shape is `StreamFrame`. The state machine
/// that drives these frames is WU4; the wire shape is final here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Streamable)]
pub struct StreamHeader {
    /// Frame kind (SPEC §3: OPEN=0, OPEN_ACK=1, DATA=2, CREDIT=3, CLOSE=4, CLOSE_ACK=5, RESET=6).
    pub frame: u8,
    /// Strictly-monotonic per-direction sequence number from 0 (the replay index, SPEC §3/§5.6).
    pub seq: u64,
    /// Credit-based flow-control window (SPEC §3 backpressure).
    pub window: u32,
}

/// Stream frame kinds (SPEC §3). The wire field [`StreamHeader::frame`] is a `u8`; this enum names the
/// values for WU4's state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFrame {
    Open = 0,
    OpenAck = 1,
    Data = 2,
    Credit = 3,
    Close = 4,
    CloseAck = 5,
    Reset = 6,
}

/// The e2e-sealed region (SPEC §5.2). WU1 defines the shape; WU2 fills `kem_enc` (the G1 ephemeral
/// encapsulation) and `ciphertext` (`AEAD.Seal` of the [`InnerMessage`]).
#[derive(Debug, Clone, PartialEq, Eq, Streamable)]
pub struct SealedPayload {
    /// The DHKEM-over-G1 ephemeral encapsulation — a 48-byte compressed G1 point (SPEC §5.1). A
    /// placeholder (zeros) until WU2 seals.
    pub kem_enc: Bytes48,
    /// `AEAD.Seal(key, nonce, aad=header, pt=InnerMessage)` (SPEC §5.2). Empty until WU2 seals.
    pub ciphertext: Vec<u8>,
}

/// The sealed inner message (SPEC §5.2, FINAL field list — order is normative). Every field lives
/// inside the AEAD-authenticated + signed region so a relay cannot tamper with any of it.
///
/// WU1 carries every field; the anti-replay (`counter`/`timestamp_ms`), expiry (`expires_at`), and
/// signature (`sender_sig`) SEMANTICS are enforced by WU2/WU4 — the wire shape is final here.
#[derive(Debug, Clone, PartialEq, Eq, Streamable)]
pub struct InnerMessage {
    /// Re-bound message type, checked equal to the cleartext header (anti type-confusion, SPEC §5.2).
    pub message_type: u32,
    /// Re-bound correlation id, checked equal to the cleartext header (SPEC §5.2).
    pub correlation_id: Bytes32,
    /// Compression algorithm id of `payload` (SPEC §1.1).
    pub compression: u8,
    /// Declared original length of `payload` — the decompression-bomb bound (SPEC §1.1).
    pub uncompressed_len: u32,
    /// Per-(sender→recipient) strictly-monotonic anti-replay counter (SPEC §5.6). Enforced in WU4.
    pub counter: u64,
    /// Sender wall-clock Unix milliseconds — the freshness field (SPEC §5.6). Enforced in WU4.
    pub timestamp_ms: u64,
    /// Sender-controlled TTL, Unix milliseconds; 0 = no explicit expiry (SPEC §5.6b). Enforced in WU4.
    pub expires_at: u64,
    /// The COMPRESSED type-payload bytes (SPEC §1.1). The sole content region.
    pub payload: Vec<u8>,
    /// The mandatory 96-byte BLS G2 sender signature (SPEC §5.1). Zeros until WU2 signs.
    pub sender_sig: Bytes96,
}

/// The base envelope (SPEC §2, field order normative). Fields 1-8 are the cleartext routing header;
/// field 9 is the sealed region.
#[derive(Debug, Clone, PartialEq, Eq, Streamable)]
pub struct DigMessageEnvelope {
    /// Envelope format version (SPEC §2 field 1).
    pub version: u8,
    /// Cleartext message type (routing); re-bound inside the seal (SPEC §2 field 2).
    pub message_type: u32,
    /// Interaction-shape + sealed bitfield (SPEC §2 field 3).
    pub flags: u8,
    /// Random per initiating message; echoed by responses and every stream frame (SPEC §2 field 4).
    pub correlation_id: Bytes32,
    /// Sender DID launcher id (SPEC §2 field 5).
    pub sender: Bytes32,
    /// Recipient DID launcher id (SPEC §2 field 6).
    pub recipient: Bytes32,
    /// Sender key epoch for rotation disambiguation (SPEC §2 field 7).
    pub sender_epoch: u32,
    /// Present iff the shape is a stream frame (SPEC §2 field 8 / §3).
    pub stream: Option<StreamHeader>,
    /// The e2e-sealed region — all type-specific content (SPEC §2 field 9 / §5).
    pub sealed: SealedPayload,
}

impl DigMessageEnvelope {
    /// Serialize the cleartext header (fields 1-8, excluding the sealed region) — the bytes WU2 binds
    /// as the AEAD AAD so an on-path party cannot alter routing metadata (SPEC §5.2).
    ///
    /// # Errors
    /// [`MessageError::Codec`] if any field fails to serialize (should not happen for a well-formed
    /// in-memory envelope).
    pub fn header_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let codec = |e: chia_traits::Error| MessageError::Codec(e.to_string());
        self.version.stream(&mut out).map_err(codec)?;
        self.message_type.stream(&mut out).map_err(codec)?;
        self.flags.stream(&mut out).map_err(codec)?;
        self.correlation_id.stream(&mut out).map_err(codec)?;
        self.sender.stream(&mut out).map_err(codec)?;
        self.recipient.stream(&mut out).map_err(codec)?;
        self.sender_epoch.stream(&mut out).map_err(codec)?;
        self.stream.stream(&mut out).map_err(codec)?;
        Ok(out)
    }
}

/// Serialize an envelope to its on-wire bytes, enforcing the [`MAX_ENVELOPE_BYTES`] cap (SPEC §1).
///
/// # Errors
/// [`MessageError::EnvelopeTooLarge`] if the frame exceeds the cap; [`MessageError::Codec`] on a
/// serialization failure.
pub fn encode_envelope(envelope: &DigMessageEnvelope) -> Result<Vec<u8>> {
    let bytes = envelope
        .to_bytes()
        .map_err(|e| MessageError::Codec(e.to_string()))?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(MessageError::EnvelopeTooLarge {
            size: bytes.len(),
            max: MAX_ENVELOPE_BYTES,
        });
    }
    Ok(bytes)
}

/// Decode an envelope from on-wire bytes, rejecting an over-cap frame BEFORE decoding and an unknown
/// version after (SPEC §1, §2).
///
/// # Errors
/// [`MessageError::EnvelopeTooLarge`] if the frame exceeds the cap; [`MessageError::Truncated`] on a
/// short/malformed frame; [`MessageError::UnsupportedVersion`] for a newer version.
pub fn decode_envelope(bytes: &[u8]) -> Result<DigMessageEnvelope> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(MessageError::EnvelopeTooLarge {
            size: bytes.len(),
            max: MAX_ENVELOPE_BYTES,
        });
    }
    let envelope = DigMessageEnvelope::from_bytes(bytes)
        .map_err(|e| MessageError::Truncated(e.to_string()))?;
    if envelope.version > ENVELOPE_VERSION {
        return Err(MessageError::UnsupportedVersion(envelope.version));
    }
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression::COMPRESSION_NONE;

    /// Build an envelope with deterministic, distinct field values for round-trip assertions.
    fn sample(shape: InteractionShape, stream: Option<StreamHeader>) -> DigMessageEnvelope {
        DigMessageEnvelope {
            version: ENVELOPE_VERSION,
            message_type: 0x0000_0201,
            flags: shape.as_bits() | FLAG_SEALED,
            correlation_id: Bytes32::new([1u8; 32]),
            sender: Bytes32::new([2u8; 32]),
            recipient: Bytes32::new([3u8; 32]),
            sender_epoch: 7,
            stream,
            sealed: SealedPayload {
                kem_enc: Bytes48::new([4u8; 48]),
                ciphertext: vec![9, 8, 7, 6, 5],
            },
        }
    }

    #[test]
    fn envelope_round_trips_for_every_shape() {
        let cases = [
            (InteractionShape::OneShot, None),
            (InteractionShape::Request, None),
            (InteractionShape::Response, None),
            (
                InteractionShape::StreamFrame,
                Some(StreamHeader {
                    frame: StreamFrame::Data as u8,
                    seq: 42,
                    window: 8,
                }),
            ),
        ];
        for (shape, stream) in cases {
            let env = sample(shape, stream);
            let bytes = encode_envelope(&env).unwrap();
            let decoded = decode_envelope(&bytes).unwrap();
            assert_eq!(env, decoded, "{shape:?} must round-trip");
        }
    }

    #[test]
    fn encoding_is_byte_deterministic() {
        let env = sample(InteractionShape::OneShot, None);
        assert_eq!(
            encode_envelope(&env).unwrap(),
            encode_envelope(&env).unwrap()
        );
    }

    #[test]
    fn inner_message_round_trips() {
        let inner = InnerMessage {
            message_type: 0x0000_0201,
            correlation_id: Bytes32::new([1u8; 32]),
            compression: COMPRESSION_NONE,
            uncompressed_len: 5,
            counter: 11,
            timestamp_ms: 1_700_000_000_000,
            expires_at: 0,
            payload: vec![1, 2, 3, 4, 5],
            sender_sig: Bytes96::new([0u8; 96]),
        };
        let bytes = inner.to_bytes().unwrap();
        assert_eq!(InnerMessage::from_bytes(&bytes).unwrap(), inner);
    }

    #[test]
    fn unknown_newer_version_is_rejected() {
        let mut env = sample(InteractionShape::OneShot, None);
        env.version = ENVELOPE_VERSION + 1;
        let bytes = env.to_bytes().unwrap();
        assert_eq!(
            decode_envelope(&bytes).unwrap_err(),
            MessageError::UnsupportedVersion(ENVELOPE_VERSION + 1)
        );
    }

    #[test]
    fn oversized_frame_is_rejected_before_decoding() {
        let bytes = vec![0u8; MAX_ENVELOPE_BYTES + 1];
        assert_eq!(
            decode_envelope(&bytes).unwrap_err(),
            MessageError::EnvelopeTooLarge {
                size: MAX_ENVELOPE_BYTES + 1,
                max: MAX_ENVELOPE_BYTES
            }
        );
    }

    #[test]
    fn oversized_envelope_encode_is_rejected() {
        let mut env = sample(InteractionShape::OneShot, None);
        env.sealed.ciphertext = vec![0u8; MAX_ENVELOPE_BYTES + 1];
        assert!(matches!(
            encode_envelope(&env).unwrap_err(),
            MessageError::EnvelopeTooLarge { .. }
        ));
    }

    #[test]
    fn truncated_frame_is_rejected() {
        let env = sample(InteractionShape::OneShot, None);
        let bytes = encode_envelope(&env).unwrap();
        let err = decode_envelope(&bytes[..bytes.len() / 2]).unwrap_err();
        assert!(matches!(err, MessageError::Truncated(_)));
    }

    #[test]
    fn header_bytes_excludes_the_sealed_region() {
        let env = sample(InteractionShape::OneShot, None);
        let header = env.header_bytes().unwrap();
        let full = env.to_bytes().unwrap();
        // The header is a strict prefix of the full encoding (fields 1-8 precede field 9).
        assert!(full.starts_with(&header));
        assert!(header.len() < full.len());
    }

    #[test]
    fn flags_shape_helpers_round_trip() {
        for shape in [
            InteractionShape::OneShot,
            InteractionShape::Request,
            InteractionShape::Response,
            InteractionShape::StreamFrame,
        ] {
            let flags = shape.as_bits() | FLAG_SEALED;
            assert_eq!(InteractionShape::from_flags(flags), Some(shape));
            assert_eq!(flags & FLAG_SEALED, FLAG_SEALED);
        }
    }

    #[test]
    fn message_type_round_trips() {
        let mt = MessageType(0x1000_0000);
        assert_eq!(
            MessageType::from_bytes(&mt.to_bytes().unwrap()).unwrap(),
            mt
        );
    }
}
