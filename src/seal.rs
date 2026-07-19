//! WU2: the e2e SEAL pipeline (SPEC §5) — the crypto crux of dig-message.
//!
//! ONE Chia BLS12-381 identity keypair does everything: its G2 signature authenticates the sender and
//! ECDH over its G1 group seals the payload. There is NO X25519 and NO Ed25519.
//!
//! ## Seal (send) — SPEC §1 pipeline + §5.1
//! serialize payload → **compress** (§1.1) → **BLS-G2 sign** the transcript (§5.1, domain-separated so
//! it can never be a chain AGG_SIG) → **G1-DHKEM auth-seal** (HPKE AuthEncap analog over BLS12-381 G1:
//! ephemeral + static-sender ECDH → HKDF-SHA256 → ChaCha20Poly1305). The `kem_enc` is the 48-byte
//! ephemeral G1 point; the sealed region opens ONLY with the recipient private key AND the correct
//! sender public key.
//!
//! ## Open (receive) — SPEC §5.2 / §5.7
//! subgroup-check `kem_enc` + sender key BEFORE any DH → G1-DHKEM auth-decap + AEAD-open → verify the
//! BLS-G2 sender signature → header-match check → **expiry** discard (§5.6b) → **anti-replay** check
//! (§5.6) → decompress under the bomb guard (§1.1) → deliver. Fail-closed at every step.
//!
//! The DH / sign / verify / subgroup primitives come from `dig-identity` (never re-rolled). The DHKEM /
//! HKDF / AEAD composition lives HERE (the decider's crate split).

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use chia_bls::SecretKey;
use chia_protocol::{Bytes32, Bytes48, Bytes96};
use chia_traits::Streamable as _;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::compression::{compress_payload, decompress_payload};
use crate::constants::MAX_DECOMPRESSED_BYTES;
use crate::envelope::{
    DigMessageEnvelope, InnerMessage, InteractionShape, SealedPayload, StreamHeader, FLAG_SEALED,
};
use crate::error::{MessageError, Result};
use crate::replay::ReplayGuard;
use crate::transcript::TranscriptFields;
use dig_identity::{g1_dh, g1_subgroup_check, public_key_bytes};

/// The HKDF info label for the DHKEM-over-G1 key schedule (SPEC §5.1). Binding the KEM material into
/// `info` (below) ties the derived key to this exact encapsulation, sender, and recipient.
const KDF_INFO_LABEL: &[u8] = b"dig-message/dhkem-g1/v1";

/// The AEAD key (32) + base nonce (12) derived from the shared secret (SPEC §5.1).
const OKM_LEN: usize = 32 + 12;

/// The current envelope format version this sealer emits (SPEC §2 field 1).
const VERSION: u8 = crate::constants::ENVELOPE_VERSION;

/// Everything the sender supplies to seal one message (SPEC §5.1). The anti-replay `counter` +
/// `timestamp_ms` and the `expires_at` TTL are sender-chosen; the crate binds + enforces them.
pub struct SealParams<'a> {
    /// The sender identity secret key (the ONE BLS12-381 key — signs G2 and does the static G1 DH).
    pub sender_sk: &'a SecretKey,
    /// The sender DID launcher id (cleartext header, bound as AAD).
    pub sender: Bytes32,
    /// The sender key epoch for rotation disambiguation (SPEC §2 field 7).
    pub sender_epoch: u32,
    /// The recipient DID launcher id.
    pub recipient: Bytes32,
    /// The recipient BLS G1 identity public key (48-byte compressed), the seal target.
    pub recipient_pub: &'a [u8; 48],
    /// The message type id (SPEC §4).
    pub message_type: u32,
    /// The interaction shape (SPEC §3).
    pub shape: InteractionShape,
    /// The correlation id (SPEC §2 field 4).
    pub correlation_id: Bytes32,
    /// The stream header, present iff `shape` is a stream frame (SPEC §3).
    pub stream: Option<StreamHeader>,
    /// The per-(sender→recipient) strictly-monotonic anti-replay counter (SPEC §5.6).
    pub counter: u64,
    /// Sender wall-clock Unix milliseconds — the freshness field (SPEC §5.6).
    pub timestamp_ms: u64,
    /// Sender-controlled TTL, Unix milliseconds; 0 = no explicit expiry (SPEC §5.6b).
    pub expires_at: u64,
    /// The raw (uncompressed, unsealed) type-payload bytes.
    pub payload: &'a [u8],
}

/// A successfully opened + verified message (SPEC §5.2). The `payload` is the decompressed plaintext;
/// the caller routes it via the type registry (SPEC §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedMessage {
    pub message_type: u32,
    pub correlation_id: Bytes32,
    pub shape: InteractionShape,
    pub sender: Bytes32,
    pub sender_epoch: u32,
    pub counter: u64,
    pub timestamp_ms: u64,
    pub expires_at: u64,
    /// The decompressed, verified plaintext type-payload bytes.
    pub payload: Vec<u8>,
}

/// Seal a message end-to-end (SPEC §5.1), generating a fresh ephemeral for forward secrecy.
///
/// # Errors
/// [`MessageError::InvalidPoint`] if `recipient_pub` fails the subgroup check;
/// [`MessageError::SealFailed`] on an ephemeral-key or AEAD failure;
/// [`MessageError::PayloadTooLarge`] / [`MessageError::Codec`] from compression.
pub fn seal_message(params: &SealParams) -> Result<DigMessageEnvelope> {
    let esk = random_ephemeral()?;
    seal_with_ephemeral(params, &esk)
}

/// Seal with a caller-provided ephemeral secret (deterministic KATs). Prefer [`seal_message`] in
/// production — a fresh random ephemeral per message is what gives forward secrecy (SPEC §5.1).
///
/// ⚠️ **INTERNAL USE ONLY** — restricted to `pub(crate)` to prevent accidental nonce-reuse in
/// production code. Reusing ephemeralss breaks forward secrecy (ChaCha20Poly1305 catastrophic failure)
/// and is incompatible with WU4 streaming. Use [`seal_message`] instead, which auto-generates
/// fresh ephemeralss. Deterministic KAT tests access this from within the crate (unit tests in
/// this module, not integration tests).
///
/// # Errors
/// As [`seal_message`].
pub(crate) fn seal_with_ephemeral(
    params: &SealParams,
    esk: &SecretKey,
) -> Result<DigMessageEnvelope> {
    // SPEC §1: compress BEFORE sealing (sealed ciphertext is incompressible).
    let compressed = compress_payload(params.payload)?;

    let sender_pub = public_key_bytes(params.sender_sk);
    let kem_enc = public_key_bytes(esk);

    // SPEC §5.1 AuthEncap: Z = dh(esk, recipient_pub) || dh(sender_static_sk, recipient_pub).
    let z = auth_encap_secret(esk, params.sender_sk, params.recipient_pub)?;
    let okm = kdf(&z, &kem_enc, &sender_pub, params.recipient_pub);

    // SPEC §5.1: BLS-G2 sign the transcript, then place the signature inside the sealed InnerMessage.
    let transcript = TranscriptFields {
        version: VERSION,
        message_type: params.message_type,
        flags: params.shape.as_bits() | FLAG_SEALED,
        correlation_id: params.correlation_id,
        sender: params.sender,
        recipient: params.recipient,
        sender_epoch: params.sender_epoch,
        counter: params.counter,
        timestamp_ms: params.timestamp_ms,
        expires_at: params.expires_at,
        stream: params.stream,
        kem_enc: &kem_enc,
        compression: compressed.compression,
        uncompressed_len: compressed.uncompressed_len,
        compressed_payload: &compressed.bytes,
    };
    let sender_sig = transcript.sign(params.sender_sk);

    let inner = InnerMessage {
        message_type: params.message_type,
        correlation_id: params.correlation_id,
        compression: compressed.compression,
        uncompressed_len: compressed.uncompressed_len,
        counter: params.counter,
        timestamp_ms: params.timestamp_ms,
        expires_at: params.expires_at,
        payload: compressed.bytes,
        sender_sig: Bytes96::new(sender_sig),
    };
    let inner_bytes = inner
        .to_bytes()
        .map_err(|e| MessageError::SealFailed(e.to_string()))?;

    // The cleartext header is bound as AEAD AAD so an on-path party cannot alter routing metadata
    // (SPEC §5.2). Build the envelope with the final kem_enc + an empty ciphertext to derive the
    // header bytes, then fill the ciphertext.
    let mut envelope = DigMessageEnvelope {
        version: VERSION,
        message_type: params.message_type,
        flags: params.shape.as_bits() | FLAG_SEALED,
        correlation_id: params.correlation_id,
        sender: params.sender,
        recipient: params.recipient,
        sender_epoch: params.sender_epoch,
        stream: params.stream,
        sealed: SealedPayload {
            kem_enc: Bytes48::new(kem_enc),
            ciphertext: Vec::new(),
        },
    };
    let aad = envelope.header_bytes()?;
    envelope.sealed.ciphertext = aead_seal(&okm, &aad, &inner_bytes)?;
    Ok(envelope)
}

/// Open + fully verify a sealed envelope (SPEC §5.2 / §5.7), advancing the anti-replay guard.
///
/// `resolve_sender_pub` maps `(sender DID, sender_epoch)` to the sender's 48-byte BLS G1 key (wire a
/// `dig-identity` chain resolution here); returning `None` fails closed with
/// [`MessageError::UnresolvableSender`]. `now_ms` is the receiver's wall clock for the freshness +
/// expiry checks.
///
/// # Errors
/// Fail-closed at each step: [`MessageError::UnresolvableSender`], [`MessageError::InvalidPoint`],
/// [`MessageError::OpenFailed`], [`MessageError::BadSignature`], [`MessageError::HeaderMismatch`],
/// [`MessageError::TtlTooLong`], [`MessageError::Expired`], [`MessageError::Replay`],
/// [`MessageError::DecompressionBomb`], and the codec/compression errors.
pub fn open_message(
    recipient_sk: &SecretKey,
    envelope: &DigMessageEnvelope,
    resolve_sender_pub: impl Fn(Bytes32, u32) -> Option<[u8; 48]>,
    guard: &mut ReplayGuard,
    now_ms: u64,
) -> Result<OpenedMessage> {
    let shape = InteractionShape::from_flags(envelope.flags).ok_or(MessageError::HeaderMismatch)?;

    // Resolve the sender key from the (AAD-bound, un-tamperable) cleartext DID + epoch.
    let sender_pub = resolve_sender_pub(envelope.sender, envelope.sender_epoch)
        .ok_or(MessageError::UnresolvableSender)?;

    let kem_enc: [u8; 48] = envelope
        .sealed
        .kem_enc
        .as_ref()
        .try_into()
        .expect("Bytes48 is exactly 48 bytes");

    // SPEC §5.1 (HARD): subgroup-check every received G1 point BEFORE any DH.
    if !g1_subgroup_check(&kem_enc) || !g1_subgroup_check(&sender_pub) {
        return Err(MessageError::InvalidPoint);
    }

    // SPEC §5.1 AuthDecap: Z2 = dh(recipient_sk, kem_enc) || dh(recipient_sk, sender_static_pub).
    let z = auth_decap_secret(recipient_sk, &sender_pub, &kem_enc)?;
    let recipient_pub = public_key_bytes(recipient_sk);
    let okm = kdf(&z, &kem_enc, &sender_pub, &recipient_pub);

    let aad = envelope.header_bytes()?;
    let inner_bytes = aead_open(&okm, &aad, &envelope.sealed.ciphertext)?;
    let inner =
        InnerMessage::from_bytes(&inner_bytes).map_err(|e| MessageError::Codec(e.to_string()))?;

    // (a) Verify the mandatory BLS G2 sender signature over the full transcript (SPEC §5.2).
    let transcript = TranscriptFields {
        version: envelope.version,
        message_type: envelope.message_type,
        flags: envelope.flags,
        correlation_id: envelope.correlation_id,
        sender: envelope.sender,
        recipient: envelope.recipient,
        sender_epoch: envelope.sender_epoch,
        counter: inner.counter,
        timestamp_ms: inner.timestamp_ms,
        expires_at: inner.expires_at,
        stream: envelope.stream,
        kem_enc: &kem_enc,
        compression: inner.compression,
        uncompressed_len: inner.uncompressed_len,
        compressed_payload: &inner.payload,
    };
    let sig: [u8; 96] = inner
        .sender_sig
        .as_ref()
        .try_into()
        .expect("Bytes96 is exactly 96 bytes");
    if !transcript.verify(&sender_pub, &sig) {
        return Err(MessageError::BadSignature);
    }

    // (b) Anti type-confusion / anti-splice: inner header MUST equal the cleartext header.
    if inner.message_type != envelope.message_type
        || inner.correlation_id != envelope.correlation_id
    {
        return Err(MessageError::HeaderMismatch);
    }

    // (c) Expiry discard (SPEC §5.6b) — BEFORE touching replay state.
    check_expiry(inner.timestamp_ms, inner.expires_at, now_ms)?;

    // (d) Anti-replay (SPEC §5.6): freshness window + bounded sliding-window dedup.
    if !guard.check_and_admit(
        envelope.sender,
        envelope.sender_epoch,
        inner.counter,
        inner.timestamp_ms,
        now_ms,
    ) {
        return Err(MessageError::Replay);
    }

    // (e) Bomb-guard cap + (f) decompress under the §1.1 output bound.
    if inner.uncompressed_len as usize > MAX_DECOMPRESSED_BYTES {
        return Err(MessageError::DecompressionBomb {
            declared: inner.uncompressed_len as usize,
            max: MAX_DECOMPRESSED_BYTES,
        });
    }
    let payload = decompress_payload(inner.compression, &inner.payload, inner.uncompressed_len)?;

    Ok(OpenedMessage {
        message_type: inner.message_type,
        correlation_id: inner.correlation_id,
        shape,
        sender: envelope.sender,
        sender_epoch: envelope.sender_epoch,
        counter: inner.counter,
        timestamp_ms: inner.timestamp_ms,
        expires_at: inner.expires_at,
        payload,
    })
}

/// SPEC §5.6b expiry semantics: reject an over-long TTL, discard a past-expiry message; `expires_at`
/// == 0 means no explicit expiry.
fn check_expiry(timestamp_ms: u64, expires_at: u64, now_ms: u64) -> Result<()> {
    if expires_at == 0 {
        return Ok(());
    }
    if expires_at > timestamp_ms.saturating_add(crate::constants::MAX_MESSAGE_TTL_MS) {
        return Err(MessageError::TtlTooLong);
    }
    if now_ms > expires_at {
        return Err(MessageError::Expired);
    }
    Ok(())
}

/// Sender-side AuthEncap ikm: `dh(esk, recipient_pub) || dh(sender_static_sk, recipient_pub)`.
fn auth_encap_secret(
    esk: &SecretKey,
    sender_sk: &SecretKey,
    recipient_pub: &[u8; 48],
) -> Result<[u8; 96]> {
    let ephemeral = g1_dh(esk, recipient_pub).ok_or(MessageError::InvalidPoint)?;
    let static_term = g1_dh(sender_sk, recipient_pub).ok_or(MessageError::InvalidPoint)?;
    Ok(concat_dh(&ephemeral, &static_term))
}

/// Recipient-side AuthDecap ikm: `dh(recipient_sk, kem_enc) || dh(recipient_sk, sender_pub)`.
fn auth_decap_secret(
    recipient_sk: &SecretKey,
    sender_pub: &[u8; 48],
    kem_enc: &[u8; 48],
) -> Result<[u8; 96]> {
    let ephemeral = g1_dh(recipient_sk, kem_enc).ok_or(MessageError::InvalidPoint)?;
    let static_term = g1_dh(recipient_sk, sender_pub).ok_or(MessageError::InvalidPoint)?;
    Ok(concat_dh(&ephemeral, &static_term))
}

/// Concatenate the two 48-byte DH results into the 96-byte HKDF ikm (`Z`).
fn concat_dh(a: &[u8; 48], b: &[u8; 48]) -> [u8; 96] {
    let mut z = [0u8; 96];
    z[..48].copy_from_slice(a);
    z[48..].copy_from_slice(b);
    z
}

/// HKDF-SHA256 key schedule (SPEC §5.1): extract over `salt=empty, ikm=Z`, expand over
/// `info = KDF_INFO_LABEL || kem_enc || sender_pub || recipient_pub` to the AEAD key + base nonce.
fn kdf(
    z: &[u8; 96],
    kem_enc: &[u8; 48],
    sender_pub: &[u8; 48],
    recipient_pub: &[u8; 48],
) -> [u8; OKM_LEN] {
    let hk = Hkdf::<Sha256>::new(None, z);
    let mut info = Vec::with_capacity(KDF_INFO_LABEL.len() + 48 * 3);
    info.extend_from_slice(KDF_INFO_LABEL);
    info.extend_from_slice(kem_enc);
    info.extend_from_slice(sender_pub);
    info.extend_from_slice(recipient_pub);
    let mut okm = [0u8; OKM_LEN];
    hk.expand(&info, &mut okm)
        .expect("OKM_LEN is well within the HKDF-SHA256 output limit");
    okm
}

/// ChaCha20Poly1305 seal with the header as AAD (SPEC §5.2).
fn aead_seal(okm: &[u8; OKM_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(&okm[..32])
        .map_err(|_| MessageError::SealFailed("invalid AEAD key length".into()))?;
    let nonce: [u8; 12] = okm[32..].try_into().expect("OKM tail is exactly 12 bytes");
    cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| MessageError::SealFailed("AEAD encrypt failed".into()))
}

/// ChaCha20Poly1305 open with the header as AAD (SPEC §5.2). A wrong key, wrong sender, tampered
/// ciphertext, or tampered AAD all fail here — fail-closed, no plaintext leaks.
fn aead_open(okm: &[u8; OKM_LEN], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(&okm[..32]).map_err(|_| MessageError::OpenFailed)?;
    let nonce: [u8; 12] = okm[32..].try_into().expect("OKM tail is exactly 12 bytes");
    cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| MessageError::OpenFailed)
}

/// Generate a fresh ephemeral BLS secret key for the DHKEM encapsulation (SPEC §5.1 forward secrecy).
fn random_ephemeral() -> Result<SecretKey> {
    let mut ikm = [0u8; 32];
    getrandom::getrandom(&mut ikm)
        .map_err(|e| MessageError::SealFailed(format!("ephemeral key entropy: {e}")))?;
    Ok(SecretKey::from_seed(&ikm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_identity::{derive_identity_sk, master_secret_key_from_seed};
    use sha2::Digest;

    fn sk(label: &str) -> SecretKey {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        derive_identity_sk(&master_secret_key_from_seed(&seed))
    }

    /// A deterministic ephemeral for reproducible KATs (never a hard-coded literal — CodeQL).
    fn ephemeral(label: &str) -> SecretKey {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        SecretKey::from_seed(&seed)
    }

    fn did(n: u8) -> Bytes32 {
        Bytes32::new([n; 32])
    }

    struct Party {
        sk: SecretKey,
        did: Bytes32,
        pub_key: [u8; 48],
    }
    fn party(label: &str, did_byte: u8) -> Party {
        let sk = sk(label);
        let pub_key = public_key_bytes(&sk);
        Party {
            sk,
            did: did(did_byte),
            pub_key,
        }
    }

    fn params<'a>(
        sender: &'a Party,
        recipient: &'a Party,
        payload: &'a [u8],
        counter: u64,
        timestamp_ms: u64,
        expires_at: u64,
    ) -> SealParams<'a> {
        SealParams {
            sender_sk: &sender.sk,
            sender: sender.did,
            sender_epoch: 0,
            recipient: recipient.did,
            recipient_pub: &recipient.pub_key,
            message_type: 0x0000_0201,
            shape: InteractionShape::OneShot,
            correlation_id: did(0xAB),
            stream: None,
            counter,
            timestamp_ms,
            expires_at,
            payload,
        }
    }

    /// A resolver returning a fixed sender key (the unit-test stand-in for dig-identity resolution).
    fn resolver(pk: [u8; 48]) -> impl Fn(Bytes32, u32) -> Option<[u8; 48]> {
        move |_did, _epoch| Some(pk)
    }

    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn seal_open_round_trip_raw() {
        let alice = party("seal/alice", 1);
        let bob = party("seal/bob", 2);
        let msg = b"hello bob";
        let env =
            seal_with_ephemeral(&params(&alice, &bob, msg, 0, NOW, 0), &ephemeral("e1")).unwrap();
        let mut guard = ReplayGuard::new();
        let opened = open_message(&bob.sk, &env, resolver(alice.pub_key), &mut guard, NOW).unwrap();
        assert_eq!(opened.payload, msg);
        assert_eq!(opened.sender, alice.did);
        assert_eq!(opened.counter, 0);
    }

    #[test]
    fn seal_open_round_trip_compressed() {
        let alice = party("seal/alice2", 1);
        let bob = party("seal/bob2", 2);
        let msg: Vec<u8> = (0..4096).map(|i| (i % 7) as u8).collect();
        let env =
            seal_with_ephemeral(&params(&alice, &bob, &msg, 0, NOW, 0), &ephemeral("e2")).unwrap();
        // Compression engaged: the sealed frame is far smaller than the 4 KiB plaintext.
        assert!(env.sealed.ciphertext.len() < msg.len());
        let mut guard = ReplayGuard::new();
        let opened = open_message(&bob.sk, &env, resolver(alice.pub_key), &mut guard, NOW).unwrap();
        assert_eq!(opened.payload, msg);
    }

    #[test]
    fn relay_sees_only_ciphertext_no_plaintext_substring() {
        let alice = party("seal/leak-a", 1);
        let bob = party("seal/leak-b", 2);
        let secret = b"TOP-SECRET-PLAINTEXT-MARKER";
        let env = seal_with_ephemeral(
            &params(&alice, &bob, secret, 0, NOW, 0),
            &ephemeral("eleak"),
        )
        .unwrap();
        let wire = crate::envelope::encode_envelope(&env).unwrap();
        assert!(
            wire.windows(secret.len()).all(|w| w != secret),
            "the plaintext must never appear on the wire"
        );
    }

    #[test]
    fn wrong_recipient_fails() {
        let alice = party("seal/a3", 1);
        let bob = party("seal/b3", 2);
        let eve = party("seal/eve3", 9);
        let env = seal_with_ephemeral(
            &params(&alice, &bob, b"secret", 0, NOW, 0),
            &ephemeral("e3"),
        )
        .unwrap();
        let mut guard = ReplayGuard::new();
        let err =
            open_message(&eve.sk, &env, resolver(alice.pub_key), &mut guard, NOW).unwrap_err();
        assert_eq!(err, MessageError::OpenFailed);
    }

    #[test]
    fn wrong_sender_pub_fails() {
        let alice = party("seal/a4", 1);
        let bob = party("seal/b4", 2);
        let mallory = party("seal/m4", 9);
        let env = seal_with_ephemeral(
            &params(&alice, &bob, b"secret", 0, NOW, 0),
            &ephemeral("e4"),
        )
        .unwrap();
        let mut guard = ReplayGuard::new();
        // Resolver returns the WRONG sender key -> the auth-DH static term differs -> AEAD open fails.
        let err =
            open_message(&bob.sk, &env, resolver(mallory.pub_key), &mut guard, NOW).unwrap_err();
        assert_eq!(err, MessageError::OpenFailed);
    }

    #[test]
    fn unresolvable_sender_fails_closed() {
        let alice = party("seal/a5", 1);
        let bob = party("seal/b5", 2);
        let env =
            seal_with_ephemeral(&params(&alice, &bob, b"x", 0, NOW, 0), &ephemeral("e5")).unwrap();
        let mut guard = ReplayGuard::new();
        let err = open_message(&bob.sk, &env, |_d, _e| None, &mut guard, NOW).unwrap_err();
        assert_eq!(err, MessageError::UnresolvableSender);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let alice = party("seal/a6", 1);
        let bob = party("seal/b6", 2);
        let mut env =
            seal_with_ephemeral(&params(&alice, &bob, b"x", 0, NOW, 0), &ephemeral("e6")).unwrap();
        let last = env.sealed.ciphertext.len() - 1;
        env.sealed.ciphertext[last] ^= 0x01;
        let mut guard = ReplayGuard::new();
        let err =
            open_message(&bob.sk, &env, resolver(alice.pub_key), &mut guard, NOW).unwrap_err();
        assert_eq!(err, MessageError::OpenFailed);
    }

    #[test]
    fn tampered_header_aad_rejected() {
        let alice = party("seal/a7", 1);
        let bob = party("seal/b7", 2);
        let mut env =
            seal_with_ephemeral(&params(&alice, &bob, b"x", 0, NOW, 0), &ephemeral("e7")).unwrap();
        // Flip the cleartext message_type: the AAD no longer matches -> AEAD open fails.
        env.message_type ^= 0xFF;
        let mut guard = ReplayGuard::new();
        let err =
            open_message(&bob.sk, &env, resolver(alice.pub_key), &mut guard, NOW).unwrap_err();
        assert_eq!(err, MessageError::OpenFailed);
    }

    #[test]
    fn non_subgroup_kem_enc_rejected() {
        let alice = party("seal/a8", 1);
        let bob = party("seal/b8", 2);
        let mut env =
            seal_with_ephemeral(&params(&alice, &bob, b"x", 0, NOW, 0), &ephemeral("e8")).unwrap();
        // A crafted non-subgroup / malformed kem_enc (all-0xFF is off-curve).
        env.sealed.kem_enc = Bytes48::new([0xFFu8; 48]);
        let mut guard = ReplayGuard::new();
        let err =
            open_message(&bob.sk, &env, resolver(alice.pub_key), &mut guard, NOW).unwrap_err();
        assert_eq!(err, MessageError::InvalidPoint);
    }

    #[test]
    fn bad_signature_rejected() {
        // Isolate the signature gate from the AEAD gate: seal a correctly-keyed envelope whose inner
        // carries a ZEROED (invalid) sender_sig, so AEAD-open succeeds but sig-verify must REJECT.
        let alice = party("seal/sigA", 1);
        let bob = party("seal/sigB", 2);
        let esk = ephemeral("esig");
        let compressed = compress_payload(b"x").unwrap();
        let sender_pub = public_key_bytes(&alice.sk);
        let kem_enc = public_key_bytes(&esk);
        let z = auth_encap_secret(&esk, &alice.sk, &bob.pub_key).unwrap();
        let okm = kdf(&z, &kem_enc, &sender_pub, &bob.pub_key);

        let inner = InnerMessage {
            message_type: 0x0000_0201,
            correlation_id: did(0xAB),
            compression: compressed.compression,
            uncompressed_len: compressed.uncompressed_len,
            counter: 0,
            timestamp_ms: NOW,
            expires_at: 0,
            payload: compressed.bytes,
            sender_sig: Bytes96::new([0u8; 96]), // invalid signature
        };
        let inner_bytes = inner.to_bytes().unwrap();
        let mut env = DigMessageEnvelope {
            version: VERSION,
            message_type: 0x0000_0201,
            flags: InteractionShape::OneShot.as_bits() | FLAG_SEALED,
            correlation_id: did(0xAB),
            sender: alice.did,
            recipient: bob.did,
            sender_epoch: 0,
            stream: None,
            sealed: SealedPayload {
                kem_enc: Bytes48::new(kem_enc),
                ciphertext: Vec::new(),
            },
        };
        let aad = env.header_bytes().unwrap();
        env.sealed.ciphertext = aead_seal(&okm, &aad, &inner_bytes).unwrap();

        let mut guard = ReplayGuard::new();
        let err =
            open_message(&bob.sk, &env, resolver(alice.pub_key), &mut guard, NOW).unwrap_err();
        assert_eq!(err, MessageError::BadSignature);
    }

    #[test]
    fn replay_rejected() {
        let alice = party("seal/a9", 1);
        let bob = party("seal/b9", 2);
        let env =
            seal_with_ephemeral(&params(&alice, &bob, b"x", 0, NOW, 0), &ephemeral("e9")).unwrap();
        let mut guard = ReplayGuard::new();
        assert!(open_message(&bob.sk, &env, resolver(alice.pub_key), &mut guard, NOW).is_ok());
        let err =
            open_message(&bob.sk, &env, resolver(alice.pub_key), &mut guard, NOW).unwrap_err();
        assert_eq!(err, MessageError::Replay);
    }

    #[test]
    fn stale_timestamp_rejected() {
        let alice = party("seal/a10", 1);
        let bob = party("seal/b10", 2);
        let env = seal_with_ephemeral(
            &params(&alice, &bob, b"x", 0, NOW - 3_600_000, 0),
            &ephemeral("e10"),
        )
        .unwrap();
        let mut guard = ReplayGuard::new();
        let err =
            open_message(&bob.sk, &env, resolver(alice.pub_key), &mut guard, NOW).unwrap_err();
        assert_eq!(err, MessageError::Replay);
    }

    #[test]
    fn in_window_reorder_accepted() {
        let alice = party("seal/a11", 1);
        let bob = party("seal/b11", 2);
        let mk = |c: u64| {
            seal_with_ephemeral(
                &params(&alice, &bob, b"x", c, NOW, 0),
                &ephemeral(&format!("e11-{c}")),
            )
            .unwrap()
        };
        let mut guard = ReplayGuard::new();
        assert!(open_message(&bob.sk, &mk(5), resolver(alice.pub_key), &mut guard, NOW).is_ok());
        assert!(open_message(&bob.sk, &mk(3), resolver(alice.pub_key), &mut guard, NOW).is_ok());
        assert_eq!(
            open_message(&bob.sk, &mk(3), resolver(alice.pub_key), &mut guard, NOW).unwrap_err(),
            MessageError::Replay
        );
    }

    #[test]
    fn expired_message_discarded() {
        let alice = party("seal/a12", 1);
        let bob = party("seal/b12", 2);
        let env = seal_with_ephemeral(
            &params(&alice, &bob, b"x", 0, NOW, NOW + 1000),
            &ephemeral("e12"),
        )
        .unwrap();
        let mut guard = ReplayGuard::new();
        let err = open_message(
            &bob.sk,
            &env,
            resolver(alice.pub_key),
            &mut guard,
            NOW + 5000,
        )
        .unwrap_err();
        assert_eq!(err, MessageError::Expired);
    }

    #[test]
    fn within_expiry_accepted() {
        let alice = party("seal/a13", 1);
        let bob = party("seal/b13", 2);
        let env = seal_with_ephemeral(
            &params(&alice, &bob, b"x", 0, NOW, NOW + 60_000),
            &ephemeral("e13"),
        )
        .unwrap();
        let mut guard = ReplayGuard::new();
        assert!(open_message(
            &bob.sk,
            &env,
            resolver(alice.pub_key),
            &mut guard,
            NOW + 1000
        )
        .is_ok());
    }

    #[test]
    fn over_long_ttl_rejected() {
        let alice = party("seal/a14", 1);
        let bob = party("seal/b14", 2);
        let expires = NOW + crate::constants::MAX_MESSAGE_TTL_MS + 10_000;
        let env = seal_with_ephemeral(
            &params(&alice, &bob, b"x", 0, NOW, expires),
            &ephemeral("e14"),
        )
        .unwrap();
        let mut guard = ReplayGuard::new();
        let err =
            open_message(&bob.sk, &env, resolver(alice.pub_key), &mut guard, NOW).unwrap_err();
        assert_eq!(err, MessageError::TtlTooLong);
    }

    #[test]
    fn self_addressed_round_trips() {
        // SPEC §5.6a: sender == recipient key (IPC / note-to-self) is first-class.
        let me = party("seal/self", 7);
        let env = seal_with_ephemeral(
            &SealParams {
                sender_sk: &me.sk,
                sender: me.did,
                sender_epoch: 0,
                recipient: me.did,
                recipient_pub: &me.pub_key,
                message_type: 0x0000_0601,
                shape: InteractionShape::OneShot,
                correlation_id: did(0xCD),
                stream: None,
                counter: 0,
                timestamp_ms: NOW,
                expires_at: 0,
                payload: b"note to self",
            },
            &ephemeral("eself"),
        )
        .unwrap();
        let mut guard = ReplayGuard::new();
        let opened = open_message(&me.sk, &env, resolver(me.pub_key), &mut guard, NOW).unwrap();
        assert_eq!(opened.payload, b"note to self");
        // Replay of the self-message is still rejected.
        assert_eq!(
            open_message(&me.sk, &env, resolver(me.pub_key), &mut guard, NOW).unwrap_err(),
            MessageError::Replay
        );
    }

    #[test]
    fn seal_message_uses_random_ephemeral_and_round_trips() {
        // The production path (random ephemeral): two seals of the same message differ (fresh KEM) but
        // both open correctly — the forward-secrecy property (SPEC §5.1).
        let alice = party("seal/rand-a", 1);
        let bob = party("seal/rand-b", 2);
        let p = params(&alice, &bob, b"random-ephemeral", 0, NOW, 0);
        let env1 = seal_message(&p).unwrap();
        let env2 = seal_message(&p).unwrap();
        assert_ne!(
            env1.sealed.kem_enc, env2.sealed.kem_enc,
            "fresh ephemeral per seal"
        );
        let mut guard = ReplayGuard::new();
        let opened =
            open_message(&bob.sk, &env1, resolver(alice.pub_key), &mut guard, NOW).unwrap();
        assert_eq!(opened.payload, b"random-ephemeral");
    }

    // ── WU2 deterministic-ephemeral KATs (golden vectors for integration testing) ──
    // These moved from tests/kat.rs into the crate so they can access pub(crate) seal_with_ephemeral.
    // Non-seal KATs stay in tests/kat.rs and use only the public seal_message API.

    const KAT_NOW: u64 = 1_700_000_000_000;

    fn b32_from_seed(tag: &[u8]) -> Bytes32 {
        let seed: [u8; 32] = sha2::Sha256::digest(tag).into();
        Bytes32::new(seed)
    }

    fn kat_sk(label: &str) -> SecretKey {
        let seed: [u8; 32] = sha2::Sha256::digest(label.as_bytes()).into();
        let msk = dig_identity::master_secret_key_from_seed(&seed);
        dig_identity::derive_identity_sk(&msk)
    }

    fn kat_ephemeral(label: &str) -> SecretKey {
        let seed: [u8; 32] = sha2::Sha256::digest(label.as_bytes()).into();
        SecretKey::from_seed(&seed)
    }

    fn kat_resolver(pk: [u8; 48]) -> impl Fn(Bytes32, u32) -> Option<[u8; 48]> {
        move |_did, _epoch| Some(pk)
    }

    fn kat_params<'a>(
        sender_sk: &'a SecretKey,
        sender: Bytes32,
        recipient: Bytes32,
        recipient_pub: &'a [u8; 48],
        payload: &'a [u8],
    ) -> SealParams<'a> {
        SealParams {
            sender_sk,
            sender,
            sender_epoch: 0,
            recipient,
            recipient_pub,
            message_type: 0x0001_0101,
            shape: InteractionShape::OneShot,
            correlation_id: b32_from_seed(b"kat/corr"),
            stream: None,
            counter: 0,
            timestamp_ms: KAT_NOW,
            expires_at: 0,
            payload,
        }
    }

    #[test]
    fn kat_seal_open_round_trip_raw_and_compressed() {
        let alice = kat_sk("kat/seal/alice");
        let bob = kat_sk("kat/seal/bob");
        let (a_did, b_did) = (b32_from_seed(b"kat/a"), b32_from_seed(b"kat/b"));
        let b_pub = public_key_bytes(&bob);

        for (label, msg) in [
            ("raw", b"hi".to_vec()),
            (
                "zstd",
                (0..2048).map(|i| (i % 5) as u8).collect::<Vec<u8>>(),
            ),
        ] {
            let params = kat_params(&alice, a_did, b_did, &b_pub, &msg);
            let env = seal_with_ephemeral(&params, &kat_ephemeral(label)).unwrap();
            let mut guard = ReplayGuard::new();
            let opened = open_message(
                &bob,
                &env,
                kat_resolver(public_key_bytes(&alice)),
                &mut guard,
                KAT_NOW,
            )
            .unwrap();
            assert_eq!(opened.payload, msg, "{label} payload round-trips");
        }
    }

    #[test]
    fn kat_relay_sees_only_ciphertext() {
        let alice = kat_sk("kat/leak/a");
        let bob = kat_sk("kat/leak/b");
        let secret = b"UNIQUE-PLAINTEXT-NEEDLE-XYZ";
        let b_pub = public_key_bytes(&bob);
        let params = kat_params(
            &alice,
            b32_from_seed(b"a"),
            b32_from_seed(b"b"),
            &b_pub,
            secret,
        );
        let env = seal_with_ephemeral(&params, &kat_ephemeral("leak")).unwrap();
        let wire = crate::envelope::encode_envelope(&env).unwrap();
        assert!(wire.windows(secret.len()).all(|w| w != secret));
    }

    #[test]
    fn kat_wrong_recipient_and_wrong_sender_reject() {
        let alice = kat_sk("kat/wr/a");
        let bob = kat_sk("kat/wr/b");
        let eve = kat_sk("kat/wr/eve");
        let b_pub = public_key_bytes(&bob);
        let params = kat_params(
            &alice,
            b32_from_seed(b"a"),
            b32_from_seed(b"b"),
            &b_pub,
            b"secret",
        );
        let env = seal_with_ephemeral(&params, &kat_ephemeral("wr")).unwrap();

        let mut g1 = ReplayGuard::new();
        assert_eq!(
            open_message(
                &eve,
                &env,
                kat_resolver(public_key_bytes(&alice)),
                &mut g1,
                KAT_NOW
            )
            .unwrap_err(),
            MessageError::OpenFailed,
            "wrong recipient key cannot open"
        );
        let mut g2 = ReplayGuard::new();
        assert_eq!(
            open_message(
                &bob,
                &env,
                kat_resolver(public_key_bytes(&eve)),
                &mut g2,
                KAT_NOW
            )
            .unwrap_err(),
            MessageError::OpenFailed,
            "wrong sender key cannot open"
        );
    }

    #[test]
    fn kat_non_subgroup_kem_enc_rejected() {
        let alice = kat_sk("kat/sg/a");
        let bob = kat_sk("kat/sg/b");
        let b_pub = public_key_bytes(&bob);
        let params = kat_params(
            &alice,
            b32_from_seed(b"a"),
            b32_from_seed(b"b"),
            &b_pub,
            b"x",
        );
        let mut env = seal_with_ephemeral(&params, &kat_ephemeral("sg")).unwrap();
        env.sealed.kem_enc = Bytes48::new([0xFFu8; 48]);
        let mut guard = ReplayGuard::new();
        assert_eq!(
            open_message(
                &bob,
                &env,
                kat_resolver(public_key_bytes(&alice)),
                &mut guard,
                KAT_NOW
            )
            .unwrap_err(),
            MessageError::InvalidPoint
        );
    }

    #[test]
    fn kat_replay_and_expiry() {
        let alice = kat_sk("kat/re/a");
        let bob = kat_sk("kat/re/b");
        let a_pub = public_key_bytes(&alice);
        let b_pub = public_key_bytes(&bob);
        let (a_did, b_did) = (b32_from_seed(b"a"), b32_from_seed(b"b"));

        // Replay: the same envelope twice -> second REJECT.
        let env = seal_with_ephemeral(
            &kat_params(&alice, a_did, b_did, &b_pub, b"x"),
            &kat_ephemeral("re0"),
        )
        .unwrap();
        let mut guard = ReplayGuard::new();
        assert!(open_message(&bob, &env, kat_resolver(a_pub), &mut guard, KAT_NOW).is_ok());
        assert_eq!(
            open_message(&bob, &env, kat_resolver(a_pub), &mut guard, KAT_NOW).unwrap_err(),
            MessageError::Replay
        );

        // Past-expires -> DISCARD.
        let mut expiring_params = kat_params(&alice, a_did, b_did, &b_pub, b"x");
        expiring_params.counter = 1;
        expiring_params.expires_at = KAT_NOW + 1000;
        let expiring = seal_with_ephemeral(&expiring_params, &kat_ephemeral("re1")).unwrap();
        let mut g2 = ReplayGuard::new();
        assert_eq!(
            open_message(
                &bob,
                &expiring,
                kat_resolver(a_pub),
                &mut g2,
                KAT_NOW + 5000
            )
            .unwrap_err(),
            MessageError::Expired
        );
    }

    #[test]
    fn kat_self_addressed_round_trip() {
        let me = kat_sk("kat/self");
        let me_pub = public_key_bytes(&me);
        let did = b32_from_seed(b"kat/self/did");
        let params = kat_params(&me, did, did, &me_pub, b"note to self");
        let env = seal_with_ephemeral(&params, &kat_ephemeral("self")).unwrap();
        let mut guard = ReplayGuard::new();
        let opened = open_message(&me, &env, kat_resolver(me_pub), &mut guard, KAT_NOW).unwrap();
        assert_eq!(opened.payload, b"note to self");
    }
}
