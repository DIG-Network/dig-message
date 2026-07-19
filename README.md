# dig-message

Canonical **generic base message protocol** for the DIG Network: the ONE structured
envelope every DIRECTED (1:1 / group) peer-to-peer message rides — RPC calls, data/
content requests, chat, email, video signaling, presence, authenticated local IPC —
anything one peer sends another. Consensus BROADCAST (blocks/transactions/attestations)
is the documented exemption and stays mTLS-authenticated + signed, not dig-message-sealed
(SPEC §5.4).

Stack: **dig-gossip** (transport: mTLS P2P) → **dig-message** (this crate: envelope +
framing + compression + the type registry + the e2e seal) → **dig-identity** (the DID/
keys the seal resolves) → dig-chat / dig-email / dig-video-chat / peer-RPC / IPC (message
TYPES built on this base).

Security: mTLS at the transport **plus** every payload is e2e-sealed to the recipient
using the ONE Chia BLS12-381 identity key (dig-identity slot 0x0010) — its G2 signature
authenticates the sender and a DHKEM over its G1 group seals the payload (no X25519, no
Ed25519), so a TLS-terminating relay sees only ciphertext + routing metadata (CLAUDE.md
§5.4). Every message is also anti-replay protected and carries a sender-controlled expiry.

Wire: a compact, byte-deterministic Chia-Streamable binary format (never JSON), payload
compressed (raw or zstd) BEFORE the seal, length-framed and size-bounded. `SPEC.md` is the
normative contract this README summarizes for day-to-day use — read it for the byte-level
detail (transcript encoding, KDF/AEAD composition, the full threat model).

Status — **v0.3.1**: the envelope + framing + compression (WU1), the extensible type
registry (WU3), and the full e2e seal/open pipeline with BLS signing + anti-replay +
expiry (WU2) are shipped. **Streaming (the `StreamHeader`/`StreamFrame` state machine,
WU4) is in flight** — the wire fields are already final (see below) but the OPEN/DATA/
CLOSE state-machine driver is landing separately. wasm/JS bindings (WU5) follow.

## The export interface

Everything below is re-exported from the crate root (`dig_message::*`); the module paths
are shown for reference.

### Envelope (`envelope`)

The byte-deterministic Chia-Streamable wire shapes and their codec.

- **`DigMessageEnvelope`** — the base envelope. Fields 1-8 (`version`, `message_type`,
  `flags`, `correlation_id`, `sender`, `recipient`, `sender_epoch`, `stream`) are the
  cleartext routing header a relay reads to route + multiplex; field 9 (`sealed`) is the
  e2e-sealed region — ALL type-specific content lives there, never in cleartext.
  `envelope.header_bytes()` returns the serialized cleartext header, the exact bytes bound
  as the seal's AEAD associated data (AAD).
- **`InnerMessage`** — the sealed inner message (only ever seen after a successful open):
  the re-bound `message_type`/`correlation_id` (anti type-confusion), `compression` +
  `uncompressed_len`, the anti-replay `counter` + `timestamp_ms`, the `expires_at` TTL, the
  compressed `payload` bytes, and the mandatory 96-byte `sender_sig`.
  - **`SealedPayload`** — `{ kem_enc: Bytes48, ciphertext: Vec<u8> }`, the wire shape of
    field 9: the DHKEM ephemeral encapsulation and the AEAD-sealed `InnerMessage` bytes.
- **`InteractionShape`** — the four ways a message relates to others: `OneShot` (fire-
  and-forget), `Request` / `Response` (correlated via `correlation_id`), `StreamFrame` (a
  frame of a stream). Encoded in `flags` bits 0-1 (`from_flags` / `as_bits`); `FLAG_SEALED`
  (bit 2) MUST be set on every directed message; `FLAG_SHAPE_MASK` isolates the shape bits.
- **`StreamHeader`** — `{ frame: u8, seq: u64, window: u32 }`, present iff the shape is
  `StreamFrame`. **`StreamFrame`** names the frame kinds (`Open`, `OpenAck`, `Data`,
  `Credit`, `Close`, `CloseAck`, `Reset`). The fields are final; the driving state machine
  is WU4 (see Status above).
- **`encode_envelope(&DigMessageEnvelope) -> Result<Vec<u8>>`** / **`decode_envelope(&[u8])
  -> Result<DigMessageEnvelope>`** — the length-framed, size-bounded codec. Encoding rejects
  a frame over `MAX_ENVELOPE_BYTES` (16 MiB); decoding rejects an over-cap frame BEFORE
  parsing and an unknown newer `version` after.

### Compression (`compression`)

The crypto-free codec that runs before the seal, in its own fresh context per message.

- **`compress_payload(&[u8]) -> Result<CompressedPayload>`** — picks the codec per the raw
  threshold (`MIN_COMPRESS_BYTES` = 64 bytes): payloads below it, or that zstd fails to
  shrink, stay raw (`COMPRESSION_NONE`); larger, genuinely-compressible payloads use zstd
  level 3 (`COMPRESSION_ZSTD`, pinned, deterministic, no dictionary).
- **`decompress_payload(compression: u8, data: &[u8], uncompressed_len: u32) ->
  Result<Vec<u8>>`** — the decompression-bomb guard: rejects a declared length over
  `MAX_DECOMPRESSED_BYTES` (64 MiB) BEFORE decoding, bounds the decoder output to that cap
  DURING, and rejects on any length mismatch.
- **`CompressedPayload`** — `{ compression: u8, bytes: Vec<u8>, uncompressed_len: u32 }`,
  the result `seal_message` compresses before sealing.
- **`COMPRESSION_NONE`** (0, mandatory) / **`COMPRESSION_ZSTD`** (1, recommended default).
  Ids 2..=63 are reserved for future standard codecs, 64..=255 for experimental/vendor —
  never shipped as canonical. An unrecognized id fails cleanly (`UnsupportedCompression`),
  never mis-decodes.

### The extensible type registry (`registry`)

The runtime seam through which every downstream subsystem (dig-chat, dig-email, dig-
video, peer-RPC, IPC) plugs its own message types into this one base protocol, without
dig-message depending on any of them.

**Reserved id bands** (each subsystem owns a 256-wide band, allocated additively within
it; an id, once assigned, is never renumbered or repurposed):

| Band constant | Range | Owner |
|---|---|---|
| `BAND_CORE` | `0x0000_0000..=0x0000_00FF` | handshake / ack / error / keepalive |
| `BAND_PEER_RPC` | `0x0000_0100..=0x0000_01FF` | peer-to-peer request/response |
| `BAND_DIG_CHAT` | `0x0000_0200..=0x0000_02FF` | dig-chat |
| `BAND_DIG_EMAIL` | `0x0000_0300..=0x0000_03FF` | dig-email |
| `BAND_DIG_VIDEO` | `0x0000_0400..=0x0000_04FF` | dig-video-chat signaling |
| `BAND_PRESENCE` | `0x0000_0500..=0x0000_05FF` | presence / directed data-request |
| `BAND_IPC` | `0x0000_0600..=0x0000_06FF` | dig-ipc-protocol (local dig-app ↔ dig-node) |
| — | `0x0000_0700..=0x0FFF_FFFF` | reserved for future bands (currently unallocated — `0x0700` is reserved for a social-graph band, see #1192) |
| `BAND_EXPERIMENTAL` | `>= 0x1000_0000` | experimental / vendor, never canonical |

`MessageType::band()` classifies any `u32` id into its `MessageBand` (total — every id
maps to a band, including `MessageBand::Reserved` for an unallocated one). Four named
core-band constants ship built in: `MessageType::CORE_HANDSHAKE` / `CORE_ACK` /
`CORE_ERROR` / `CORE_KEEPALIVE`.

- **`MessageKind`** — the compile-time contract a downstream type declares: `const TYPE_ID:
  MessageType` (its reserved id) + `type Payload: Streamable` (its typed, byte-
  deterministic payload).
- **`MessageRegistry`** — the runtime `MessageType -> handler` table. `new()` an empty
  one; `register::<K, F>(handler)` adds a `MessageKind` additively (`DuplicateType` if
  that id is already registered — never silently overwritten); `contains()` / `len()` /
  `is_empty()` introspect it; `dispatch(message_type, shape, payload_bytes)` decodes the
  bytes into the kind's `Payload` and invokes the handler.
- **`Dispatch`** — the outcome of a `dispatch` call: `Handled` (a registered handler ran)
  or `Dropped` (the type was unknown and the shape was one-shot/response — the intended
  forward-compat behavior, not an error). An unknown `Request`/`StreamFrame` instead
  returns `MessageError::UnsupportedType` so the caller can reply with an error. Dispatch
  never panics on an unknown type.

### The e2e seal pipeline (`seal`)

ONE Chia BLS12-381 identity keypair does everything: its G2 signature authenticates the
sender, and ECDH over its G1 group (a DHKEM, HPKE AuthEncap-style) seals the payload to
the recipient. No X25519, no Ed25519.

- **`seal_message(&SealParams) -> Result<DigMessageEnvelope>`** — the full send-side
  pipeline: compress → BLS-G2 sign the transcript (domain-separated so it can never be
  confused with a chain `AGG_SIG_*` signature) → G1-DHKEM auth-seal with a fresh ephemeral
  key (forward secrecy — two seals of the same message never produce the same `kem_enc`).
- **`open_message(recipient_sk, &envelope, resolve_sender_pub, &mut ReplayGuard, now_ms) ->
  Result<OpenedMessage>`** — the full receive-side pipeline, fail-closed at every step:
  subgroup-check the KEM point + resolved sender key → G1-DHKEM auth-decap + AEAD-open →
  verify the BLS-G2 sender signature → check the inner header matches the cleartext header
  (anti-splice) → expiry discard → anti-replay check → decompress under the bomb guard.
  `resolve_sender_pub` maps `(sender DID, sender_epoch)` to the sender's 48-byte BLS G1 key
  (wire a `dig-identity` chain lookup here); returning `None` fails closed with
  `UnresolvableSender`.
- **`SealParams`** — everything a sender supplies: `sender_sk`, `sender` (DID),
  `sender_epoch`, `recipient` (DID), `recipient_pub`, `message_type`, `shape`,
  `correlation_id`, `stream` (for a stream frame), the anti-replay `counter` +
  `timestamp_ms`, `expires_at` (0 = no explicit expiry), and the raw `payload` bytes.
- **`OpenedMessage`** — the verified result: `message_type`, `correlation_id`, `shape`,
  `sender`, `sender_epoch`, `counter`, `timestamp_ms`, `expires_at`, and the decompressed
  plaintext `payload` — ready to hand to `MessageRegistry::dispatch`.
- **`ReplayGuard`** (`replay` module) — the anti-replay state machine: a freshness window
  (±5 min default) rejecting stale/future timestamps, plus a bounded per-`(sender,
  sender_epoch)` sliding-window counter dedup (in-window reorder accepted, a duplicate or
  too-old counter rejected), under an LRU cap on tracked senders so a Sybil flood cannot
  exhaust memory. `ReplayGuard::new()` starts empty; `check_and_admit(...)` is called
  internally by `open_message` — construct one per receiver/session and reuse it across
  opens from that peer.

### Errors (`error`)

`MessageError` is the crate's stable, catalogued error taxonomy (`thiserror`-derived, a
scripted client can key off the variant): `EnvelopeTooLarge`, `Truncated`,
`UnsupportedVersion`, `UnsupportedCompression`, `DecompressionBomb`,
`DecompressedLengthMismatch`, `PayloadTooLarge`, `Codec`, `UnsupportedType`,
`DuplicateType`, `InvalidPoint`, `UnresolvableSender`, `SealFailed`, `OpenFailed`,
`BadSignature`, `HeaderMismatch`, `Replay`, `Expired`, `TtlTooLong`. `Result<T>` is the
crate's `Result<T, MessageError>` alias.

## Usage

### Seal a message to a recipient

```rust
use dig_message::{seal_message, encode_envelope, InteractionShape, SealParams};

// `sender_sk` is the sender's dig-identity BLS12-381 identity key (slot 0x0010);
// `recipient_pub` is the recipient's 48-byte compressed BLS G1 public key, resolved via
// dig-identity from the recipient DID.
let envelope = seal_message(&SealParams {
    sender_sk: &sender_sk,
    sender: sender_did,
    sender_epoch: 0,
    recipient: recipient_did,
    recipient_pub: &recipient_pub,
    message_type: 0x0000_0201, // a dig-chat text message id (BAND_DIG_CHAT + offset)
    shape: InteractionShape::OneShot,
    correlation_id,
    stream: None,
    counter: next_counter, // persisted per (sender -> recipient), strictly monotonic
    timestamp_ms: now_ms,
    expires_at: 0, // no explicit expiry
    payload: b"hello",
})?;

// Wire bytes ready to hand to the dig-gossip directed send (send_to / request).
let wire_bytes = encode_envelope(&envelope)?;
```

### Receive: decode → open → verify

```rust
use dig_message::{decode_envelope, open_message, replay::ReplayGuard};

let envelope = decode_envelope(&wire_bytes)?;

// One ReplayGuard per receiver/session, reused across every open from that peer.
let mut guard = ReplayGuard::new();

let opened = open_message(
    &recipient_sk,             // this receiver's dig-identity secret key
    &envelope,
    |sender_did, sender_epoch| resolve_bls_key(sender_did, sender_epoch), // dig-identity lookup
    &mut guard,
    now_ms,
)?;

// `opened.payload` is decompressed, signature-verified, replay-checked plaintext —
// hand it (with opened.message_type / opened.shape) to a MessageRegistry to dispatch.
```

### Register a type and dispatch

```rust
use chia_streamable_macro::Streamable;
use dig_message::{registry::{MessageKind, MessageRegistry, BAND_DIG_CHAT}, MessageType};

#[derive(Streamable)]
struct ChatText { body: Vec<u8> }

struct ChatTextKind;
impl MessageKind for ChatTextKind {
    const TYPE_ID: MessageType = MessageType(BAND_DIG_CHAT);
    type Payload = ChatText;
}

let mut registry = MessageRegistry::new();
registry.register::<ChatTextKind, _>(|msg: ChatText| {
    // handle the decoded, typed payload
    Ok(())
})?;

// After open_message: route the opened payload to its registered handler.
registry.dispatch(MessageType(opened.message_type), opened.shape, &opened.payload)?;
```

## See also

- **`SPEC.md`** — the normative contract this README summarizes: the byte-level wire
  format, the signed transcript encoding, the DHKEM/HKDF/AEAD composition, the full
  streaming state machine, and the threat model. Any behavior described here defers to
  `SPEC.md` on conflict.
- Design + DAG: DIG-Network/dig_ecosystem#796.
