# dig-message — SPECIFICATION

Normative specification of the DIG Network generic base message protocol: the ONE structured, typed,
streamable, e2e-sealed envelope every DIRECTED (1:1 / group) peer-to-peer message rides. The
authoritative contract an independent reimplementation is built against. Key words per RFC 2119.

Status: skeleton (design frozen by DIG-Network/dig_ecosystem#796 / #811; byte-level KAT vectors are
filled during WU1-WU5 implementation, marked [KAT: ...] below). The design decisions herein are final.

## 0. Scope, stack position, and the two-wires reconciliation (NORMATIVE)

dig-message is the base message protocol layered between the transport and the identity layer:

    dig-gossip (transport: mTLS P2P, discovery, relay/NAT, opaque byte delivery, peer_id=SHA256(SPKI DER))
      -> dig-message (THIS crate: envelope + framing + type registry + streaming + e2e seal)
        -> dig-identity (DID: signing 0x0010, encryption 0x0011, peer_id 0x0012)
          -> dig-chat / dig-email / dig-video-chat / peer-RPC / data-request  (message TYPES)

The DIG Network has TWO distinct wires; this reconciliation is normative:

1. The client-to-node JSON-RPC-over-HTTP ladder — dig-rpc-protocol (types) + dig-rpc (axum server),
   ecosystem section 5.3 (dig.local -> localhost -> rpc.dig.net). Client-to-node control/read; browsers
   reach the PublicRead surface over plain HTTPS with NO client cert and NO recipient DID.
   dig-message SITS BESIDE this wire and does NOT subsume it. Rationale (final, no user fork):
   (a) the section 5.3 golden RPC fixtures MUST NOT break; (b) anonymous public/browser reads have no
   recipient DID to seal to (section 5.4 requires a recipient encryption key) and require plain
   HTTPS+CORS a browser can present; (c) a local-control surface gains nothing from an e2e seal. The
   HTTP JSON-RPC ladder is unchanged.

2. The peer-to-peer directed-message wire — dig-protocol DigMessage (Chia Message framing, u8 msg_type)
   carried over dig-gossip. dig-message SUBSUMES the directed peer-to-peer framing layer: every directed
   message a peer sends another (chat, email, video signaling, presence, directed data requests, and
   peer-to-peer request/response) is a dig-message envelope. Consensus BROADCAST (opcodes 200-219:
   blocks, transactions, attestations, checkpoints — public, all-peers) is the documented section 5.4
   exemption and stays mTLS-authenticated + signed, NOT dig-message-sealed.

Transport binding. A dig-message envelope is the data region of a dig_protocol::DigMessage with
msg_type = DIG_MESSAGE (220) — a single new directed opcode in the free 220..=255 band (200..=219 are
consensus broadcast). It rides the dig-gossip directed seam (send_to / request / a new streaming
helper). dig-gossip already exposes directed unicast (GossipHandle::send_to, ::request) beside
broadcast; the streaming helper is added in WU6.

## 1. Encoding & framing (NORMATIVE)

- Encoding = Chia Streamable. The envelope and every sub-structure are Chia Streamable (canonical,
  byte-deterministic, length-prefixed for variable regions) so Rust, wasm, and JS agree byte-for-byte
  (reuse chia-protocol / chia-wallet-sdk Streamable; never hand-roll framing).
- Length-framed + size-bounded. The outer DigMessage is already length-framed by dig-protocol;
  dig-message re-declares a hard MAX_ENVELOPE_BYTES cap (default 16 MiB; stream chunks capped separately,
  section 3) and a receiver MUST reject an over-cap or truncated envelope before decoding.
- Canonical types. DID identifiers are Bytes32 (identity singleton launcher_id) via
  chia-protocol/chia-wallet-sdk. Keys are the raw 32-byte X25519 (0x0011) / Ed25519 (0x0010) forms.

## 2. Base envelope (byte-level, NORMATIVE)

DigMessageEnvelope (Streamable), field order normative:

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | version | u8 | Envelope format version (current = 1). Additive: a newer reader MUST accept older versions; an unknown newer version is rejected UNSUPPORTED_VERSION. |
| 2 | message_type | u32 | Extensible type-registry id (section 4). Additive-only, never renumbered/repurposed (section 5.1 spirit). |
| 3 | flags | u8 | Bitfield: bits 0-1 = interaction shape (0=one-shot, 1=request, 2=response, 3=stream-frame); bit 2 = sealed (MUST be 1 for directed messages); remaining reserved-zero. |
| 4 | correlation_id | Bytes32 | Random per initiating message; echoed by the response and by every frame of a stream. |
| 5 | sender | Bytes32 | Sender DID launcher_id. |
| 6 | recipient | Bytes32 | Recipient DID launcher_id. |
| 7 | sender_epoch | u32 | Sender key epoch (identity slot 0x0013), for key-rotation disambiguation. |
| 8 | stream | Option<StreamHeader> | Present iff flags shape = stream-frame (section 3). |
| 9 | sealed | SealedPayload | The e2e-sealed region (section 5). ALL type-specific content lives here. |

The header fields (1-8) are cleartext envelope metadata (a relay needs recipient to route and
correlation_id/stream to multiplex). message_type is ALSO cleartext (routing) AND re-bound inside the
seal (section 5) to prevent type-confusion. No payload content is ever cleartext.
[KAT: golden envelope bytes for each shape.]

## 3. The three interaction shapes + streaming state machine (NORMATIVE)

- One-shot (fire-and-forget): a single envelope, shape=one-shot, no response expected.
- Request/response (correlated): a request envelope (shape=request) and a response envelope
  (shape=response) sharing correlation_id. A responder MUST echo the correlation_id; a requester MUST
  match responses by it and enforce a timeout.
- Streaming (first-class base capability): a long-lived, ordered, backpressured, cancelable,
  bidirectionally half-closable channel keyed by correlation_id.

StreamHeader (Streamable): { frame: u8, seq: u64, window: u32 } where frame in
{OPEN=0, OPEN_ACK=1, DATA=2, CREDIT=3, CLOSE=4, CLOSE_ACK=5, RESET=6}.

State machine (each direction tracked independently for half-close):

    Idle --OPEN(seal establishes stream secret, section 5.3)--> Opening
    Opening --OPEN_ACK--> Open
    Open  --DATA(seq, <=MAX_CHUNK)--> Open   (ordered: seq strictly monotonic; gap/reorder = error)
    Open  <--CREDIT(n)-->                    (credit-based backpressure: <= granted window in flight)
    Open  --CLOSE--> HalfClosed(local)       (this direction done; peer may still send)
          (both directions CLOSE + CLOSE_ACK) --> Closed
    Open/Opening/HalfClosed --RESET--> Closed (immediate abort, either party, any state)

- Ordered: seq is strictly monotonic per direction from 0; a receiver MUST reject a gap or
  out-of-order/replayed seq. The reliable mTLS WS transport guarantees delivery order; seq detects
  tampering/loss and drives the AEAD nonce chain (section 5.3).
- Backpressure: credit-based flow control. The receiver grants a window via CREDIT(n); the sender MUST
  NOT have more than the granted window of unacknowledged DATA in flight. Initial window is in
  OPEN/OPEN_ACK.
- Cancelable: RESET aborts immediately from any state, either party.
- Half-close both ways: CLOSE closes the sending direction only; the peer keeps sending until it also
  sends CLOSE. Full close when both directions closed (or on RESET).
- Chunk cap: MAX_CHUNK_BYTES (default 1 MiB).
- [KAT: streaming round-trip; a CANCEL/RESET vector; a backpressure vector.]

## 4. Extensible type registry (NORMATIVE)

- MessageType(u32) newtype. Additive-only: an id, once assigned, is never renumbered or repurposed; a
  receiver that does not recognize a message_type MUST fail cleanly (UNSUPPORTED_TYPE for request/stream;
  silently drop for one-shot) — never panic (section 5.1 spirit).
- Reserved bands (normative allocation; each subsystem owns a band, additive within it):

  | Band | Owner |
  |---|---|
  | 0x0000_0000 .. 0x0000_00FF | core (handshake, ack, error, keepalive) |
  | 0x0000_0100 .. 0x0000_01FF | peer-RPC (peer-to-peer request/response) |
  | 0x0000_0200 .. 0x0000_02FF | dig-chat (#768) |
  | 0x0000_0300 .. 0x0000_03FF | dig-email (#794) |
  | 0x0000_0400 .. 0x0000_04FF | dig-video-chat (#795, signaling) |
  | 0x0000_0500 .. 0x0000_05FF | presence / directed data-request |
  | >= 0x1000_0000 | experimental / vendor (never shipped as canonical) |

- The registration seam (Rust): a MessageKind trait — const TYPE_ID: MessageType; type Payload:
  Streamable; — plus a runtime MessageRegistry (MessageType -> decode+dispatch) a subsystem populates
  additively. A downstream crate (dig-chat) implements MessageKind for its payload types and registers
  them; dig-message never depends on a downstream crate.
- [KAT: unknown-type-dropped (one-shot) + unknown-type-error (request) vectors.]

## 5. Security — e2e seal to the recipient + sender authentication (HARD, ecosystem section 5.4)

mTLS is assumed at the dig-gossip transport. The dig-message sealed region is ADDITIONALLY sealed to the
recipient identity encryption key so any TLS-terminating relay/forwarder sees only ciphertext.

### 5.1 Cipher suite (vetted; NEVER invented)
- HPKE (RFC 9180), ciphersuite: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305. Recipient
  public key = the recipient DID slot 0x0011 X25519 key (resolved via dig-identity).
- Sender authentication = Ed25519 (slot 0x0010) signature, carried INSIDE the seal (so it is not
  relay-visible and is bound to the encryption). The signature covers a domain-separated transcript:
  "dig-message/v1" || version || message_type || correlation_id || sender || recipient || sender_epoch
  || hpke_enc || plaintext_hash. Binding hpke_enc (the HPKE encapsulated key) prevents KEM-reuse/replay
  across recipients. (HPKE mode_base for encryption; sender-auth via the Ed25519 signature, NOT HPKE
  mode_auth, because the authenticating identity is the DID Ed25519 key.)

### 5.2 SealedPayload (Streamable)
{ hpke_enc: [u8;32], ciphertext: Vec<u8> } where ciphertext = HPKE.Seal(recipient_0x0011, aad =
cleartext-header-bytes, pt = InnerMessage). Binding the cleartext header as AAD prevents an on-path party
from altering routing metadata. InnerMessage (Streamable) = { message_type: u32, correlation_id: Bytes32,
payload: Vec<u8>, sender_sig: [u8;64] }; a receiver MUST verify sender_sig against the resolved sender
0x0010 key AND that inner message_type/correlation_id equal the cleartext header (anti type-confusion /
anti splice).

### 5.3 Streaming keys
The STREAM OPEN seal establishes a per-stream secret (HPKE export, RFC 9180 section 5.3, exporter_context
= "dig-message/stream/v1" || correlation_id). Subsequent DATA chunks are AEAD-sealed (ChaCha20Poly1305)
under keys derived from that secret with nonce = seq (the monotonic section 3 counter), so per-chunk HPKE
is avoided while confidentiality + ordering + replay-resistance hold. The base spec provides this
per-stream secure channel; a higher layer (dig-chat #768) MAY layer a Double Ratchet over its payload.

### 5.4 Public-broadcast exemption
Consensus broadcast (opcodes 200-219: blocks, transactions, attestations, checkpoints — addressed to ALL
peers) has no single recipient key and is NOT dig-message-sealed; it stays mTLS-authenticated + signed.
dig-message governs DIRECTED (1:1/group) messaging only.

- [KAT: seal/open round-trip with fixed keys (test nonces DERIVED from a hashed seed, never integer
  literals — CodeQL); a relay-sees-only-ciphertext test asserting no plaintext substring in the on-wire
  envelope; a tampered-AAD/tampered-sig rejection vector; a wrong-recipient decrypt-fail vector.]

## 6. Threat model (NORMATIVE summary)

| Threat | Mitigation |
|---|---|
| Curious/compromised relay reads content | HPKE seal to recipient 0x0011; relay sees only ciphertext + routing metadata (section 5) |
| On-path tampering of routing metadata | Cleartext header bound as HPKE AAD (section 5.2) |
| Sender spoofing | Ed25519 (0x0010) signature over the transcript, verified against resolved DID (section 5.1) |
| Type-confusion / payload splicing | message_type + correlation_id re-bound inside the seal, checked == header (section 5.2) |
| Cross-recipient replay of a sealed message | Transcript binds recipient + hpke_enc (section 5.1) |
| Stream chunk replay/reorder/injection | Monotonic seq = AEAD nonce; per-stream derived key (section 5.3) |
| Resource exhaustion (huge msg / unbounded stream) | MAX_ENVELOPE_BYTES / MAX_CHUNK_BYTES / credit window (section 1, 3) |
| Key rotation / stale key | sender_epoch (0x0013) disambiguates; receiver resolves the epoch key |
| Unknown/newer version or type | Clean reject/drop, never panic (section 2, 4) |
| Metadata leakage (who talks to whom) | Documented residual: envelope reveals sender/recipient DID + timing to the relay; out of base scope (a future sealed-sender/onion layer MAY reduce it) |

## 7. Conformance

An implementation conforms iff it (a) encodes/decodes every section 2/3 structure byte-identically to the
golden KATs; (b) seals/opens per section 5 and passes the relay-ciphertext + tamper + wrong-recipient
KATs; (c) drives the section 3 streaming state machine incl. backpressure + half-close + cancel;
(d) handles unknown version/type per section 2/4 without panic; (e) agrees byte-for-byte across the Rust
and wasm/JS targets. SPEC.md, docs.dig.net protocol page, and superproject SYSTEM.md MUST agree
(ecosystem section 4.2 layering).
