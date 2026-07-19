# dig-message — SPECIFICATION

Normative specification of the DIG Network generic base message protocol: the ONE structured, typed,
streamable, e2e-sealed envelope every DIRECTED (1:1 / group) peer-to-peer message rides. The
authoritative contract an independent reimplementation is built against. Key words per RFC 2119.

Status: skeleton (design frozen by DIG-Network/dig_ecosystem#796 / #811, amended 2026-07-19 to a
COMPRESSED BINARY format — compress-before-seal, additive compression-algo negotiation, decompression-
bomb guard — to a UNIVERSALLY SIGNED + REPLAY-PROTECTED format — mandatory CHIA BLS (BLS12-381)
sender-signature inside the seal on EVERY message/frame + a bounded sliding-window anti-replay scheme — and to an
DHKEM-over-BLS12-381-G1 AUTH-MODE seal (HPKE-style, ONE Chia BLS keypair does BOTH the G2 sender
signature AND the G1 ECDH seal — NO X25519, NO Ed25519) openable ONLY by the recipient private key +
the sender public key; self-addressed (sender==recipient key, e.g. IPC) is first-class; byte-level KAT
vectors are filled during WU1-WU5 implementation, marked [KAT: ...] below). The design decisions herein
are final.

## 0. Scope, stack position, and the two-wires reconciliation (NORMATIVE)

dig-message is the base message protocol layered between the transport and the identity layer:

    dig-gossip (transport: mTLS P2P, discovery, relay/NAT, opaque byte delivery, peer_id=SHA256(SPKI DER))
      -> dig-message (THIS crate: envelope + framing + type registry + streaming + e2e seal)
        -> dig-identity (DID: ONE Chia BLS12-381 identity key 0x0010 = sign (G2) + seal-DH (G1); peer_id 0x0012)
          -> dig-chat / dig-email / dig-video-chat / peer-RPC / data-request  (message TYPES)

The DIG Network has TWO distinct wires; this reconciliation is normative:

1. The client-to-node JSON-RPC-over-HTTP ladder — dig-rpc-protocol (types) + dig-rpc (axum server),
   ecosystem section 5.3 (dig.local -> localhost -> rpc.dig.net). Client-to-node control/read; browsers
   reach the PublicRead surface over plain HTTPS with NO client cert and NO recipient DID.
   dig-message SITS BESIDE this wire and does NOT subsume it. Rationale (final, no user fork):
   (a) the section 5.3 golden RPC fixtures MUST NOT break; (b) ANONYMOUS public/browser reads have no
   recipient DID to seal to (section 5.4 needs the recipient's BLS identity key) and require plain
   HTTPS+CORS a browser can present. The anonymous-HTTP-read path is the ONLY path that stays BESIDE
   dig-message (unsealed). NOTE: authenticated local IPC (dig-app <-> dig-node, a SHARED/same identity
   key) is NOT beside — it RIDES dig-message as a registered type (see wire 2 + section 4 IPC band),
   sealed+signed to the shared key (the self-addressed case, section 5.6a). The HTTP JSON-RPC ladder is
   unchanged.

2. The peer-to-peer directed-message wire — dig-protocol DigMessage (Chia Message framing, u8 msg_type)
   carried over dig-gossip. dig-message SUBSUMES the directed peer-to-peer framing layer: every directed
   message a peer sends another (chat, email, video signaling, presence, directed data requests,
   peer-to-peer request/response, AND authenticated local IPC — dig-ipc-protocol is a dig-message TYPE,
   section 4) is a dig-message envelope. Consensus BROADCAST (opcodes 200-219:
   blocks, transactions, attestations, checkpoints — public, all-peers) is the documented section 5.4
   exemption and stays mTLS-authenticated + signed, NOT dig-message-sealed.

Transport binding. A dig-message envelope is the data region of a dig_protocol::DigMessage with
msg_type = DIG_MESSAGE (220) — a single new directed opcode in the free 220..=255 band (200..=219 are
consensus broadcast). It rides the dig-gossip directed seam (send_to / request / a new streaming
helper). dig-gossip already exposes directed unicast (GossipHandle::send_to, ::request) beside
broadcast; the streaming helper is added in WU6.

## 1. Encoding, framing & compression (NORMATIVE)

- Compact BINARY format. dig-message is a compact binary wire format, NOT a text/JSON format. The
  envelope and every sub-structure are Chia Streamable (canonical, byte-deterministic, length-prefixed
  for variable regions) so Rust, wasm, and JS agree byte-for-byte (reuse chia-protocol /
  chia-wallet-sdk Streamable; never hand-roll framing, never emit JSON/text on the wire).
- Payload pipeline (NORMATIVE ordering, security-critical): serialize the type payload (Streamable
  bytes) -> COMPRESS (section 1.1) -> e2e-SEAL (DHKEM-over-G1 auth mode, section 5). Compression MUST
  happen BEFORE the seal: sealed ciphertext is high-entropy and incompressible, so compressing after the
  seal is useless;
  compressing the plaintext first is the only placement that gains size. The receiver reverses it:
  open seal -> bomb-guard check -> decompress -> decode payload.
- Length-framed + size-bounded. The outer DigMessage is already length-framed by dig-protocol;
  dig-message re-declares a hard MAX_ENVELOPE_BYTES cap (default 16 MiB, measured on the on-wire
  compressed+sealed frame) and a MAX_DECOMPRESSED_BYTES cap (default 64 MiB per message; stream chunks
  capped separately, section 3). A receiver MUST reject an over-cap or truncated envelope before
  decoding, and MUST enforce MAX_DECOMPRESSED_BYTES BEFORE and DURING decompression (section 1.1
  decompression-bomb guard).
- Canonical types. DID identifiers are Bytes32 (identity singleton launcher_id) via
  chia-protocol/chia-wallet-sdk. Keys: ONE Chia BLS12-381 identity key (dig-identity slot 0x0010) —
  a 48-byte compressed G1 public key (minimal-pubkey-size), 96-byte G2 signature — is used for BOTH the
  sender signature (G2) AND the seal DH (G1). NO X25519, NO Ed25519 (section 5.1).

### 1.1 Compression layer (additive negotiation + bomb guard, NORMATIVE)

Compression is applied to the Streamable payload bytes INSIDE the seal (the compressed bytes are the
sealed plaintext; the algorithm id and original length are carried in the sealed InnerMessage,
section 5.2 — so they are AEAD-authenticated and NOT relay-visible, adding no metadata leak).

- Algorithm id (u8, additive per section 5.1). Once assigned, an id is NEVER renumbered or repurposed.

  | id | Algorithm | Support | Use |
  |---|---|---|---|
  | 0 | none / raw | MANDATORY (every impl MUST support) | Small or incompressible payloads (section below). |
  | 1 | zstd | RECOMMENDED default | General payloads above the raw threshold. Level PINNED = 3 (zstd default; deterministic, no dictionary). |
  | 2..=63 | reserved (standard algos) | — | Future standard codecs (e.g. brotli), assigned additively. |
  | 64..=255 | reserved (experimental/vendor) | — | Never shipped as canonical. |

- Raw threshold. A sender MUST use id=0 (raw) when the payload is below MIN_COMPRESS_BYTES
  (default 64 bytes) OR when compression does not shrink it (compressed length >= raw length —
  incompressible/already-compressed data). Otherwise it SHOULD use id=1 (zstd). This keeps small and
  incompressible payloads from paying a compression header/expansion penalty.
- Unknown-id handling (never crash). A receiver that does not recognize the compression id MUST fail
  cleanly: UNSUPPORTED_COMPRESSION for request/stream, silent drop for one-shot (mirrors the
  section 4 unknown-type rule). It MUST NOT panic or attempt to decompress with a wrong codec.
- Decompression-bomb guard (HARD). The sealed InnerMessage carries uncompressed_len:u32 (the declared
  original length). Before decompressing, a receiver MUST reject the frame if uncompressed_len >
  MAX_DECOMPRESSED_BYTES. During decompression it MUST bound the output stream to MAX_DECOMPRESSED_BYTES
  and abort (reject the frame) if the decoder tries to exceed that OR if the actual decoded length !=
  uncompressed_len. A hostile peer MUST NOT be able to OOM the host via a compression bomb.
- Codec = a byte-deterministic zstd usable from Rust AND wasm/JS (section 1.2). id=0 is the trivial
  identity codec (payload bytes verbatim).

### 1.2 wasm/JS codec parity (NORMATIVE)

The zstd codec (id=1) MUST have a wasm/JS-compatible implementation so browser/extension peers encode
and decode byte-identically to native Rust peers. Rust uses the `zstd` crate (libzstd bindings) pinned
to level 3, no dictionary, single-frame; the wasm/JS target uses a WASM build of libzstd
(e.g. `@bokuweb/zstd-wasm` / a vendored `libzstd` compiled to wasm) at the SAME level/params. Because
compression happens before the seal and the compressed bytes are what get AEAD-authenticated, the two
targets MUST produce identical compressed bytes for the pinned params — a Rust<->wasm/JS byte-agreement
KAT (section 7, WU5) proves it. id=0 (raw) is trivially identical across targets.

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
seal (section 5) to prevent type-confusion. No payload content is ever cleartext. The compression
algorithm id and the uncompressed length live INSIDE the seal (section 5.2 InnerMessage), NOT in the
cleartext header — so compression metadata is AEAD-authenticated and invisible to the relay.
[KAT: golden envelope bytes for each shape, including a raw(id=0) and a zstd(id=1) sealed payload.]
(WU1 golden vectors — committed as SHA-256 digests of the deterministic on-wire bytes — live in
`tests/kat.rs`: one-shot / request / response / stream-frame envelope encodings + the raw and
zstd(level-3) compression round-trips; the seal/signature/replay/streaming vectors are the marked
WU2/WU4 placeholders there.)

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
- Signed frames: EVERY stream frame is BLS-signed (section 5.1) inside its seal with the frame type
  + seq bound; an unsigned/bad-sig/replayed/reordered frame is rejected (section 5.3/5.6).
- [KAT: streaming round-trip; a CANCEL/RESET vector; a backpressure vector; a cross-session frame-replay
  reject vector.]

## 4. Extensible type registry (NORMATIVE)

- MessageType(u32) newtype. Additive-only: an id, once assigned, is never renumbered or repurposed; a
  receiver that does not recognize a message_type MUST fail cleanly (UNSUPPORTED_TYPE for request/stream;
  silently drop for one-shot) — never panic (section 5.1 spirit).
- Reserved bands (normative allocation; each subsystem owns a band, additive within it):

  | Band | Owner |
  |---|---|
  | 0x0000_0000 .. 0x0000_00FF | core (handshake, ack, error, keepalive) |
  | 0x0000_0100 .. 0x0000_01FF | peer-RPC (peer-to-peer request/response) |
  | 0x0000_0600 .. 0x0000_06FF | dig-ipc-protocol (authenticated local dig-app <-> dig-node IPC; self-addressed shared key) |
  | 0x0000_0200 .. 0x0000_02FF | dig-chat (#768) |
  | 0x0000_0300 .. 0x0000_03FF | dig-email (#794) |
  | 0x0000_0400 .. 0x0000_04FF | dig-video-chat (#795, signaling) |
  | 0x0000_0500 .. 0x0000_05FF | presence / directed data-request |
  | >= 0x1000_0000 | experimental / vendor (never shipped as canonical) |

  Core band assignments (additive, WU3): handshake = 0x0000_0000, ack = 0x0000_0001,
  error = 0x0000_0002, keepalive = 0x0000_0003. An id that falls in NO allocated subsystem band above
  (e.g. 0x0000_0700 .. 0x0FFF_FFFF) is Reserved for a future band; a reader MUST still be able to
  classify it (it maps to the Reserved band) and MUST apply the unknown-type rule if it is unregistered.
- The registration seam (Rust): a MessageKind trait — const TYPE_ID: MessageType; type Payload:
  Streamable; — plus a runtime MessageRegistry (MessageType -> decode+dispatch) a subsystem populates
  additively. A downstream crate (dig-chat) implements MessageKind for its payload types and registers
  them; dig-message never depends on a downstream crate. Registering an already-assigned id is REFUSED
  (never silently overwritten), upholding the additive-only rule. dispatch(message_type, shape, payload)
  routes to the registered handler; an unregistered type returns UNSUPPORTED_TYPE for a request/stream
  shape and is silently dropped for a one-shot/response shape (never a panic).
- [KAT: unknown-type-dropped (one-shot) + unknown-type-error (request) vectors.]

## 5. Security — e2e seal + universal sender signature + replay protection (HARD, ecosystem section 5.4)

mTLS is assumed at the dig-gossip transport. The dig-message sealed region is ADDITIONALLY sealed to the
recipient identity key so any TLS-terminating relay/forwarder sees only ciphertext. ONE key type does
everything: the identity Chia BLS12-381 keypair (dig-identity slot 0x0010) — its G2 signatures
authenticate the sender, and ECDH over its G1 group seals the payload. There is NO X25519 and NO Ed25519
anywhere.

### 5.1 Keys, signature, and seal (vetted; NEVER invented)

- Identity key = Chia BLS12-381 (minimal-pubkey-size: G1 public key = 48-byte compressed point, private
  = a scalar in Z_r, G2 signature = 96-byte compressed point), the wallet-controlled key via
  chia-wallet-sdk / chia_bls (blst). The SAME keypair is used for BOTH the sender signature (G2) and the
  seal DH (G1). Section 5.7 covers the key-reuse safety + domain separation.
- Sender SIGNATURE = BLS (AugSchemeMPL, the Chia augmented scheme), MANDATORY and UNIVERSAL: EVERY
  dig-message — one-shot, request, response, and every streaming frame (OPEN / OPEN_ACK / DATA / CREDIT
  / CLOSE / CLOSE_ACK / RESET) — carries a sender signature. No unsigned or bad-signature message/frame
  is EVER accepted (fail-closed, section 5.6). The signature is carried INSIDE the seal (not
  relay-visible; only the recipient learns + verifies the sender). It signs SIG_DOMAIN || transcript
  (domain separation, section 5.1a), where transcript binds EVERYTHING (nothing malleable):
  version || message_type || flags || correlation_id || sender || recipient || sender_epoch || counter
  || timestamp_ms || expires_at || stream_frame || stream_seq || kem_enc || compression ||
  uncompressed_len || compressed_payload_hash. stream_frame/stream_seq are the section 3 stream fields
  (0 for non-stream); compressed_payload_hash is the SHA-256 of the on-the-wire compressed payload bytes;
  kem_enc is the seal KEM encapsulation (below). Binding kem_enc prevents KEM-reuse/replay across
  recipients; binding counter + timestamp_ms is the anti-replay commitment (section 5.6); binding
  expires_at makes the TTL sender-authenticated + un-extendable (section 5.6b); binding stream_frame +
  stream_seq prevents per-frame replay/reorder/cross-frame splice (section 5.3).
  - Transcript encoding (NORMATIVE, byte-deterministic — the cross-implementation contract). The signed
    bytes are `SIG_DOMAIN || transcript`, `SIG_DOMAIN = "DIGNET-MSG:dig-message/v1"` (ASCII, no NUL).
    `transcript` is the fixed-width, BIG-ENDIAN concatenation, in this exact order:
    `version:u8 ‖ message_type:u32 ‖ flags:u8 ‖ correlation_id:32B ‖ sender:32B ‖ recipient:32B ‖
    sender_epoch:u32 ‖ counter:u64 ‖ timestamp_ms:u64 ‖ expires_at:u64 ‖ stream_frame:u8 ‖
    stream_seq:u64 ‖ kem_enc:48B ‖ compression:u8 ‖ uncompressed_len:u32 ‖ compressed_payload_hash:32B`
    — total 235 transcript bytes plus the domain tag. `stream_frame`/`stream_seq` are 0 for a
    non-stream message; `compressed_payload_hash` is the SHA-256 of the on-wire compressed payload
    bytes. A second implementation MUST reproduce these bytes exactly for its signature to verify.
  - Seal composition (NORMATIVE). The DHKEM-over-G1 key schedule is HKDF-SHA256 with `salt = empty`,
    `ikm = Z` (the two concatenated 48-byte DH points, section 5.1 order), and
    `info = "dig-message/dhkem-g1/v1" || kem_enc || sender_pub || recipient_pub`, expanded to 44 bytes
    = the 32-byte ChaCha20Poly1305 key ‖ the 12-byte base nonce. `ciphertext = AEAD.Seal(key, nonce,
    aad = cleartext-header-bytes, pt = InnerMessage)` (section 5.2).
- SEAL = DHKEM over the BLS12-381 G1 prime-order subgroup + HKDF-SHA256 + ChaCha20Poly1305-AEAD, in AUTH
  mode. This instantiates the GENERIC, group-agnostic HPKE DHKEM (RFC 9180 section 4.1) over a valid
  prime-order DH group (G1, order r), exactly as ECIES/DHIES (SEC1, ISO 18033-2) is defined over any such
  group — a sound, established construction, NOT an invented primitive. The DH is scalar-mult on G1:
  dh(sk, pk) = sk * pk (a G1 point), serialized as the 48-byte compressed point.
  - AUTH mode = ephemeral + static-sender (the HPKE AuthEncap analog, chosen for FORWARD SECRECY — a
    long-lived stream or a later static-key compromise does not retroactively expose past traffic; the
    static-sender term still gives the "openable only by recipient priv + sender pub" property):
    - Sender: generate ephemeral (esk, epk=esk*G1); kem_enc = epk (48 bytes). Compute
      Z = dh(esk, recipient_pub) || dh(sender_static_sk, recipient_pub). shared_secret =
      HKDF-SHA256(salt=empty, ikm=Z, info="dig-message/dhkem-g1/v1" || kem_enc || sender_pub ||
      recipient_pub) -> the AEAD key + base nonce.
    - Recipient: Z2 = dh(recipient_sk, kem_enc) || dh(recipient_sk, sender_static_pub); same HKDF -> the
      same key. Opening therefore REQUIRES the recipient private key AND the correct sender public key; a
      wrong/absent sender pubkey yields a different key and AEAD-open FAILS.
  - Subgroup safety (HARD): before ANY DH, a receiver MUST validate every received G1 point (kem_enc and
    the resolved sender_pub) is a valid, non-identity point in the prime-order r-subgroup (blst in_g1 /
    subgroup check; reject the identity/infinity point and any small-order point). This blocks
    small-subgroup / invalid-curve key-recovery attacks. A point failing the check -> REJECT.

### 5.1a BLS signature domain separation vs chain spends (HARD — custody-adjacent)
The identity BLS key is Chia-native; a dig-message signature MUST be impossible to confuse with, or
replay as, a Chia spend signature (AGG_SIG_ME / AGG_SIG_UNSAFE) or vice-versa. Two layers, both REQUIRED:

1. Message domain tag. The signed message is SIG_DOMAIN || transcript, where
   SIG_DOMAIN = "DIGNET-MSG:dig-message/v1" (a fixed ASCII augmentation). An AGG_SIG_ME message is the
   condition message with coin_id || genesis_challenge appended and never carries SIG_DOMAIN, so a
   dig-message signature can never be a valid AGG_SIG_ME signature, and an AGG_SIG_ME signature (bound to
   a coin + genesis) never verifies against the SIG_DOMAIN-prefixed dig-message message.
2. Key separation (the LOAD-BEARING defense against AGG_SIG_UNSAFE). Because AGG_SIG_UNSAFE signs an
   attacker-chosen message with NO chain-appended suffix, a message domain tag ALONE is insufficient (an
   attacker can craft an AGG_SIG_UNSAFE condition whose message equals our signed bytes). The identity
   signing key (0x0010) therefore MUST NOT be a wallet coin-custody / spend key: it secures NO coins, so
   any confused-deputy signature authorizes nothing of value. Implementations MUST sign dig-messages ONLY
   via a dedicated dig-message helper — NEVER through any wallet spend-signing code path, and NEVER with a
   key that guards funds.

### 5.2 SealedPayload (Streamable)
{ kem_enc: [u8;48], ciphertext: Vec<u8> } where kem_enc is the ephemeral G1 encapsulation (section 5.1)
and ciphertext = AEAD.Seal(key=shared_secret, nonce=base_nonce, aad = cleartext-header-bytes,
pt = InnerMessage). Binding the cleartext header as AAD prevents an on-path party from altering routing
metadata. To resolve sender_pub the recipient reads the sender DID from the cleartext header (bound as
AAD, so un-tamperable) and resolves that DID BLS G1 identity key (slot 0x0010) via dig-identity at the
sender_epoch epoch, runs the subgroup check (section 5.1), then decapsulates + opens; an
unknown/unresolvable sender DID, a non-subgroup point, or a mismatched sender key -> open FAILS
(fail-closed).

InnerMessage (Streamable), FINAL field list = { message_type: u32, correlation_id: Bytes32,
compression: u8, uncompressed_len: u32, counter: u64, timestamp_ms: u64, expires_at: u64,
payload: Vec<u8>, sender_sig: [u8;96] } where payload is the COMPRESSED type-payload bytes (section 1.1),
compression is the algorithm id, uncompressed_len is the declared original length (the bomb-guard bound),
counter + timestamp_ms are the anti-replay fields (section 5.6), expires_at is the sender-controlled TTL
(section 5.6b), and sender_sig is the MANDATORY 96-byte BLS G2 signature (section 5.1) — every
InnerMessage carries it, none is optional. A receiver MUST, in order: (a) verify sender_sig (AugSchemeMPL)
against the resolved sender G1 key over SIG_DOMAIN || transcript — an absent, malformed, or non-verifying
signature is a REJECT (fail-closed); (b) check inner message_type/correlation_id equal the cleartext
header (anti type-confusion / anti splice); (c) apply the expiry check (section 5.6b) and DISCARD if
expired; (d) run the anti-replay check (section 5.6) on (sender, sender_epoch, counter, timestamp_ms) and
REJECT a replay/stale message; (e) reject if uncompressed_len > MAX_DECOMPRESSED_BYTES; then
(f) decompress payload per compression under the section 1.1 output bound and check the decoded length ==
uncompressed_len. Because every field lives inside the AEAD-authenticated + signed InnerMessage, none can
be tampered by a relay.

### 5.3 Streaming keys
The STREAM OPEN seal establishes a per-stream secret via an HKDF-Expand of the OPEN shared_secret
(section 5.1), exporter_context = "dig-message/stream/v1" || correlation_id || kem_enc. Binding kem_enc
(the fresh ephemeral G1 encapsulation per OPEN) makes the per-stream key unique per session even if a
correlation_id ever recurred, so a frame from a prior session can never be decrypted or injected into a
new one (cross-session replay defense). EVERY stream frame is BLS-signed inside its seal per section 5.1,
with the transcript binding stream_frame + stream_seq, so no frame can be replayed, reordered, injected,
or forged; the monotonic per-direction seq (section 3) is the replay index within a session. Subsequent
DATA chunks are AEAD-sealed (ChaCha20Poly1305) under keys derived from the per-stream secret with nonce =
seq, so per-chunk DH is avoided while confidentiality + ordering + replay-resistance hold. Each DATA
chunk is compressed (section 1.1) INDEPENDENTLY before its AEAD seal — one compression context per chunk,
never a shared running context (see the compress-then-encrypt boundary, section 5.5). The stream
compression algorithm id is fixed at OPEN (carried in the sealed OPEN InnerMessage); each DATA chunk
declares its own uncompressed_len for the per-chunk MAX_CHUNK_DECOMPRESSED_BYTES bomb guard
(default = MAX_CHUNK_BYTES). The stream expires_at is the OPEN frame expires_at and bounds the WHOLE
session: once now_ms > session.expires_at a receiver MUST discard further frames and RESET the stream
(section 5.6b). The base spec provides this per-stream secure channel; a higher layer (dig-chat #768) MAY
layer a Double Ratchet over its payload.

### 5.4 Public-broadcast exemption
Consensus broadcast (opcodes 200-219: blocks, transactions, attestations, checkpoints — addressed to ALL
peers) has no single recipient key and is NOT dig-message-sealed; it stays mTLS-authenticated + signed.
dig-message governs DIRECTED (1:1/group) messaging only.

- [KAT: seal/open round-trip with fixed keys (test nonces DERIVED from a hashed seed, never integer
  literals — CodeQL); a relay-sees-only-ciphertext test (no plaintext substring on the wire); a
  tampered-AAD / tampered-sig rejection; a wrong-recipient decrypt-fail; a wrong-sender-pubkey
  decrypt-fail; a NON-SUBGROUP / identity-point kem_enc -> REJECT; a COMPRESSED (id=1)
  compress->seal->open->decompress round-trip == original; a raw (id=0) round-trip; an
  unknown-compression-id-rejected; a decompression-bomb-rejected; the G1-DH round-trip agrees
  sender-side == recipient-side.]

### 5.5 Compress-then-encrypt threat boundary (CRIME/BREACH class, NORMATIVE)

Compressing before encrypting can, in the general TLS/HTTP setting, leak plaintext via ciphertext length
under an adaptive-chosen-plaintext attacker (CRIME/BREACH): the attacker repeatedly injects data into a
compression context that ALSO contains a stable secret, and reads the compressed length to guess the
secret byte-by-byte. That attack class does NOT apply to dig-message discrete sealed messages, and the
SPEC forbids the configurations where it would:

- Each message (and each stream chunk) is compressed in its OWN, fresh compression context, then sealed
  with a FRESH ephemeral KEM (or a fresh per-chunk AEAD nonce over a per-stream key). There is no
  long-lived compression context mixing a stable secret with attacker-varied inputs across many probes,
  and the length side channel is per-discrete-message, not a repeated oracle over one secret.
- FORBIDDEN (MUST NOT): compressing attacker-influenced data together WITH secret data in a single
  compression context, or streaming a stable secret repeatedly alongside attacker-chosen data in one
  running compression context. Every compression context MUST be single-message / single-chunk
  (section 5.3) — the boundary that keeps compress-before-seal provably safe here.
- Payloads that genuinely interleave a per-connection secret with attacker-chosen content in one buffer
  MUST set compression=0 (raw); they are outside the safe regime above.

### 5.6 Replay protection (mandatory, ALL messages — NORMATIVE)

Every non-broadcast dig-message is replay-protected. The seal gives confidentiality + AEAD integrity, the
BLS signature gives non-repudiable sender-auth, and this section adds FRESHNESS — three distinct,
all-required properties. The scheme (pinned):

- Anti-replay fields (signed + sealed, section 5.2): counter: u64 — a per-(sender -> recipient)
  strictly-monotonic message counter the SENDER persists per recipient (starts at 0, +1 each message,
  never reused/decreased); timestamp_ms: u64 — sender wall-clock Unix milliseconds. Both are inside the
  seal and covered by the signature, so neither is malleable by a relay.
- Freshness window: FRESHNESS_WINDOW_MS (default 300_000 = +/-5 min). A receiver REJECTS a message whose
  timestamp_ms is outside [now - FRESHNESS_WINDOW_MS, now + FRESHNESS_WINDOW_MS].
- Sliding-window dedup (bounded, DoS-safe). Per (sender DID, sender_epoch) the receiver keeps O(1) state:
  a highest_counter: u64 plus a fixed-width bitmap window REPLAY_WINDOW (default 1024 bits). counter >
  highest -> ACCEPT + advance + set bit; within window & bit UNSET -> ACCEPT + set bit (in-window
  reorder); bit already SET or counter <= highest - REPLAY_WINDOW -> REJECT. The bitmap is fixed-size, so
  a counter flood from one sender CANNOT grow per-sender state.
- Memory bound (nonce-flood / Sybil guard). The tracked-sender set is a bounded LRU capped at
  MAX_TRACKED_SENDERS (default 100_000), evicting senders idle beyond FRESHNESS_WINDOW_MS first; a new
  sender entry requires a valid BLS signature over a resolvable DID (section 5.1), so forging distinct
  senders to exhaust the LRU is cryptographically costly.
- Streaming: within a session the per-direction monotonic stream_seq (section 3) is the replay index; the
  per-stream key is bound to the fresh OPEN kem_enc (section 5.3) so no frame is replayable across
  sessions. The OPEN frame itself is covered by the counter/timestamp scheme.
- Fail-closed: a message failing signature OR the anti-replay check is DROPPED, never delivered.

### 5.6a Self-addressed messages (sender == recipient key; IPC — NORMATIVE, HARD)
The sender and recipient identity key MAY be the SAME (self-addressed: local IPC dig-app <-> dig-node on
a shared identity, a note-to-self, a loopback test). This is FIRST-CLASS and MUST round-trip identically
to a distinct-party message. No layer may assume sender != recipient:
- Seal: the G1 auth-DH is well-defined when sender_static == recipient. The static term is
  dh(recipient_sk, sender_static_pub) = sk*(sk*G1) = (sk^2)*G1 — a valid, non-identity G1 point for any
  sk != 0 (a real BLS key is never 0), so there is no divide-by-zero / degenerate / identity result and
  no self-rejection. The ephemeral term dh(esk, recipient_pub) is independent and always valid. Seal and
  open therefore succeed to self.
- Signature: the BLS sig signs + verifies a self-addressed transcript normally (sender==recipient in the
  transcript is just data).
- Replay: the per-(sender -> recipient) counter + dedup key is the ORDERED PAIR (sender, recipient); the
  pair (X, X) is a valid, independent counter stream — no assumption the two DIDs differ.
- Envelope: sender == recipient is a VALID envelope; a receiver MUST NOT reject it.
- [KAT: a self-addressed (sender key == recipient key) message round-trips — seal->open succeeds, BLS sig
  verifies, replay accepts-then-rejects-on-replay — byte-for-byte identical semantics to a distinct-party
  message.]

### 5.6b Message expiry / TTL (sender-controlled discard — NORMATIVE)
expires_at: u64 (Unix milliseconds) is a SENDER-controlled per-message time-to-live, inside the seal and
covered by the signature transcript (section 5.1) — so a relay/attacker can neither extend nor shorten it
without breaking the signature. It is DISTINCT from and INDEPENDENT of the anti-replay freshness window
(section 5.6): freshness is a fixed +/-5 min anti-replay bound on timestamp_ms; expires_at is a
per-message validity deadline the sender chooses (an offer valid 1h, a presence ping valid 30s).

- Semantics: a receiver DISCARDS (rejects with NO side-effect — not delivered, not counted, no error
  reply) any message where now_ms > expires_at.
- Sentinel: expires_at == 0 means NO explicit expiry (the section 5.6 freshness window still bounds a
  non-streaming message replay validity).
- Cap: a non-zero expires_at MUST NOT exceed timestamp_ms + MAX_MESSAGE_TTL_MS (MAX_MESSAGE_TTL_MS
  default 2_592_000_000 = 30 days); a message claiming a longer validity is REJECTED (never clamped —
  clamping would alter signed content). This stops a message claiming near-infinite validity.
- Both checks apply INDEPENDENTLY: an expired-but-in-freshness-window message is still DISCARDED (expiry
  wins), and a fresh-but-expired message is DISCARDED; a message must pass BOTH expiry AND anti-replay to
  be delivered.
- Streaming: the OPEN frame expires_at bounds the whole session; once now_ms > session.expires_at the
  receiver discards further frames and RESETs the stream (section 5.3).
- [KAT: within-expires accepted; past-expires DISCARDED (no processing/side-effect); a tampered
  expires_at -> sig-verify FAILS (confirms it is inside the seal + signed); expired-but-in-freshness-
  window -> DISCARDED; fresh-but-expired -> DISCARDED; expires_at > timestamp_ms + MAX_MESSAGE_TTL_MS ->
  REJECTED; expires_at == 0 -> no expiry applied.]

### 5.7 Composed, distinct guarantees + key-reuse safety (NORMATIVE)

A directed dig-message composes independent security properties on ONE BLS keypair; all required:

1. Seal — DHKEM-over-G1 AUTH mode (section 5.1): CONFIDENTIALITY + FORWARD SECRECY (ephemeral) + DENIABLE
   sender-auth bound to BOTH keys (opens only with recipient priv AND correct sender pub). The AEAD is
   symmetric/deniable, so it authenticates the sender TO THE RECIPIENT but is not transferable.
2. BLS (G2) signature (section 5.1/5.2): TRANSFERABLE, Chia-native NON-REPUDIATION — a third party can
   verify the sender signed. Kept alongside the deniable seal precisely because the seal alone is
   deniable.
3. Anti-replay (section 5.6) + expiry (section 5.6b): FRESHNESS + sender-controlled validity.

Key-reuse safety (same BLS scalar for G2-signing AND G1-DH). The two uses live in DIFFERENT groups (sign
hashes to G2 and outputs sk*H_G2(m); DH outputs sk*P for a G1 point P) and are further separated by
distinct KDF/augment domains — SIG_DOMAIN="DIGNET-MSG:dig-message/v1" for signatures vs
info="dig-message/dhkem-g1/v1"||... for the KEM HKDF — so neither use is an oracle for the other: a
signature never reveals sk*P for an attacker-chosen G1 P, and a DH never produces a G2 signature. This
mirrors established single-key sign+DH reuse arguments under domain separation and is documented as an
accepted residual (a derived encryption sub-scalar would be a defense-in-depth ALTERNATIVE, but the
ecosystem mandates ONE keypair; the group + domain separation is the mitigation). See the threat model.

Ordering: sender computes the BLS sig over SIG_DOMAIN||transcript (which binds the replay token + expiry +
header + compressed payload), places it in InnerMessage, then G1-auth-seals the whole. Receiver reverses:
subgroup-check + AuthDecap + AEAD-Open (needs sender pub) -> verify BLS sig -> expiry check -> anti-replay
check -> decompress.

## 6. Threat model (NORMATIVE summary)

| Threat | Mitigation |
|---|---|
| Curious/compromised relay reads content | DHKEM-over-G1 AUTH-mode seal bound to recipient + sender BLS G1 keys; opening needs the recipient private key AND the sender public key; relay sees only ciphertext + routing metadata (section 5.1) |
| On-path tampering of routing metadata | Cleartext header bound as AEAD AAD (section 5.2) |
| Sender spoofing / signature-stripping | MANDATORY BLS (0x0010) signature on EVERY message/frame over the full transcript, verified against the resolved DID; unsigned/bad-sig -> REJECT fail-closed (section 5.1/5.6) |
| Sender impersonation at the KEM / forged-origin ciphertext | G1 auth mode binds the ciphertext to the sender static G1 key; a party lacking the sender scalar cannot produce an envelope that opens under (recipient_sk, sender_pub) (section 5.1) |
| Confused deputy: dig-message sig replayed as a chain spend | Domain tag SIG_DOMAIN + the identity signing key secures NO coins (defeats AGG_SIG_UNSAFE); a dig-message sig authorizes no spend and never verifies as AGG_SIG_ME (section 5.1a) |
| BLS key reuse (sign G2 vs DH G1 on one scalar) | Different groups + distinct KDF/augment domains; neither use is an oracle for the other; accepted residual (section 5.7) |
| Small-subgroup / invalid-curve on the seal KEM | Mandatory G1 subgroup + non-identity check on kem_enc and the resolved sender_pub before any DH (section 5.1) |
| Deniability vs non-repudiation | The seal AEAD is deniable (recipient-only auth); the BLS sig adds transferable non-repudiation — both intentionally present (section 5.7) |
| Type-confusion / payload splicing | message_type + correlation_id re-bound inside the seal, checked == header (section 5.2) |
| Cross-recipient replay of a sealed message | Transcript binds recipient + kem_enc (section 5.1) |
| Stream chunk replay/reorder/injection | Monotonic seq = AEAD nonce; per-stream derived key (section 5.3) |
| Resource exhaustion (huge msg / unbounded stream) | MAX_ENVELOPE_BYTES / MAX_CHUNK_BYTES / credit window (section 1, 3) |
| Decompression bomb (small frame -> huge output OOM) | uncompressed_len declared + checked; output bounded to MAX_DECOMPRESSED_BYTES; abort on overrun/mismatch (section 1.1) |
| Message replay (resend a captured sealed message) | Signed+sealed per-sender monotonic counter + timestamp freshness window + bounded sliding-window dedup; duplicate/stale -> REJECT (section 5.6) |
| Stale / over-long-lived message | Sender-authenticated expires_at TTL: discard when now > expires_at; capped at MAX_MESSAGE_TTL_MS (section 5.6b) |
| Reflection / cross-session frame injection | Transcript binds recipient + kem_enc + stream_frame/seq; per-stream key bound to the fresh OPEN kem_enc; frame from another session/direction -> REJECT (section 5.3/5.6) |
| Anti-replay state exhaustion (nonce/Sybil flood) | Fixed per-sender bitmap window (no growth per counter) + LRU-capped sender table (MAX_TRACKED_SENDERS) + valid-DID-signature admission (section 5.6) |
| Compression side channel (CRIME/BREACH) | Per-message/per-chunk fresh compression + fresh seal context; no secret+attacker-data in one context; raw(id=0) for interleaved-secret payloads (section 5.5) |
| Unknown compression algorithm id | Clean reject (UNSUPPORTED_COMPRESSION) / drop, never panic or mis-decode (section 1.1) |
| Self-addressed (sender==recipient) degeneracy | G1 self-DH sk*(sk*G1) is a valid non-identity point; seal/sig/replay/envelope all handle it (section 5.6a) |
| Key rotation / stale key | sender_epoch (0x0013) disambiguates; receiver resolves the epoch key |
| Unknown/newer version or type | Clean reject/drop, never panic (section 2, 4) |
| Metadata leakage (who talks to whom) | Documented residual: envelope reveals sender/recipient DID + timing to the relay; out of base scope (a future sealed-sender/onion layer MAY reduce it) |

## 7. Conformance

An implementation conforms iff it (a) encodes/decodes every section 2/3 structure byte-identically to the
golden KATs; (b) seals/opens per section 5 (DHKEM-over-G1 auth mode) and passes the relay-ciphertext +
tamper + wrong-recipient + wrong-sender-pubkey + non-subgroup KATs; (c) drives the section 3 streaming
state machine incl. backpressure + half-close + cancel; (d) handles unknown version/type/compression-id
per section 1.1/2/4 without panic; (e) agrees byte-for-byte across the Rust and wasm/JS targets, INCLUDING
the zstd(id=1) compressed bytes for the pinned params (section 1.2) and the G1-DH/seal vectors;
(f) compresses before sealing per the section 1 pipeline and enforces the section 1.1 decompression-bomb
guard + the section 5.5 single-context compression boundary; (g) signs EVERY message/frame with the BLS
(0x0010) sender key (domain-separated per section 5.1a) and rejects any unsigned/bad-signature message
fail-closed; (h) enforces the section 5.6 anti-replay scheme (counter + freshness window + bounded
sliding-window dedup) and the section 5.6b expires_at TTL, passing their replay/stale/reorder/cross-session
/flood + within/past-expiry KATs; (i) uses ONE BLS keypair for both the G2 signature and the G1-DH seal
(no X25519/Ed25519) and round-trips the section 5.6a self-addressed (sender==recipient) case identically
to a distinct-party message. SPEC.md, docs.dig.net protocol page, and superproject SYSTEM.md MUST agree
(ecosystem section 4.2 layering).
