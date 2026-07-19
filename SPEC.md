# dig-message — SPECIFICATION

Normative specification of the DIG Network generic base message protocol: the ONE structured, typed,
streamable, e2e-sealed envelope every DIRECTED (1:1 / group) peer-to-peer message rides. The
authoritative contract an independent reimplementation is built against. Key words per RFC 2119.

Status: skeleton (design frozen by DIG-Network/dig_ecosystem#796 / #811, amended 2026-07-19 to a
COMPRESSED BINARY format — compress-before-seal, additive compression-algo negotiation, decompression-
bomb guard — to a UNIVERSALLY SIGNED + REPLAY-PROTECTED format — mandatory Ed25519 sender-signature
inside the seal on EVERY message/frame + a bounded sliding-window anti-replay scheme — and to an
HPKE AUTH-MODE seal — the envelope is openable ONLY by the recipient private key + the sender public
key (bound to both keypairs at the KEM); byte-level KAT
vectors are filled during WU1-WU5 implementation, marked [KAT: ...] below). The design decisions herein
are final.

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

## 1. Encoding, framing & compression (NORMATIVE)

- Compact BINARY format. dig-message is a compact binary wire format, NOT a text/JSON format. The
  envelope and every sub-structure are Chia Streamable (canonical, byte-deterministic, length-prefixed
  for variable regions) so Rust, wasm, and JS agree byte-for-byte (reuse chia-protocol /
  chia-wallet-sdk Streamable; never hand-roll framing, never emit JSON/text on the wire).
- Payload pipeline (NORMATIVE ordering, security-critical): serialize the type payload (Streamable
  bytes) -> COMPRESS (section 1.1) -> e2e-SEAL (HPKE, section 5). Compression MUST happen BEFORE the
  seal: HPKE ciphertext is high-entropy and incompressible, so compressing after the seal is useless;
  compressing the plaintext first is the only placement that gains size. The receiver reverses it:
  open seal -> bomb-guard check -> decompress -> decode payload.
- Length-framed + size-bounded. The outer DigMessage is already length-framed by dig-protocol;
  dig-message re-declares a hard MAX_ENVELOPE_BYTES cap (default 16 MiB, measured on the on-wire
  compressed+sealed frame) and a MAX_DECOMPRESSED_BYTES cap (default 64 MiB per message; stream chunks
  capped separately, section 3). A receiver MUST reject an over-cap or truncated envelope before
  decoding, and MUST enforce MAX_DECOMPRESSED_BYTES BEFORE and DURING decompression (section 1.1
  decompression-bomb guard).
- Canonical types. DID identifiers are Bytes32 (identity singleton launcher_id) via
  chia-protocol/chia-wallet-sdk. Keys are the raw 32-byte X25519 (0x0011) / Ed25519 (0x0010) forms.

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
- Signed frames: EVERY stream frame is Ed25519-signed inside its seal (section 5.1) with the frame type
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

## 5. Security — e2e seal + universal sender signature + replay protection (HARD, ecosystem section 5.4)

mTLS is assumed at the dig-gossip transport. The dig-message sealed region is ADDITIONALLY sealed to the
recipient identity encryption key so any TLS-terminating relay/forwarder sees only ciphertext.

### 5.1 Cipher suite (vetted; NEVER invented)
- HPKE (RFC 9180) in AUTH mode (mode_auth, RFC 9180 section 5.1.1), ciphersuite: DHKEM(X25519,
  HKDF-SHA256) [auth variant] + HKDF-SHA256 + ChaCha20Poly1305. The sender seals with
  SetupAuthS(pkR, skS) using the recipient's X25519 public key (recipient DID slot 0x0011, resolved via
  dig-identity) AND the SENDER's OWN static X25519 private key (sender DID slot 0x0011). The recipient
  opens with SetupAuthR(enc, skR, pkS) using their X25519 private (0x0011) AND the sender's X25519
  PUBLIC key. The envelope is therefore cryptographically bound to BOTH keypairs: opening REQUIRES the
  recipient private key AND the correct sender public key — no third party can open it, and an open with
  a wrong/absent sender pubkey FAILS. mode_auth is NOT mode_base: base (anonymous-sender) HPKE is
  FORBIDDEN for directed dig-messages (all directed messages use auth mode; the only unsealed traffic is
  the section 5.4 public-broadcast exemption).
- Sender authentication = Ed25519 (slot 0x0010) signature, MANDATORY and UNIVERSAL: EVERY dig-message
  — one-shot, request, response, and every streaming frame (OPEN / OPEN_ACK / DATA / CREDIT / CLOSE /
  CLOSE_ACK / RESET) — carries a sender signature. No unsigned or bad-signature message/frame is EVER
  accepted (fail-closed, section 5.6). The signature is carried INSIDE the seal (so it is not
  relay-visible and is bound to the encryption; only the recipient learns + verifies the sender). It
  covers a domain-separated transcript that binds EVERYTHING (nothing malleable):
  "dig-message/v1" || version || message_type || flags || correlation_id || sender || recipient ||
  sender_epoch || counter || timestamp_ms || stream_frame || stream_seq || hpke_enc || compression ||
  uncompressed_len || compressed_payload_hash — where stream_frame/stream_seq are the section 3 stream
  fields (0 for non-stream messages) and compressed_payload_hash is the hash of the on-the-wire
  compressed payload bytes. Binding hpke_enc (the HPKE encapsulated key) prevents KEM-reuse/replay across
  recipients; binding counter + timestamp_ms is the anti-replay commitment (section 5.6); binding
  stream_frame + stream_seq prevents per-frame replay/reorder/cross-frame splice (section 5.3). The Ed25519 signature is
  KEPT ALONGSIDE HPKE auth mode — the two are DISTINCT, both required (section 5.7): HPKE auth mode gives
  DENIABLE sender-authentication + KEM-level confidentiality binding to both keypairs; the Ed25519
  signature gives TRANSFERABLE NON-REPUDIATION (a third party can verify the sender signed). The sig is
  computed over the transcript above (plaintext + replay token + header), then the whole InnerMessage is
  HPKE-auth-sealed.

### 5.2 SealedPayload (Streamable)
{ hpke_enc: [u8;32], ciphertext: Vec<u8> } where (enc=hpke_enc, ctx) = SetupAuthS(pkR=recipient_0x0011,
skS=sender_0x0011_priv) and ciphertext = ctx.Seal(aad = cleartext-header-bytes, pt = InnerMessage). The
recipient computes ctx = SetupAuthR(hpke_enc, skR=recipient_0x0011_priv, pkS=sender_0x0011_pub) and
ctx.Open — so BOTH the recipient private key and the sender public key are required to open (section 5.1
auth mode). To resolve pkS the recipient reads the `sender` DID from the cleartext header (which is bound
as HPKE AAD, so it cannot be altered on-path) and resolves that DID's 0x0011 X25519 public key via
dig-identity (at the `sender_epoch` key epoch) BEFORE opening; an unknown/unresolvable sender DID or a
mismatched sender key -> open FAILS (fail-closed). Binding the cleartext header as AAD prevents an
on-path party from altering routing metadata. InnerMessage (Streamable) = { message_type: u32, correlation_id: Bytes32,
compression: u8, uncompressed_len: u32, counter: u64, timestamp_ms: u64, payload: Vec<u8>,
sender_sig: [u8;64] } where `payload` is the COMPRESSED type-payload bytes (section 1.1), `compression`
is the algorithm id, `uncompressed_len` is the declared original length (the bomb-guard bound),
`counter` + `timestamp_ms` are the anti-replay fields (section 5.6), and `sender_sig` is the MANDATORY
Ed25519 signature (section 5.1) — every InnerMessage carries it, none is optional. A receiver MUST, in
order: (a) verify sender_sig against the resolved sender 0x0010 key — an absent, malformed, or
non-verifying signature is a REJECT, never accepted (fail-closed); (b) check inner
message_type/correlation_id equal the cleartext header (anti type-confusion / anti splice);
(c) run the anti-replay check (section 5.6) on (sender, sender_epoch, counter, timestamp_ms) and REJECT
a replay/stale message; (d) reject if uncompressed_len > MAX_DECOMPRESSED_BYTES; then (e) decompress
`payload` per `compression` under the section 1.1 output bound and check the decoded length ==
uncompressed_len. Because every field lives inside the AEAD-authenticated + signed InnerMessage, none can
be tampered by a relay. The sender_sig transcript (section 5.1) covers the compressed payload hash + the
anti-replay fields + the envelope-authenticated header, so the signature commits to exactly what is
sealed AND to its freshness.

### 5.3 Streaming keys
The STREAM OPEN seal establishes a per-stream secret (HPKE export, RFC 9180 section 5.3, exporter_context
= "dig-message/stream/v1" || correlation_id || hpke_enc), where the OPEN HPKE context is the auth-mode
context (SetupAuthS/SetupAuthR, section 5.1) so the exported per-stream secret is ALSO bound to both the
sender and recipient keypairs. Binding hpke_enc (fresh per OPEN) makes the per-stream key unique per
session even if a correlation_id ever recurred, so a frame from a prior
session can never be decrypted or injected into a new one (cross-session replay defense). EVERY stream
frame (OPEN/OPEN_ACK/DATA/CREDIT/CLOSE/CLOSE_ACK/RESET) is Ed25519-signed inside its seal per section 5.1,
with the transcript binding stream_frame + stream_seq, so no frame can be replayed, reordered, injected,
or forged; the monotonic per-direction seq (section 3) is the replay index within a session. Subsequent DATA chunks are AEAD-sealed (ChaCha20Poly1305)
under keys derived from that secret with nonce = seq (the monotonic section 3 counter), so per-chunk HPKE
is avoided while confidentiality + ordering + replay-resistance hold. Each DATA chunk is compressed
(section 1.1) INDEPENDENTLY before its AEAD seal — one compression context per chunk, never a shared
running context across chunks (see the compress-then-encrypt boundary, section 5.5). The stream's
compression algorithm id is fixed at OPEN (carried in the sealed OPEN InnerMessage); each DATA chunk
declares its own uncompressed_len for the per-chunk MAX_CHUNK_DECOMPRESSED_BYTES bomb guard
(default = MAX_CHUNK_BYTES). The base spec provides this per-stream secure channel; a higher layer
(dig-chat #768) MAY layer a Double Ratchet over its payload.

### 5.4 Public-broadcast exemption
Consensus broadcast (opcodes 200-219: blocks, transactions, attestations, checkpoints — addressed to ALL
peers) has no single recipient key and is NOT dig-message-sealed; it stays mTLS-authenticated + signed.
dig-message governs DIRECTED (1:1/group) messaging only.

### 5.5 Compress-then-encrypt threat boundary (CRIME/BREACH class, NORMATIVE)

Compressing before encrypting can, in the general TLS/HTTP setting, leak plaintext via ciphertext length
under an adaptive-chosen-plaintext attacker (CRIME/BREACH): the attacker repeatedly injects data into a
compression context that ALSO contains a stable secret, and reads the compressed length to guess the
secret byte-by-byte. That attack class does NOT apply to dig-message discrete sealed messages, and the
SPEC forbids the configurations where it would:

- Each message (and each stream chunk) is compressed in its OWN, fresh compression context, then sealed
  with a FRESH per-message HPKE context (or a fresh per-chunk AEAD nonce over a per-stream key). There is
  no long-lived compression context that mixes a stable secret with attacker-varied inputs across many
  probes, and the length side channel is per-discrete-message, not a repeated oracle over one secret.
- FORBIDDEN (MUST NOT): compressing attacker-influenced data together WITH secret data in a single
  compression context, or streaming a stable secret repeatedly alongside attacker-chosen data in one
  running compression context. An implementation MUST keep every compression context single-message /
  single-chunk (section 5.3) — this is the boundary that keeps compress-before-seal provably safe here.
- Payloads that genuinely interleave a per-connection secret with attacker-chosen content in one buffer
  MUST set compression=0 (raw); they are outside the safe regime above.

- [KAT: seal/open round-trip with fixed keys (test nonces DERIVED from a hashed seed, never integer
  literals — CodeQL); a relay-sees-only-ciphertext test asserting no plaintext substring in the on-wire
  envelope; a tampered-AAD/tampered-sig rejection vector; a wrong-recipient decrypt-fail vector;
  a COMPRESSED (id=1) compress->seal->open->decompress round-trip == original; a raw (id=0) round-trip;
  an unknown-compression-id-rejected vector; a decompression-bomb-rejected vector (declared/actual
  decompressed size > MAX_DECOMPRESSED_BYTES -> clean reject, no OOM); an HPKE-AUTH open SUCCEEDS with
  (recipient priv 0x0011 + correct sender pub 0x0011); an open with a WRONG sender public key -> FAIL; an
  open with the wrong recipient key -> FAIL.]

### 5.6 Replay protection (mandatory, ALL messages — NORMATIVE)

Every non-broadcast dig-message is replay-protected. HPKE gives confidentiality + AEAD integrity, the
Ed25519 signature gives non-repudiable sender-auth, and this section adds FRESHNESS — three distinct,
all-required properties. The scheme (pinned):

- Anti-replay fields (signed + sealed, section 5.2): `counter: u64` — a per-(sender -> recipient)
  strictly-monotonic message counter the SENDER persists per recipient (starts at 0 for the first
  message to that recipient, +1 each message, never reused, never decreases); `timestamp_ms: u64` —
  sender wall-clock Unix milliseconds at send. Both are inside the seal and covered by the signature, so
  neither is malleable by a relay.
- Freshness window: FRESHNESS_WINDOW_MS (default 300_000 = +/-5 min). A receiver REJECTS a message whose
  timestamp_ms is outside [now - FRESHNESS_WINDOW_MS, now + FRESHNESS_WINDOW_MS] (bounds clock skew and
  caps how long replay state must be retained).
- Sliding-window dedup (bounded, DoS-safe). Per (sender DID, sender_epoch) the receiver keeps O(1) state:
  a `highest_counter: u64` plus a fixed-width bitmap window REPLAY_WINDOW (default 1024 bits) covering
  [highest_counter - REPLAY_WINDOW + 1 .. highest_counter]. On receipt:
  - counter > highest_counter -> ACCEPT, advance the window, set the new bit (in-order / new).
  - highest_counter - REPLAY_WINDOW < counter <= highest_counter and its bit is UNSET -> ACCEPT, set the
    bit (accepts in-window reordering).
  - bit already SET, or counter <= highest_counter - REPLAY_WINDOW (too old) -> REJECT (duplicate/stale).
  The bitmap is fixed-size, so a flood of distinct counters from one sender CANNOT grow per-sender state.
- Memory bound (nonce-flood / Sybil DoS guard). The set of tracked senders is a bounded LRU capped at
  MAX_TRACKED_SENDERS (default 100_000), evicting senders idle beyond FRESHNESS_WINDOW_MS first; a sender
  whose state was evicted for staleness is re-admitted only by a fresh in-window message. Each new sender
  entry requires a valid Ed25519 signature over a resolvable DID (section 5.1), so forging distinct
  senders to exhaust the LRU is cryptographically costly, and the per-sender cost is a fixed bitmap. A
  flood of distinct nonces/counters therefore cannot exhaust memory.
- Streaming: within a session the per-direction monotonic `stream_seq` (section 3) is the replay index —
  a receiver rejects a duplicate/old/gap seq; the per-stream key is bound to the fresh OPEN hpke_enc
  (section 5.3) so no frame is replayable across sessions. The OPEN frame itself is covered by the
  counter/timestamp scheme above.
- Fail-closed: a message failing signature (section 5.1) OR the anti-replay check is DROPPED and never
  delivered to the type handler.

- [KAT: valid signed message verifies + accepts; a bad-signature vector -> REJECT; an absent/zeroed
  signature -> REJECT; a byte-identical replay of an accepted message -> REJECT (dedup bit set); a stale
  message (timestamp outside window / counter below the window) -> REJECT; an in-window reordered message
  -> ACCEPT; a cross-session streaming-frame replay (frame from a prior OPEN injected into a new session)
  -> REJECT; a nonce/counter-flood does NOT grow per-sender state beyond the fixed bitmap and does NOT
  grow the sender table beyond MAX_TRACKED_SENDERS.]

### 5.7 Three composed, distinct guarantees (NORMATIVE)

A directed dig-message composes THREE independent security properties; all are required and none
substitutes for another:

1. HPKE AUTH mode (section 5.1) — CONFIDENTIALITY + DENIABLE sender-auth bound at the KEM to BOTH
   keypairs: the envelope opens only with the recipient private key AND the correct sender public key.
   This is symmetric/deniable (either party could have produced the AEAD tag), so it authenticates the
   sender TO THE RECIPIENT but is not transferable to a third party.
2. Ed25519 (0x0010) inner signature (section 5.1/5.2) — TRANSFERABLE NON-REPUDIATION: a third party
   (given the transcript) can verify the sender signed. Kept alongside auth mode precisely because auth
   mode alone is deniable.
3. Anti-replay (section 5.6) — FRESHNESS: the signed+sealed counter + timestamp + sliding-window dedup
   reject replays/stale messages, which neither confidentiality nor a signature alone prevents.

Ordering: the sender computes the Ed25519 signature over the transcript (which already binds the replay
token + header + compressed payload), places it in InnerMessage, then HPKE-auth-seals the whole. The
receiver reverses it: SetupAuthR + Open (needs sender pubkey) -> verify Ed25519 sig -> anti-replay check
-> decompress.

## 6. Threat model (NORMATIVE summary)

| Threat | Mitigation |
|---|---|
| Curious/compromised relay reads content | HPKE AUTH-mode seal bound to recipient 0x0011 + sender 0x0011; opening needs the recipient private key AND the sender public key; relay sees only ciphertext + routing metadata (section 5.1) |
| On-path tampering of routing metadata | Cleartext header bound as HPKE AAD (section 5.2) |
| Sender spoofing / signature-stripping | MANDATORY Ed25519 (0x0010) signature on EVERY message/frame over the full transcript, verified against the resolved DID; unsigned/bad-sig -> REJECT fail-closed (section 5.1/5.6) |
| Sender impersonation at the KEM / forged-origin ciphertext | HPKE auth mode binds the ciphertext to the sender's 0x0011 static key; a party lacking skS cannot produce an envelope that opens under (skR, pkS) (section 5.1) |
| Deniability vs non-repudiation | Auth mode is deniable (recipient-only auth); the inner Ed25519 sig adds transferable non-repudiation — both intentionally present (section 5.7) |
| Type-confusion / payload splicing | message_type + correlation_id re-bound inside the seal, checked == header (section 5.2) |
| Cross-recipient replay of a sealed message | Transcript binds recipient + hpke_enc (section 5.1) |
| Stream chunk replay/reorder/injection | Monotonic seq = AEAD nonce; per-stream derived key (section 5.3) |
| Resource exhaustion (huge msg / unbounded stream) | MAX_ENVELOPE_BYTES / MAX_CHUNK_BYTES / credit window (section 1, 3) |
| Decompression bomb (small frame -> huge output OOM) | uncompressed_len declared + checked; output bounded to MAX_DECOMPRESSED_BYTES; abort on overrun/mismatch (section 1.1) |
| Message replay (resend a captured sealed message) | Signed+sealed per-sender monotonic counter + timestamp freshness window + bounded sliding-window dedup; duplicate/stale -> REJECT (section 5.6) |
| Reflection / cross-session frame injection | Transcript binds recipient + hpke_enc + stream_frame/seq; per-stream key bound to the fresh OPEN hpke_enc; frame from another session/direction -> REJECT (section 5.3/5.6) |
| Anti-replay state exhaustion (nonce/Sybil flood) | Fixed per-sender bitmap window (no growth per counter) + LRU-capped sender table (MAX_TRACKED_SENDERS) + valid-DID-signature admission (section 5.6) |
| Compression side channel (CRIME/BREACH) | Per-message/per-chunk fresh compression + fresh seal context; no secret+attacker-data in one context; raw(id=0) for interleaved-secret payloads (section 5.5) |
| Unknown compression algorithm id | Clean reject (UNSUPPORTED_COMPRESSION) / drop, never panic or mis-decode (section 1.1) |
| Key rotation / stale key | sender_epoch (0x0013) disambiguates; receiver resolves the epoch key |
| Unknown/newer version or type | Clean reject/drop, never panic (section 2, 4) |
| Metadata leakage (who talks to whom) | Documented residual: envelope reveals sender/recipient DID + timing to the relay; out of base scope (a future sealed-sender/onion layer MAY reduce it) |

## 7. Conformance

An implementation conforms iff it (a) encodes/decodes every section 2/3 structure byte-identically to the
golden KATs; (b) seals/opens per section 5 and passes the relay-ciphertext + tamper + wrong-recipient
KATs; (c) drives the section 3 streaming state machine incl. backpressure + half-close + cancel;
(d) handles unknown version/type/compression-id per section 1.1/2/4 without panic; (e) agrees
byte-for-byte across the Rust and wasm/JS targets, INCLUDING the zstd(id=1) compressed bytes for the
pinned params (section 1.2); (f) compresses before sealing per the section 1 pipeline and enforces the
section 1.1 decompression-bomb guard + the section 5.5 single-context compression boundary; (g) signs
EVERY message/frame with the Ed25519 sender key and rejects any unsigned/bad-signature message
fail-closed (section 5.1); (h) enforces the section 5.6 anti-replay scheme (counter + freshness window +
bounded sliding-window dedup) and passes its replay/stale/reorder/cross-session/flood KATs; (i) seals
directed messages with HPKE AUTH mode (SetupAuthS/SetupAuthR) so an open requires the recipient private
key AND the correct sender public key, rejects a wrong-sender-key open, and NEVER uses base mode for a
directed message (section 5.1). SPEC.md, docs.dig.net protocol page, and superproject SYSTEM.md MUST agree
(ecosystem section 4.2 layering).
