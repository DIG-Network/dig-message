# dig-message

Canonical **generic base message protocol** for the DIG Network: the ONE structured
envelope every peer-to-peer message rides — RPC calls, data/content requests, chat,
email, video signaling, presence, anything one peer sends another. Extensible per
message type (additive registry) and **streaming** (open → chunks → close, ordered,
backpressured, cancelable).

Stack: **dig-gossip** (transport) → **dig-message** (this crate: envelope + typing +
streaming + e2e seal) → **dig-identity** (identity) → dig-chat / dig-email /
dig-video-chat / RPC (message types that extend this base).

Security: mTLS at the transport **plus** payloads e2e-sealed to the recipient using the
ONE Chia BLS12-381 identity key (dig-identity slot 0x0010) — its G2 signature
authenticates the sender and a DHKEM over its G1 group seals the payload (no X25519, no
Ed25519), so a TLS-terminating relay sees only ciphertext (CLAUDE.md §5.4). Canonical
Chia types via `chia-protocol` / `chia-wallet-sdk`.

Wire: a compact, byte-deterministic Chia-Streamable binary format (never JSON), payload
compressed (raw or zstd) BEFORE the seal, length-framed and size-bounded. `SPEC.md` is
the normative contract.

Status — **WU1 + WU3 shipped** (this crate): the crypto-free foundation — envelope +
`InnerMessage` structs, framing + size bounds, the compression codec, the KAT harness,
and the extensible message-type registry (`MessageBand` id classification, the
`MessageKind` seam, and the additive `MessageRegistry` with the unknown-type forward-
compat rule). The seal + BLS sender-signature (WU2), streaming state machine (WU4), and
wasm/JS bindings (WU5) follow; the fields they populate are already final on the wire.

Design + DAG: DIG-Network/dig_ecosystem#796.
