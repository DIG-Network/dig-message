# dig-message

Canonical **generic base message protocol** for the DIG Network: the ONE structured
envelope every peer-to-peer message rides — RPC calls, data/content requests, chat,
email, video signaling, presence, anything one peer sends another. Extensible per
message type (additive registry) and **streaming** (open → chunks → close, ordered,
backpressured, cancelable).

Stack: **dig-gossip** (transport) → **dig-message** (this crate: envelope + typing +
streaming + e2e seal) → **dig-identity** (identity) → dig-chat / dig-email /
dig-video-chat / RPC (message types that extend this base).

Security: mTLS at the transport **plus** payloads e2e-sealed to the recipient's
dig-identity encryption key (X25519, slot 0x0011) — a TLS-terminating relay sees only
ciphertext (CLAUDE.md §5.4). Canonical Chia types via `chia-wallet-sdk`.

Design + DAG: DIG-Network/dig_ecosystem#796. SPEC.md is normative (forthcoming).
