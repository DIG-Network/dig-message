//! WU4: the streaming state machine (SPEC §3) — the ordered, backpressured, cancelable, bidirectionally
//! half-closable channel every long-lived directed exchange rides.
//!
//! ## What this module owns
//! - [`StreamSession`] — the pure, crypto-free per-stream state machine: the OPEN → OPEN_ACK → DATA →
//!   CLOSE lifecycle, strictly-monotonic per-direction `seq` (gap / reorder / replay → REJECT), credit
//!   backpressure, and independent per-direction half-close + RESET (SPEC §3). Pure so every transition
//!   is unit-testable without touching crypto.
//! - [`StreamEndpoint`] — the per-peer registry that wraps the seal around the state machine: it seals
//!   EVERY frame with a FRESH ephemeral via [`seal_message`] (SPEC §5.1 forward secrecy — never a fixed
//!   or session-wide ephemeral, so ChaCha20Poly1305 nonce-reuse is impossible), opens + fully verifies
//!   every inbound frame via [`open_message`], enforces the [`MAX_CONCURRENT_STREAMS`] per-peer cap
//!   (SPEC §3 DoS gate), and RESETs a stream on any failed verify / protocol violation (defense-in-depth
//!   gate item — a garbage or forged frame never poisons a stream silently).
//!
//! ## Per-frame sealing (CUSTODY-critical)
//! Each frame is an independent WU2 sealed envelope: BLS-G2 signed over the transcript (which binds the
//! `stream_frame` + `stream_seq`, SPEC §5.1) and G1-DHKEM auth-sealed under its OWN fresh ephemeral.
//! Cross-session frame replay is rejected two ways: the persistent [`ReplayGuard`] (per-sender monotonic
//! counter + freshness window) drops a captured frame re-injected later, and a frame's `correlation_id`
//! must match a live session — a frame from another stream/session addresses a different `correlation_id`
//! and finds no session.
//!
//! ## Transport ordering (the layer BELOW)
//! The reliable mTLS-WS transport (dig-gossip) delivers frames in order and its bounded
//! `StreamReassembler` (256 chunks / 4 MiB per stream) restores order across any out-of-order transport
//! delivery. That reassembler is a SINGLE-stream transport primitive that sits UNDER dig-message and is
//! wired at the dig-node integration layer (WU6); dig-message does not depend on the heavy dig-gossip
//! crate (it must stay wasm-compilable + crates.io-publishable). This state machine is the layer ABOVE:
//! it enforces the `seq` contract end-to-end and bounds the number of CONCURRENT streams — exactly the
//! responsibility the reassembler's own docs assign to "the streaming state machine (WU4)".

use std::collections::HashMap;

use chia_bls::SecretKey;
use chia_protocol::Bytes32;

use crate::constants::MAX_CONCURRENT_STREAMS;
use crate::envelope::{DigMessageEnvelope, InteractionShape, StreamFrame, StreamHeader};
use crate::error::{MessageError, Result};
use crate::replay::ReplayGuard;
use crate::seal::{open_message, seal_message, SealParams};

/// Which side opened the stream — the initiator sends OPEN and awaits OPEN_ACK; the responder receives
/// OPEN and replies OPEN_ACK (SPEC §3 handshake).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

/// The OPEN/OPEN_ACK handshake position (SPEC §3): `Opening` until the ACK completes, then `Established`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Handshake {
    Opening,
    Established,
}

/// The observable lifecycle position of a stream (SPEC §3), derived from the half-close + reset flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// OPEN sent/received, awaiting the OPEN_ACK that completes the handshake.
    Opening,
    /// Both directions open — DATA / CREDIT may flow.
    Open,
    /// We sent CLOSE; the peer may still send until it also CLOSEs (SPEC §3 half-close).
    HalfClosedLocal,
    /// The peer sent CLOSE; we may still send until we also CLOSE (SPEC §3 half-close).
    HalfClosedRemote,
    /// Both directions closed, or the stream was RESET (SPEC §3).
    Closed,
}

/// The result of a pure state-machine transition on an inbound frame — the crypto-free classification
/// [`StreamEndpoint::accept`] pairs with the opened payload to build the public [`StreamEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Accepted {
    /// OPEN_ACK completed the handshake (initiator side).
    Established,
    /// An in-order DATA chunk (its bytes travel separately, from the opened seal).
    Data,
    /// A CREDIT grant of `n` additional DATA frames for our sending direction.
    Credit(u64),
    /// The peer half-closed its sending direction.
    RemoteClosed,
    /// The peer acknowledged our CLOSE.
    CloseAcked,
    /// The peer RESET the stream (immediate abort).
    Reset,
}

/// A verified, in-order stream event delivered to the caller by [`StreamEndpoint::accept`] (SPEC §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    /// A new inbound stream OPENed by the peer — the caller should reply with
    /// [`StreamEndpoint::open_ack`] to complete the handshake.
    Opened,
    /// Our OPEN was acknowledged; the stream is now fully open (initiator side).
    Established,
    /// An in-order, verified, decompressed data chunk.
    Data(Vec<u8>),
    /// The peer granted `n` more DATA credits for our sending direction (backpressure relief).
    CreditGranted(u64),
    /// The peer half-closed its sending direction; it will send no more DATA (SPEC §3 half-close).
    RemoteClosed,
    /// The peer acknowledged our CLOSE.
    CloseAcked,
    /// The peer RESET the stream — it is aborted (SPEC §3 cancel).
    PeerReset,
}

/// The outcome of [`StreamEndpoint::accept`] (SPEC §3, RESET-on-failed-verify gate item #1162).
///
/// The security purpose of "RESET-on-failed-verify" is to NEVER deliver corrupt data and NEVER let a bad
/// frame poison a stream — **dropping the frame fully satisfies that**. Emitting a *signed* RESET is a
/// separate, RESTRICTED action, because a RESET is itself a real non-replayable frame: broadcasting one
/// in response to unauthenticated or duplicate input lets the untrusted relay (§5.4) weaponize it —
/// a self-sustaining RESET reflection storm (inject-only), or tearing down a healthy stream by replaying
/// one frame. So a RESET must NEVER beget a RESET. The three outcomes:
#[derive(Debug, PartialEq, Eq)]
pub enum StreamAccept {
    /// A verified, in-order event.
    Event(StreamEvent),
    /// The frame was rejected and SILENTLY DROPPED — nothing is transmitted. This covers every
    /// unauthenticated or non-actionable input: a failed open/verify (bad seal / bad signature /
    /// replay / expiry / unresolvable sender), a non-stream or unknown-kind frame, an inbound RESET,
    /// and any frame addressing an unknown stream. A live session, if any, is left UNTOUCHED (a garbage
    /// or replayed frame never tears down a healthy stream). `cause` records why.
    Dropped {
        /// Why the frame was dropped.
        cause: MessageError,
    },
    /// The state machine rejected an AUTHENTICATED frame on a KNOWN stream (an ordering/credit/half-close
    /// violation by the verified peer, or the concurrent-stream cap) — send this RESET and consider the
    /// stream aborted. This is the ONLY transmitting rejection, and it is safe: the frame was
    /// cryptographically authenticated, so it cannot be forged or replayed by the relay, and the peer
    /// receiving the RESET for its own live/opening stream tears it down without re-RESETting (no storm).
    Reset {
        /// The sealed RESET frame to transmit to the peer (boxed — it dwarfs the `Event` variant).
        frame: Box<DigMessageEnvelope>,
        /// Why the frame was rejected.
        cause: MessageError,
    },
}

/// The pure, crypto-free per-stream state machine (SPEC §3). One instance tracks BOTH directions of one
/// stream: our sending half (`send_*`) and the peer's sending half we receive (`recv_*`), with
/// independent half-close so either side can finish sending while the other continues.
#[derive(Debug)]
pub struct StreamSession {
    role: Role,
    handshake: Handshake,
    /// The next `seq` we will stamp on an outbound DATA frame (strictly monotonic from 0).
    send_seq: u64,
    /// The next inbound DATA `seq` we require (strictly monotonic from 0; any other value is a
    /// gap / reorder / replay → REJECT, SPEC §3).
    recv_seq: u64,
    /// DATA frames we may still send before needing more credit (granted by the peer, SPEC §3).
    send_credit: u64,
    /// DATA frames we still permit the peer to send before it needs more credit (the window WE granted).
    recv_window_remaining: u64,
    /// We sent CLOSE — our sending direction is done.
    local_closed: bool,
    /// The peer sent CLOSE — its sending direction is done.
    remote_closed: bool,
    /// The stream was RESET (either side) — a hard, immediate abort.
    reset: bool,
}

impl StreamSession {
    /// A fresh initiator session: we sent OPEN advertising `recv_window` credits for the peer→us
    /// direction, and await OPEN_ACK before sending DATA (SPEC §3).
    fn initiator(recv_window: u32) -> Self {
        Self {
            role: Role::Initiator,
            handshake: Handshake::Opening,
            send_seq: 0,
            recv_seq: 0,
            send_credit: 0,
            recv_window_remaining: u64::from(recv_window),
            local_closed: false,
            remote_closed: false,
            reset: false,
        }
    }

    /// A fresh responder session created from a received OPEN carrying `granted_credit` DATA credits for
    /// our sending direction; the handshake completes when we send OPEN_ACK (SPEC §3).
    fn responder(granted_credit: u32) -> Self {
        Self {
            role: Role::Responder,
            handshake: Handshake::Opening,
            send_seq: 0,
            recv_seq: 0,
            send_credit: u64::from(granted_credit),
            recv_window_remaining: 0,
            local_closed: false,
            remote_closed: false,
            reset: false,
        }
    }

    /// The observable [`StreamState`] (SPEC §3), derived from the handshake + half-close + reset flags.
    #[must_use]
    pub fn state(&self) -> StreamState {
        if self.reset || (self.local_closed && self.remote_closed) {
            return StreamState::Closed;
        }
        if self.handshake == Handshake::Opening {
            return StreamState::Opening;
        }
        match (self.local_closed, self.remote_closed) {
            (true, false) => StreamState::HalfClosedLocal,
            (false, true) => StreamState::HalfClosedRemote,
            _ => StreamState::Open,
        }
    }

    /// Whether the stream is fully closed (both halves closed, or RESET) and may be dropped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state() == StreamState::Closed
    }

    /// DATA credits remaining for our sending direction (SPEC §3 backpressure).
    #[must_use]
    pub fn send_credit(&self) -> u64 {
        self.send_credit
    }

    /// Complete the responder handshake by sending OPEN_ACK, advertising `recv_window` credits for the
    /// peer→us direction (SPEC §3). Returns the header to seal.
    ///
    /// # Errors
    /// [`MessageError::StreamProtocol`] if called by an initiator or when not in the opening handshake.
    fn build_open_ack(&mut self, recv_window: u32) -> Result<StreamHeader> {
        if self.role != Role::Responder || self.handshake != Handshake::Opening {
            return Err(MessageError::StreamProtocol(
                "OPEN_ACK only from a responder mid-handshake",
            ));
        }
        self.handshake = Handshake::Established;
        self.recv_window_remaining = u64::from(recv_window);
        Ok(header(StreamFrame::OpenAck, 0, recv_window))
    }

    /// Stamp + reserve credit for one outbound DATA frame (SPEC §3). Returns the header to seal.
    ///
    /// # Errors
    /// [`MessageError::StreamProtocol`] if the stream is not established, our sending direction is
    /// already closed, or we have no send credit (backpressure — wait for a CREDIT grant).
    fn build_data(&mut self) -> Result<StreamHeader> {
        if self.handshake != Handshake::Established {
            return Err(MessageError::StreamProtocol(
                "DATA before the stream is established",
            ));
        }
        if self.local_closed {
            return Err(MessageError::StreamProtocol("DATA after our own CLOSE"));
        }
        if self.send_credit == 0 {
            return Err(MessageError::StreamProtocol(
                "DATA exceeds the granted credit window",
            ));
        }
        self.send_credit -= 1;
        let seq = self.send_seq;
        self.send_seq += 1;
        Ok(header(StreamFrame::Data, seq, 0))
    }

    /// Grant the peer `n` more DATA credits for its sending direction (SPEC §3 backpressure relief).
    /// Returns the CREDIT header to seal.
    ///
    /// # Errors
    /// [`MessageError::StreamProtocol`] if the stream is not established.
    fn build_credit(&mut self, n: u32) -> Result<StreamHeader> {
        if self.handshake != Handshake::Established {
            return Err(MessageError::StreamProtocol(
                "CREDIT before the stream is established",
            ));
        }
        self.recv_window_remaining = self.recv_window_remaining.saturating_add(u64::from(n));
        Ok(header(StreamFrame::Credit, 0, n))
    }

    /// Half-close our sending direction (SPEC §3). Returns the CLOSE header to seal.
    ///
    /// # Errors
    /// [`MessageError::StreamProtocol`] if our direction is already closed.
    fn build_close(&mut self) -> Result<StreamHeader> {
        if self.local_closed {
            return Err(MessageError::StreamProtocol("CLOSE after our own CLOSE"));
        }
        self.local_closed = true;
        Ok(header(StreamFrame::Close, 0, 0))
    }

    /// Abort the stream immediately from our side (SPEC §3 cancel). Returns the RESET header to seal.
    fn build_reset(&mut self) -> StreamHeader {
        self.reset = true;
        header(StreamFrame::Reset, 0, 0)
    }

    /// Validate + apply an inbound frame against the current state (SPEC §3). Pure: it mutates only the
    /// state machine and classifies the transition; the caller pairs [`Accepted::Data`] with the opened
    /// payload. OPEN is handled by the registry (it creates the session), never here.
    ///
    /// # Errors
    /// [`MessageError::StreamProtocol`] for any illegal transition — an out-of-order/gap/replayed seq, a
    /// DATA beyond the granted credit window, a frame after a half-close or reset, or an out-of-sequence
    /// handshake frame. The caller RESETs the stream on any such rejection.
    fn on_recv(&mut self, frame: StreamFrame, hdr: StreamHeader) -> Result<Accepted> {
        if self.reset {
            return Err(MessageError::StreamProtocol("frame after RESET"));
        }
        match frame {
            StreamFrame::Open => Err(MessageError::StreamProtocol(
                "duplicate OPEN for a live stream",
            )),
            StreamFrame::OpenAck => {
                if self.role != Role::Initiator || self.handshake != Handshake::Opening {
                    return Err(MessageError::StreamProtocol("unexpected OPEN_ACK"));
                }
                self.handshake = Handshake::Established;
                self.send_credit = u64::from(hdr.window);
                Ok(Accepted::Established)
            }
            StreamFrame::Data => {
                if self.handshake != Handshake::Established {
                    return Err(MessageError::StreamProtocol(
                        "DATA before the stream is established",
                    ));
                }
                if self.remote_closed {
                    return Err(MessageError::StreamProtocol("DATA after the peer's CLOSE"));
                }
                if hdr.seq != self.recv_seq {
                    return Err(MessageError::StreamProtocol(
                        "out-of-order / gap / replayed DATA seq",
                    ));
                }
                if self.recv_window_remaining == 0 {
                    return Err(MessageError::StreamProtocol(
                        "DATA exceeds the credit window we granted",
                    ));
                }
                self.recv_window_remaining -= 1;
                self.recv_seq += 1;
                Ok(Accepted::Data)
            }
            StreamFrame::Credit => {
                if self.handshake != Handshake::Established {
                    return Err(MessageError::StreamProtocol(
                        "CREDIT before the stream is established",
                    ));
                }
                self.send_credit = self.send_credit.saturating_add(u64::from(hdr.window));
                Ok(Accepted::Credit(u64::from(hdr.window)))
            }
            StreamFrame::Close => {
                if self.handshake != Handshake::Established {
                    return Err(MessageError::StreamProtocol(
                        "CLOSE before the stream is established",
                    ));
                }
                if self.remote_closed {
                    return Err(MessageError::StreamProtocol(
                        "duplicate CLOSE from the peer",
                    ));
                }
                self.remote_closed = true;
                Ok(Accepted::RemoteClosed)
            }
            StreamFrame::CloseAck => {
                if !self.local_closed {
                    return Err(MessageError::StreamProtocol("CLOSE_ACK without our CLOSE"));
                }
                Ok(Accepted::CloseAcked)
            }
            StreamFrame::Reset => {
                self.reset = true;
                Ok(Accepted::Reset)
            }
        }
    }
}

/// A [`StreamHeader`] for a control/data frame (SPEC §3).
fn header(frame: StreamFrame, seq: u64, window: u32) -> StreamHeader {
    StreamHeader {
        frame: frame.as_u8(),
        seq,
        window,
    }
}

/// The per-peer streaming registry (SPEC §3): it multiplexes many concurrent streams to ONE peer,
/// bounds their count ([`MAX_CONCURRENT_STREAMS`]), seals every outbound frame with a fresh ephemeral,
/// and opens + fully verifies every inbound frame — RESETting a stream on any failed verify (gate items
/// DIG-Network/dig_ecosystem#1162).
///
/// One endpoint's identity key both SEALS our outbound frames (as sender) and OPENS the peer's inbound
/// frames (as recipient) — the ONE BLS12-381 identity key (SPEC §5.1).
pub struct StreamEndpoint<'a> {
    /// Our identity secret key — seals outbound (sender) + opens inbound (recipient) (SPEC §5.1).
    identity_sk: &'a SecretKey,
    /// Our DID launcher id (the `sender` of our outbound frames).
    local_did: Bytes32,
    /// Our key epoch for rotation disambiguation (SPEC §2 field 7).
    local_epoch: u32,
    /// The peer DID launcher id (the `recipient` of our outbound frames).
    peer_did: Bytes32,
    /// The peer's BLS G1 identity public key (48-byte compressed) — the seal target for our frames.
    peer_pub: &'a [u8; 48],
    /// The message-type id every frame of these streams carries (SPEC §4).
    message_type: u32,
    /// Our monotonic per-peer anti-replay counter for outbound frames (SPEC §5.6).
    send_counter: u64,
    /// Live streams keyed by `correlation_id` (SPEC §2 field 4 / §3).
    sessions: HashMap<Bytes32, StreamSession>,
    /// The per-peer concurrent-stream cap (SPEC §3 DoS gate).
    max_concurrent: usize,
    /// The inbound anti-replay guard shared across all of this peer's streams (SPEC §5.6).
    guard: ReplayGuard,
}

impl<'a> StreamEndpoint<'a> {
    /// A new endpoint for streams to one peer, using [`MAX_CONCURRENT_STREAMS`] as the cap.
    ///
    /// `identity_sk` is our ONE BLS12-381 identity key; `peer_pub` is the peer's 48-byte G1 identity
    /// key. `message_type` is the SPEC §4 type every frame carries.
    #[must_use]
    pub fn new(
        identity_sk: &'a SecretKey,
        local_did: Bytes32,
        local_epoch: u32,
        peer_did: Bytes32,
        peer_pub: &'a [u8; 48],
        message_type: u32,
    ) -> Self {
        Self {
            identity_sk,
            local_did,
            local_epoch,
            peer_did,
            peer_pub,
            message_type,
            send_counter: 0,
            sessions: HashMap::new(),
            max_concurrent: MAX_CONCURRENT_STREAMS,
            guard: ReplayGuard::new(),
        }
    }

    /// Override the per-peer concurrent-stream cap (SPEC §3), e.g. for a higher-capacity relay endpoint
    /// or a tighter test boundary. Defaults to [`MAX_CONCURRENT_STREAMS`].
    #[must_use]
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// The number of live streams to this peer.
    #[must_use]
    pub fn stream_count(&self) -> usize {
        self.sessions.len()
    }

    /// Read-only access to a live session (for inspection/testing).
    #[must_use]
    pub fn session(&self, correlation_id: Bytes32) -> Option<&StreamSession> {
        self.sessions.get(&correlation_id)
    }

    /// Open a new outbound stream, advertising `recv_window` credits for the peer→us direction (SPEC §3).
    /// Returns the sealed OPEN envelope to send.
    ///
    /// # Errors
    /// [`MessageError::StreamLimit`] if we already hold [`MAX_CONCURRENT_STREAMS`] streams;
    /// [`MessageError::StreamProtocol`] if `correlation_id` is already in use; plus any seal error.
    pub fn open(
        &mut self,
        correlation_id: Bytes32,
        recv_window: u32,
        now_ms: u64,
        expires_at: u64,
    ) -> Result<DigMessageEnvelope> {
        if self.sessions.contains_key(&correlation_id) {
            return Err(MessageError::StreamProtocol(
                "correlation_id already in use",
            ));
        }
        if self.sessions.len() >= self.max_concurrent {
            return Err(MessageError::StreamLimit {
                cap: self.max_concurrent,
            });
        }
        self.sessions
            .insert(correlation_id, StreamSession::initiator(recv_window));
        let hdr = header(StreamFrame::Open, 0, recv_window);
        self.seal_frame(correlation_id, hdr, &[], now_ms, expires_at)
    }

    /// Complete a responder handshake, advertising `recv_window` credits for the peer→us direction.
    /// Returns the sealed OPEN_ACK envelope.
    ///
    /// # Errors
    /// [`MessageError::StreamProtocol`] for an unknown stream or an illegal handshake position; plus any
    /// seal error.
    pub fn open_ack(
        &mut self,
        correlation_id: Bytes32,
        recv_window: u32,
        now_ms: u64,
        expires_at: u64,
    ) -> Result<DigMessageEnvelope> {
        let hdr = self
            .session_mut(correlation_id)?
            .build_open_ack(recv_window)?;
        self.seal_frame(correlation_id, hdr, &[], now_ms, expires_at)
    }

    /// Send one DATA chunk on an established stream, consuming one credit (SPEC §3). Returns the sealed
    /// DATA envelope.
    ///
    /// # Errors
    /// [`MessageError::StreamProtocol`] for an unknown stream, a closed direction, or exhausted credit
    /// (backpressure); plus any seal/compression error.
    pub fn send_data(
        &mut self,
        correlation_id: Bytes32,
        payload: &[u8],
        now_ms: u64,
        expires_at: u64,
    ) -> Result<DigMessageEnvelope> {
        let hdr = self.session_mut(correlation_id)?.build_data()?;
        self.seal_frame(correlation_id, hdr, payload, now_ms, expires_at)
    }

    /// Grant the peer `n` more DATA credits (SPEC §3 backpressure). Returns the sealed CREDIT envelope.
    ///
    /// # Errors
    /// [`MessageError::StreamProtocol`] for an unknown or not-yet-established stream; plus any seal error.
    pub fn grant_credit(
        &mut self,
        correlation_id: Bytes32,
        n: u32,
        now_ms: u64,
        expires_at: u64,
    ) -> Result<DigMessageEnvelope> {
        let hdr = self.session_mut(correlation_id)?.build_credit(n)?;
        self.seal_frame(correlation_id, hdr, &[], now_ms, expires_at)
    }

    /// Half-close our sending direction (SPEC §3). Returns the sealed CLOSE envelope; the stream is
    /// dropped once BOTH directions are closed.
    ///
    /// # Errors
    /// [`MessageError::StreamProtocol`] for an unknown or already-closed direction; plus any seal error.
    pub fn close(
        &mut self,
        correlation_id: Bytes32,
        now_ms: u64,
        expires_at: u64,
    ) -> Result<DigMessageEnvelope> {
        let hdr = self.session_mut(correlation_id)?.build_close()?;
        let env = self.seal_frame(correlation_id, hdr, &[], now_ms, expires_at)?;
        self.drop_if_closed(correlation_id);
        Ok(env)
    }

    /// Abort a stream immediately (SPEC §3 cancel). Returns the sealed RESET envelope and drops the
    /// stream.
    ///
    /// # Errors
    /// [`MessageError::StreamProtocol`] for an unknown stream; plus any seal error.
    pub fn reset(
        &mut self,
        correlation_id: Bytes32,
        now_ms: u64,
        expires_at: u64,
    ) -> Result<DigMessageEnvelope> {
        let hdr = self.session_mut(correlation_id)?.build_reset();
        let env = self.seal_frame(correlation_id, hdr, &[], now_ms, expires_at)?;
        self.sessions.remove(&correlation_id);
        Ok(env)
    }

    /// Open + fully verify an inbound frame and drive the state machine (SPEC §3). On success returns a
    /// verified [`StreamEvent`]; on ANY failed verify or protocol violation returns
    /// [`StreamAccept::Dropped`] — a bad/unauthenticated/non-actionable frame silently discarded (a live
    /// session is left untouched); or, ONLY for a state-machine violation by the AUTHENTICATED peer on a
    /// KNOWN stream (or the concurrent-stream cap), [`StreamAccept::Reset`] — a sealed RESET the caller
    /// sends. A RESET is NEVER emitted for unauthenticated or duplicate input, so the untrusted relay
    /// (§5.4) cannot provoke a RESET reflection storm or replay-teardown (SPEC §3, gate item #1162).
    ///
    /// `resolve_sender_pub` maps `(peer DID, epoch)` to the peer's 48-byte G1 key (usually the endpoint's
    /// own `peer_pub`); `now_ms` is our wall clock for the freshness + expiry checks.
    ///
    /// # Errors
    /// Only a failure to SEAL the RESET response (on the authenticated-violation path) propagates as
    /// `Err`; a rejected inbound frame is the non-error [`StreamAccept::Dropped`]/[`StreamAccept::Reset`]
    /// outcome.
    pub fn accept(
        &mut self,
        envelope: &DigMessageEnvelope,
        resolve_sender_pub: impl Fn(Bytes32, u32) -> Option<[u8; 48]>,
        now_ms: u64,
    ) -> Result<StreamAccept> {
        let correlation_id = envelope.correlation_id;

        // 1. Open + fully verify the seal (subgroup, AEAD, BLS sig, header-match, expiry, anti-replay).
        //    ANY failure → DROP (never a RESET): the frame is unauthenticated (garbage/forged) or a
        //    replay/stale/expired frame the relay re-injected — it cannot be trusted to name a stream, so
        //    responding with a signed RESET would let the relay weaponize it (reflection storm /
        //    replay-teardown, §5.4). Dropping fully satisfies "never deliver corrupt data"; a live
        //    session for this correlation_id (if any) is left UNTOUCHED (a replayed frame never tears
        //    down a healthy stream).
        let opened = match open_message(
            self.identity_sk,
            envelope,
            &resolve_sender_pub,
            &mut self.guard,
            now_ms,
        ) {
            Ok(opened) => opened,
            Err(cause) => return Ok(StreamAccept::Dropped { cause }),
        };

        // 2. It MUST be a stream frame with a known kind (SPEC §3). A malformed-but-authenticated frame
        //    is a no-op → DROP (no RESET: still not an actionable state-machine event).
        let Some(hdr) = envelope.stream else {
            return Ok(StreamAccept::Dropped {
                cause: MessageError::StreamProtocol("stream event on a non-stream envelope"),
            });
        };
        let Some(frame) = StreamFrame::from_u8(hdr.frame) else {
            return Ok(StreamAccept::Dropped {
                cause: MessageError::StreamProtocol("unknown stream frame kind"),
            });
        };
        if opened.shape != InteractionShape::StreamFrame {
            return Ok(StreamAccept::Dropped {
                cause: MessageError::StreamProtocol("stream frame with a non-stream shape"),
            });
        }

        // 3. An inbound RESET is terminal: a RESET must NEVER beget a RESET (anti-storm). If it names a
        //    live session, tear that session down (PeerReset); otherwise DROP it silently.
        if frame == StreamFrame::Reset {
            return Ok(if self.sessions.remove(&correlation_id).is_some() {
                StreamAccept::Event(StreamEvent::PeerReset)
            } else {
                StreamAccept::Dropped {
                    cause: MessageError::StreamProtocol("RESET for an unknown stream"),
                }
            });
        }

        // 4. OPEN starts a NEW session (registry-owned): enforce the concurrent-stream cap here.
        if frame == StreamFrame::Open {
            return self.accept_open(correlation_id, hdr, now_ms);
        }

        // 5. Every other frame drives an existing session. A frame for an UNKNOWN stream is DROPPED (no
        //    RESET): it may be a late/stale frame after we dropped the session, and RESETting it would
        //    feed a ping-pong. Only a state-machine violation by the authenticated peer on a KNOWN
        //    session warrants a RESET (the frame is provably genuine, so no forge/replay storm).
        if !self.sessions.contains_key(&correlation_id) {
            return Ok(StreamAccept::Dropped {
                cause: MessageError::StreamProtocol("frame for an unknown stream"),
            });
        }
        let transition = self
            .sessions
            .get_mut(&correlation_id)
            .expect("presence checked above")
            .on_recv(frame, hdr);
        match transition {
            Ok(accepted) => {
                let event = to_event(accepted, opened.payload);
                self.drop_if_closed(correlation_id);
                Ok(StreamAccept::Event(event))
            }
            Err(cause) => {
                self.sessions.remove(&correlation_id);
                self.reset_response(correlation_id, now_ms, cause)
            }
        }
    }

    /// Handle a verified inbound OPEN: enforce the per-peer concurrent-stream cap, create the responder
    /// session, and report [`StreamEvent::Opened`] (SPEC §3). The OPEN is already authenticated (it
    /// passed `open_message`), so a RESET here is safe — it cannot be forged/replayed by the relay.
    fn accept_open(
        &mut self,
        correlation_id: Bytes32,
        hdr: StreamHeader,
        now_ms: u64,
    ) -> Result<StreamAccept> {
        if self.sessions.contains_key(&correlation_id) {
            return self.reset_response(
                correlation_id,
                now_ms,
                MessageError::StreamProtocol("duplicate OPEN for a live stream"),
            );
        }
        if self.sessions.len() >= self.max_concurrent {
            return self.reset_response(
                correlation_id,
                now_ms,
                MessageError::StreamLimit {
                    cap: self.max_concurrent,
                },
            );
        }
        self.sessions
            .insert(correlation_id, StreamSession::responder(hdr.window));
        Ok(StreamAccept::Event(StreamEvent::Opened))
    }

    /// Build the [`StreamAccept::Reset`] outcome: seal a RESET to the peer for `correlation_id` and
    /// report `cause`. Only ever called for an AUTHENTICATED state-machine violation on a known session
    /// or the concurrent-stream cap — never for unauthenticated/duplicate input (a RESET must never beget
    /// a RESET; SPEC §3 gate item #1162).
    fn reset_response(
        &mut self,
        correlation_id: Bytes32,
        now_ms: u64,
        cause: MessageError,
    ) -> Result<StreamAccept> {
        let hdr = header(StreamFrame::Reset, 0, 0);
        let frame = self.seal_frame(correlation_id, hdr, &[], now_ms, 0)?;
        Ok(StreamAccept::Reset {
            frame: Box::new(frame),
            cause,
        })
    }

    /// Seal one frame with a FRESH ephemeral (SPEC §5.1) — never a fixed/session ephemeral, so every
    /// frame has a unique `(key, nonce)` and ChaCha20Poly1305 nonce-reuse is impossible (gate item
    /// DIG-Network/dig_ecosystem#1183). Consumes one outbound anti-replay counter (SPEC §5.6).
    fn seal_frame(
        &mut self,
        correlation_id: Bytes32,
        hdr: StreamHeader,
        payload: &[u8],
        now_ms: u64,
        expires_at: u64,
    ) -> Result<DigMessageEnvelope> {
        let counter = self.send_counter;
        self.send_counter += 1;
        let params = SealParams {
            sender_sk: self.identity_sk,
            sender: self.local_did,
            sender_epoch: self.local_epoch,
            recipient: self.peer_did,
            recipient_pub: self.peer_pub,
            message_type: self.message_type,
            shape: InteractionShape::StreamFrame,
            correlation_id,
            stream: Some(hdr),
            counter,
            timestamp_ms: now_ms,
            expires_at,
            payload,
        };
        seal_message(&params)
    }

    /// A mutable session by `correlation_id`, or [`MessageError::StreamProtocol`] if unknown.
    fn session_mut(&mut self, correlation_id: Bytes32) -> Result<&mut StreamSession> {
        self.sessions
            .get_mut(&correlation_id)
            .ok_or(MessageError::StreamProtocol("unknown stream"))
    }

    /// Drop a session once fully closed, so a completed stream frees its slot against the cap.
    fn drop_if_closed(&mut self, correlation_id: Bytes32) {
        if self
            .sessions
            .get(&correlation_id)
            .is_some_and(StreamSession::is_closed)
        {
            self.sessions.remove(&correlation_id);
        }
    }
}

/// Pair a pure [`Accepted`] transition with the opened payload to build the public [`StreamEvent`].
fn to_event(accepted: Accepted, payload: Vec<u8>) -> StreamEvent {
    match accepted {
        Accepted::Established => StreamEvent::Established,
        Accepted::Data => StreamEvent::Data(payload),
        Accepted::Credit(n) => StreamEvent::CreditGranted(n),
        Accepted::RemoteClosed => StreamEvent::RemoteClosed,
        Accepted::CloseAcked => StreamEvent::CloseAcked,
        Accepted::Reset => StreamEvent::PeerReset,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_identity::{derive_identity_sk, master_secret_key_from_seed, public_key_bytes};
    use sha2::{Digest, Sha256};

    const NOW: u64 = 1_700_000_000_000;

    fn sk(label: &str) -> SecretKey {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        derive_identity_sk(&master_secret_key_from_seed(&seed))
    }

    fn cid(tag: &str) -> Bytes32 {
        Bytes32::new(Sha256::digest(tag.as_bytes()).into())
    }

    // ── Pure state-machine transition tests (no crypto) ──────────────────────────────────────────

    #[test]
    fn initiator_handshake_then_data() {
        let mut s = StreamSession::initiator(4);
        assert_eq!(s.state(), StreamState::Opening);
        // No DATA until established.
        assert!(s.build_data().is_err());
        // OPEN_ACK grants us 2 send credits.
        assert_eq!(
            s.on_recv(StreamFrame::OpenAck, header(StreamFrame::OpenAck, 0, 2)),
            Ok(Accepted::Established)
        );
        assert_eq!(s.state(), StreamState::Open);
        assert_eq!(s.send_credit(), 2);
        // Two DATA frames spend the credit; the third is refused (backpressure).
        assert!(s.build_data().is_ok());
        assert!(s.build_data().is_ok());
        assert!(s.build_data().is_err());
    }

    #[test]
    fn outbound_data_seq_increments() {
        let mut s = StreamSession::initiator(0);
        s.on_recv(StreamFrame::OpenAck, header(StreamFrame::OpenAck, 0, 3))
            .unwrap();
        assert_eq!(s.build_data().unwrap().seq, 0);
        assert_eq!(s.build_data().unwrap().seq, 1);
        assert_eq!(s.build_data().unwrap().seq, 2);
    }

    #[test]
    fn responder_rejects_out_of_order_recv_seq() {
        // Responder established (sent OPEN_ACK granting itself a recv window of 4).
        let mut s = StreamSession::responder(0);
        s.build_open_ack(4).unwrap();
        // In-order seq 0 accepted.
        assert_eq!(
            s.on_recv(StreamFrame::Data, header(StreamFrame::Data, 0, 0)),
            Ok(Accepted::Data)
        );
        // A gap (seq 2 when 1 expected) is rejected.
        assert!(s
            .on_recv(StreamFrame::Data, header(StreamFrame::Data, 2, 0))
            .is_err());
        // A replay of seq 0 is rejected.
        assert!(s
            .on_recv(StreamFrame::Data, header(StreamFrame::Data, 0, 0))
            .is_err());
    }

    #[test]
    fn recv_credit_window_bounds_inbound_data() {
        let mut s = StreamSession::responder(0);
        s.build_open_ack(1).unwrap(); // grant exactly 1 credit
        assert_eq!(
            s.on_recv(StreamFrame::Data, header(StreamFrame::Data, 0, 0)),
            Ok(Accepted::Data)
        );
        // The 2nd DATA exceeds the granted window.
        assert!(s
            .on_recv(StreamFrame::Data, header(StreamFrame::Data, 1, 0))
            .is_err());
    }

    #[test]
    fn credit_frame_relieves_send_backpressure() {
        let mut s = StreamSession::initiator(0);
        s.on_recv(StreamFrame::OpenAck, header(StreamFrame::OpenAck, 0, 1))
            .unwrap();
        s.build_data().unwrap();
        assert!(s.build_data().is_err(), "credit exhausted");
        // A CREDIT(2) grant refills.
        assert_eq!(
            s.on_recv(StreamFrame::Credit, header(StreamFrame::Credit, 0, 2)),
            Ok(Accepted::Credit(2))
        );
        assert!(s.build_data().is_ok());
        assert!(s.build_data().is_ok());
        assert!(s.build_data().is_err());
    }

    #[test]
    fn bidirectional_half_close() {
        let mut s = StreamSession::initiator(4);
        s.on_recv(StreamFrame::OpenAck, header(StreamFrame::OpenAck, 0, 4))
            .unwrap();
        // We close our sending direction: peer may still send.
        s.build_close().unwrap();
        assert_eq!(s.state(), StreamState::HalfClosedLocal);
        assert!(s.build_data().is_err(), "no DATA after our CLOSE");
        // Peer can still deliver DATA to us.
        assert_eq!(
            s.on_recv(StreamFrame::Data, header(StreamFrame::Data, 0, 0)),
            Ok(Accepted::Data)
        );
        // Peer closes too → fully closed.
        assert_eq!(
            s.on_recv(StreamFrame::Close, header(StreamFrame::Close, 0, 0)),
            Ok(Accepted::RemoteClosed)
        );
        assert_eq!(s.state(), StreamState::Closed);
        assert!(s.is_closed());
    }

    #[test]
    fn reset_aborts_from_any_state() {
        let mut s = StreamSession::initiator(4);
        assert_eq!(
            s.on_recv(StreamFrame::Reset, header(StreamFrame::Reset, 0, 0)),
            Ok(Accepted::Reset)
        );
        assert_eq!(s.state(), StreamState::Closed);
        // No frame is accepted after reset.
        assert!(s
            .on_recv(StreamFrame::Data, header(StreamFrame::Data, 0, 0))
            .is_err());
    }

    // ── End-to-end crypto integration (seal every frame, open + verify) ──────────────────────────

    struct Pair {
        a_sk: SecretKey,
        a_did: Bytes32,
        a_pub: [u8; 48],
        b_sk: SecretKey,
        b_did: Bytes32,
        b_pub: [u8; 48],
    }
    fn pair(tag: &str) -> Pair {
        let a_sk = sk(&format!("{tag}/a"));
        let b_sk = sk(&format!("{tag}/b"));
        Pair {
            a_pub: public_key_bytes(&a_sk),
            b_pub: public_key_bytes(&b_sk),
            a_did: cid(&format!("{tag}/a-did")),
            b_did: cid(&format!("{tag}/b-did")),
            a_sk,
            b_sk,
        }
    }

    const MT: u32 = 0x0000_0200; // dig-chat band, a stream type

    #[test]
    fn full_stream_round_trip_open_data_close() {
        let p = pair("rt");
        let mut alice = StreamEndpoint::new(&p.a_sk, p.a_did, 0, p.b_did, &p.b_pub, MT);
        let mut bob = StreamEndpoint::new(&p.b_sk, p.b_did, 0, p.a_did, &p.a_pub, MT);
        let sender_is_bob = |_d: Bytes32, _e: u32| Some(p.b_pub);
        let sender_is_alice = |_d: Bytes32, _e: u32| Some(p.a_pub);
        let stream = cid("rt/stream");

        // Alice OPENs, granting Bob 4 credits.
        let open = alice.open(stream, 4, NOW, 0).unwrap();
        assert!(matches!(
            bob.accept(&open, sender_is_alice, NOW).unwrap(),
            StreamAccept::Event(StreamEvent::Opened)
        ));

        // Bob OPEN_ACKs, granting Alice 4 credits.
        let ack = bob.open_ack(stream, 4, NOW, 0).unwrap();
        assert!(matches!(
            alice.accept(&ack, sender_is_bob, NOW).unwrap(),
            StreamAccept::Event(StreamEvent::Established)
        ));

        // Alice streams two DATA chunks; Bob delivers them in order.
        let d0 = alice.send_data(stream, b"hello ", NOW, 0).unwrap();
        let d1 = alice.send_data(stream, b"world", NOW, 0).unwrap();
        assert_eq!(
            bob.accept(&d0, sender_is_alice, NOW).unwrap(),
            StreamAccept::Event(StreamEvent::Data(b"hello ".to_vec()))
        );
        assert_eq!(
            bob.accept(&d1, sender_is_alice, NOW).unwrap(),
            StreamAccept::Event(StreamEvent::Data(b"world".to_vec()))
        );

        // Alice CLOSEs; Bob sees the half-close then Alice's stream is dropped once Bob closes too.
        let close = alice.close(stream, NOW, 0).unwrap();
        assert!(matches!(
            bob.accept(&close, sender_is_alice, NOW).unwrap(),
            StreamAccept::Event(StreamEvent::RemoteClosed)
        ));
    }

    #[test]
    fn concurrent_stream_cap_rejects_the_nth_plus_one_open() {
        let p = pair("cap");
        // A tiny endpoint (cap = 2) makes the boundary cheap to hit.
        let mut bob =
            StreamEndpoint::new(&p.b_sk, p.b_did, 0, p.a_did, &p.a_pub, MT).with_max_concurrent(2);
        let mut alice = StreamEndpoint::new(&p.a_sk, p.a_did, 0, p.b_did, &p.b_pub, MT);
        let sender_is_alice = |_d: Bytes32, _e: u32| Some(p.a_pub);

        for i in 0..2 {
            let open = alice.open(cid(&format!("cap/{i}")), 1, NOW, 0).unwrap();
            assert!(matches!(
                bob.accept(&open, sender_is_alice, NOW).unwrap(),
                StreamAccept::Event(StreamEvent::Opened)
            ));
        }
        assert_eq!(bob.stream_count(), 2);

        // The 3rd concurrent OPEN is refused with a RESET carrying StreamLimit.
        let open3 = alice.open(cid("cap/3"), 1, NOW, 0).unwrap();
        match bob.accept(&open3, sender_is_alice, NOW).unwrap() {
            StreamAccept::Reset { cause, .. } => {
                assert!(matches!(cause, MessageError::StreamLimit { cap: 2 }));
            }
            other => panic!("expected a StreamLimit RESET, got {other:?}"),
        }
        assert_eq!(
            bob.stream_count(),
            2,
            "the rejected OPEN created no session"
        );
    }

    #[test]
    fn failed_verify_frame_is_dropped_never_reset() {
        // A tampered/forged frame is unauthenticated → DROP (no signed RESET), so an inject-only relay
        // cannot provoke a RESET reflection storm (§5.4).
        let p = pair("badverify");
        let mut alice = StreamEndpoint::new(&p.a_sk, p.a_did, 0, p.b_did, &p.b_pub, MT);
        let mut bob = StreamEndpoint::new(&p.b_sk, p.b_did, 0, p.a_did, &p.a_pub, MT);
        let sender_is_alice = |_d: Bytes32, _e: u32| Some(p.a_pub);
        let stream = cid("badverify/s");

        let mut open = alice.open(stream, 4, NOW, 0).unwrap();
        let last = open.sealed.ciphertext.len() - 1;
        open.sealed.ciphertext[last] ^= 0x01;
        assert_eq!(
            bob.accept(&open, sender_is_alice, NOW).unwrap(),
            StreamAccept::Dropped {
                cause: MessageError::OpenFailed
            }
        );
        assert_eq!(bob.stream_count(), 0);
    }

    #[test]
    fn frame_for_unknown_stream_is_dropped_never_reset() {
        let p = pair("proto");
        let mut alice = StreamEndpoint::new(&p.a_sk, p.a_did, 0, p.b_did, &p.b_pub, MT);
        let mut bob = StreamEndpoint::new(&p.b_sk, p.b_did, 0, p.a_did, &p.a_pub, MT);
        let sender_is_alice = |_d: Bytes32, _e: u32| Some(p.a_pub);
        let stream = cid("proto/s");

        // Alice forces an authenticated DATA without Bob ever seeing an OPEN.
        alice.open(stream, 4, NOW, 0).unwrap();
        alice
            .sessions
            .get_mut(&stream)
            .unwrap()
            .on_recv(StreamFrame::OpenAck, header(StreamFrame::OpenAck, 0, 4))
            .unwrap();
        let data = alice.send_data(stream, b"early", NOW, 0).unwrap();
        // Bob has no session for it → DROP (no RESET → no ping-pong).
        assert!(matches!(
            bob.accept(&data, sender_is_alice, NOW).unwrap(),
            StreamAccept::Dropped { .. }
        ));
    }

    #[test]
    fn replayed_data_on_a_live_stream_is_dropped_and_stream_survives() {
        // Exploit-B guard: the relay re-injects a prior valid DATA on a LIVE stream. The ReplayGuard
        // rejects it → DROP (NOT a RESET), and the healthy session MUST stay live (no teardown).
        let p = pair("replay");
        let mut alice = StreamEndpoint::new(&p.a_sk, p.a_did, 0, p.b_did, &p.b_pub, MT);
        let mut bob = StreamEndpoint::new(&p.b_sk, p.b_did, 0, p.a_did, &p.a_pub, MT);
        let sender_is_alice = |_d: Bytes32, _e: u32| Some(p.a_pub);
        let stream = cid("replay/s");

        let open = alice.open(stream, 4, NOW, 0).unwrap();
        bob.accept(&open, sender_is_alice, NOW).unwrap();
        let ack = bob.open_ack(stream, 4, NOW, 0).unwrap();
        alice.accept(&ack, |_d, _e| Some(p.b_pub), NOW).unwrap();
        let data = alice.send_data(stream, b"once", NOW, 0).unwrap();
        assert_eq!(
            bob.accept(&data, sender_is_alice, NOW).unwrap(),
            StreamAccept::Event(StreamEvent::Data(b"once".to_vec()))
        );
        // Re-inject the exact same sealed frame: guard rejects the duplicate counter → DROP.
        assert_eq!(
            bob.accept(&data, sender_is_alice, NOW).unwrap(),
            StreamAccept::Dropped {
                cause: MessageError::Replay
            }
        );
        // The stream is UNTOUCHED — a healthy stream is not torn down by a replayed frame.
        assert_eq!(bob.stream_count(), 1);
        assert_eq!(bob.session(stream).unwrap().state(), StreamState::Open);
        // And the stream keeps working: the next in-order DATA is delivered.
        let next = alice.send_data(stream, b"twice", NOW, 0).unwrap();
        assert_eq!(
            bob.accept(&next, sender_is_alice, NOW).unwrap(),
            StreamAccept::Event(StreamEvent::Data(b"twice".to_vec()))
        );
    }

    #[test]
    fn inbound_reset_for_unknown_stream_does_not_beget_a_reset() {
        // Anti-storm: an inbound RESET naming an unknown stream is DROPPED, never answered with a RESET.
        let p = pair("resetstorm");
        let mut alice = StreamEndpoint::new(&p.a_sk, p.a_did, 0, p.b_did, &p.b_pub, MT);
        let mut bob = StreamEndpoint::new(&p.b_sk, p.b_did, 0, p.a_did, &p.a_pub, MT);
        let sender_is_alice = |_d: Bytes32, _e: u32| Some(p.a_pub);

        // Alice opens then RESETs a stream Bob never saw → Bob receives a RESET for an unknown stream.
        let ghost = cid("resetstorm/ghost");
        alice.open(ghost, 1, NOW, 0).unwrap();
        let reset = alice.reset(ghost, NOW, 0).unwrap();
        assert!(matches!(
            bob.accept(&reset, sender_is_alice, NOW).unwrap(),
            StreamAccept::Dropped { .. }
        ));
        assert_eq!(bob.stream_count(), 0);
    }

    #[test]
    fn protocol_violation_on_established_stream_still_resets() {
        // The LEGIT RESET path: an authenticated peer breaks the state machine on a KNOWN session
        // (a bad DATA seq) → RESET + drop the session.
        let p = pair("legitreset");
        let mut alice = StreamEndpoint::new(&p.a_sk, p.a_did, 0, p.b_did, &p.b_pub, MT);
        let mut bob = StreamEndpoint::new(&p.b_sk, p.b_did, 0, p.a_did, &p.a_pub, MT);
        let sender_is_alice = |_d: Bytes32, _e: u32| Some(p.a_pub);
        let sender_is_bob = |_d: Bytes32, _e: u32| Some(p.b_pub);
        let stream = cid("legitreset/s");

        let open = alice.open(stream, 4, NOW, 0).unwrap();
        bob.accept(&open, sender_is_alice, NOW).unwrap();
        let ack = bob.open_ack(stream, 4, NOW, 0).unwrap();
        alice.accept(&ack, sender_is_bob, NOW).unwrap();

        // Alice (mis)sends DATA at seq 1 first (skipping 0) by desyncing her local send_seq.
        alice.sessions.get_mut(&stream).unwrap().send_seq = 1;
        let bad = alice.send_data(stream, b"gap", NOW, 0).unwrap();
        match bob.accept(&bad, sender_is_alice, NOW).unwrap() {
            StreamAccept::Reset { cause, .. } => {
                assert!(matches!(cause, MessageError::StreamProtocol(_)));
            }
            other => panic!("expected a RESET on the authenticated violation, got {other:?}"),
        }
        assert_eq!(bob.stream_count(), 0, "the violated session is dropped");
    }

    #[test]
    fn every_frame_uses_a_unique_ephemeral() {
        // CUSTODY: no two frames may share a KEM ephemeral (kem_enc) — that would be ChaCha20Poly1305
        // nonce-reuse. Seal a batch of frames and assert all kem_enc values are distinct.
        let p = pair("uniq");
        let mut alice = StreamEndpoint::new(&p.a_sk, p.a_did, 0, p.b_did, &p.b_pub, MT);
        let stream = cid("uniq/s");
        let mut kems = Vec::new();
        kems.push(alice.open(stream, 100, NOW, 0).unwrap().sealed.kem_enc);
        alice
            .sessions
            .get_mut(&stream)
            .unwrap()
            .on_recv(StreamFrame::OpenAck, header(StreamFrame::OpenAck, 0, 100))
            .unwrap();
        for _ in 0..16 {
            kems.push(
                alice
                    .send_data(stream, b"x", NOW, 0)
                    .unwrap()
                    .sealed
                    .kem_enc,
            );
        }
        let unique: std::collections::HashSet<_> = kems.iter().collect();
        assert_eq!(
            unique.len(),
            kems.len(),
            "every frame must use a fresh ephemeral"
        );
    }

    #[test]
    fn credit_grant_close_ack_and_peer_reset_round_trip() {
        // Exercise the CREDIT / CLOSE-ack / RESET receive paths end-to-end over the seal.
        let p = pair("credit");
        let mut alice = StreamEndpoint::new(&p.a_sk, p.a_did, 0, p.b_did, &p.b_pub, MT);
        let mut bob = StreamEndpoint::new(&p.b_sk, p.b_did, 0, p.a_did, &p.a_pub, MT);
        let sender_is_alice = |_d: Bytes32, _e: u32| Some(p.a_pub);
        let sender_is_bob = |_d: Bytes32, _e: u32| Some(p.b_pub);
        let stream = cid("credit/s");

        let open = alice.open(stream, 1, NOW, 0).unwrap();
        bob.accept(&open, sender_is_alice, NOW).unwrap();
        let ack = bob.open_ack(stream, 1, NOW, 0).unwrap();
        alice.accept(&ack, sender_is_bob, NOW).unwrap();

        // Bob grants Alice 3 more credits (backpressure relief).
        let credit = bob.grant_credit(stream, 3, NOW, 0).unwrap();
        assert_eq!(
            alice.accept(&credit, sender_is_bob, NOW).unwrap(),
            StreamAccept::Event(StreamEvent::CreditGranted(3))
        );
        assert_eq!(alice.session(stream).unwrap().send_credit(), 4);

        // Bob RESETs; Alice sees PeerReset and drops the stream.
        let reset = bob.reset(stream, NOW, 0).unwrap();
        assert_eq!(
            alice.accept(&reset, sender_is_bob, NOW).unwrap(),
            StreamAccept::Event(StreamEvent::PeerReset)
        );
        assert_eq!(alice.stream_count(), 0);
        assert_eq!(
            bob.stream_count(),
            0,
            "reset drops the sender's session too"
        );
    }

    #[test]
    fn close_ack_is_delivered() {
        let p = pair("closeack");
        let mut alice = StreamEndpoint::new(&p.a_sk, p.a_did, 0, p.b_did, &p.b_pub, MT);
        let mut bob = StreamEndpoint::new(&p.b_sk, p.b_did, 0, p.a_did, &p.a_pub, MT);
        let sender_is_alice = |_d: Bytes32, _e: u32| Some(p.a_pub);
        let sender_is_bob = |_d: Bytes32, _e: u32| Some(p.b_pub);
        let stream = cid("closeack/s");

        let open = alice.open(stream, 2, NOW, 0).unwrap();
        bob.accept(&open, sender_is_alice, NOW).unwrap();
        let ack = bob.open_ack(stream, 2, NOW, 0).unwrap();
        alice.accept(&ack, sender_is_bob, NOW).unwrap();

        // Alice CLOSEs; Bob CLOSE_ACKs; Alice receives the CloseAcked event.
        let close = alice.close(stream, NOW, 0).unwrap();
        bob.accept(&close, sender_is_alice, NOW).unwrap();
        // Bob replies with a raw CLOSE_ACK frame (no dedicated builder — craft via a RESET-shaped seal).
        let close_ack = bob
            .seal_frame(stream, header(StreamFrame::CloseAck, 0, 0), &[], NOW, 0)
            .unwrap();
        assert_eq!(
            alice.accept(&close_ack, sender_is_bob, NOW).unwrap(),
            StreamAccept::Event(StreamEvent::CloseAcked)
        );
    }

    #[test]
    fn endpoint_send_side_error_branches() {
        let p = pair("errs");
        let mut alice = StreamEndpoint::new(&p.a_sk, p.a_did, 0, p.b_did, &p.b_pub, MT);
        let stream = cid("errs/s");

        // Sending on an unknown stream is a protocol error.
        assert!(matches!(
            alice.send_data(stream, b"x", NOW, 0),
            Err(MessageError::StreamProtocol(_))
        ));

        alice.open(stream, 1, NOW, 0).unwrap();
        // A duplicate correlation_id OPEN is refused.
        assert!(matches!(
            alice.open(stream, 1, NOW, 0),
            Err(MessageError::StreamProtocol(_))
        ));

        // The concurrent-stream cap also gates the SEND (open) side, not only accept.
        let mut tight =
            StreamEndpoint::new(&p.a_sk, p.a_did, 0, p.b_did, &p.b_pub, MT).with_max_concurrent(1);
        tight.open(cid("errs/only"), 1, NOW, 0).unwrap();
        assert!(matches!(
            tight.open(cid("errs/2"), 1, NOW, 0),
            Err(MessageError::StreamLimit { cap: 1 })
        ));
    }

    #[test]
    fn half_closed_remote_state_then_local_close() {
        // Cover the HalfClosedRemote branch: peer closes first, we keep sending, then we close.
        let mut s = StreamSession::initiator(4);
        s.on_recv(StreamFrame::OpenAck, header(StreamFrame::OpenAck, 0, 4))
            .unwrap();
        s.on_recv(StreamFrame::Close, header(StreamFrame::Close, 0, 0))
            .unwrap();
        assert_eq!(s.state(), StreamState::HalfClosedRemote);
        assert!(
            s.build_data().is_ok(),
            "we may still send after the peer's CLOSE"
        );
        s.build_close().unwrap();
        assert_eq!(s.state(), StreamState::Closed);
    }
}
