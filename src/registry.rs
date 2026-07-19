//! The extensible message-type registry (SPEC §4) — the runtime seam through which every downstream
//! subsystem (dig-chat, dig-email, dig-video, peer-RPC, IPC) plugs its own message types into the one
//! base protocol WITHOUT dig-message depending on any of them.
//!
//! Three pieces make the seam:
//! - [`MessageBand`] + [`MessageType::band`] — the normative id allocation (each subsystem owns a
//!   256-wide band), so a reader can classify any id it sees.
//! - [`MessageKind`] — the compile-time contract a type declares: its reserved id + its typed,
//!   byte-deterministic [`Streamable`] payload.
//! - [`MessageRegistry`] — the runtime table that maps a [`MessageType`] to a decode-and-handle
//!   closure, populated additively.
//!
//! Forward compatibility (SPEC §4, the §5.1 additive-only spirit) is the load-bearing property: a
//! `message_type` the registry has never seen MUST fail CLEANLY — [`MessageError::UnsupportedType`] for
//! a request/stream shape (so the caller replies with an error), a silent drop for a one-shot/response
//! shape — and MUST NEVER panic. An old reader therefore keeps working when newer senders introduce
//! new types.

use std::collections::HashMap;

use chia_traits::Streamable;

use crate::envelope::{InteractionShape, MessageType};
use crate::error::{MessageError, Result};

/// The base of the core band (handshake / ack / error / keepalive) (SPEC §4).
pub const BAND_CORE: u32 = 0x0000_0000;
/// The base of the peer-RPC band (peer-to-peer request/response) (SPEC §4).
pub const BAND_PEER_RPC: u32 = 0x0000_0100;
/// The base of the dig-chat band (SPEC §4, #768).
pub const BAND_DIG_CHAT: u32 = 0x0000_0200;
/// The base of the dig-email band (SPEC §4, #794).
pub const BAND_DIG_EMAIL: u32 = 0x0000_0300;
/// The base of the dig-video-chat signaling band (SPEC §4, #795).
pub const BAND_DIG_VIDEO: u32 = 0x0000_0400;
/// The base of the presence / directed data-request band (SPEC §4).
pub const BAND_PRESENCE: u32 = 0x0000_0500;
/// The base of the dig-ipc-protocol band (authenticated local dig-app ↔ dig-node IPC) (SPEC §4).
pub const BAND_IPC: u32 = 0x0000_0600;
/// The base of the dig-social-graph band — the social-graph connection manager's directed connection
/// offers/acceptances (SPEC §4, #1192, #991 SG-2). RESERVED: no concrete ids allocated yet beyond
/// the first-consumer `MSG_TYPE_CONNECTION_OFFER` (#991), which lives in dig-social-graph.
pub const BAND_SOCIAL_GRAPH: u32 = 0x0000_0700;
/// The base of the node↔relay sealed control band — register / hole-punch / retainer traffic between a
/// DIG Node and its relay (SPEC §4, #1199). RESERVED: owned by the dig-relay/dig-node relay-control
/// wire, no concrete ids allocated yet.
pub const BAND_RELAY_CONTROL: u32 = 0x0000_0800;
/// The base of the relay↔relay mesh band — frames exchanged between relay instances forming the relay
/// mesh (SPEC §4, #1200). RESERVED: owned by dig-relay's mesh wire, no concrete ids allocated yet.
pub const BAND_RELAY_MESH: u32 = 0x0000_0900;
/// The base of the experimental / vendor band — never shipped as a canonical type (SPEC §4).
pub const BAND_EXPERIMENTAL: u32 = 0x1000_0000;

/// A subsystem's reserved id band (SPEC §4). Each named band is owned by one subsystem and allocated
/// additively within it; ids that fall in no allocated subsystem band classify as [`MessageBand::Reserved`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageBand {
    /// Handshake, ack, error, keepalive (`0x0000_0000..=0x0000_00FF`).
    Core,
    /// Peer-to-peer request/response (`0x0000_0100..=0x0000_01FF`).
    PeerRpc,
    /// dig-chat (`0x0000_0200..=0x0000_02FF`).
    DigChat,
    /// dig-email (`0x0000_0300..=0x0000_03FF`).
    DigEmail,
    /// dig-video-chat signaling (`0x0000_0400..=0x0000_04FF`).
    DigVideo,
    /// Presence / directed data-request (`0x0000_0500..=0x0000_05FF`).
    Presence,
    /// dig-ipc-protocol (`0x0000_0600..=0x0000_06FF`).
    Ipc,
    /// dig-social-graph connection manager (`0x0000_0700..=0x0000_07FF`, #1192).
    SocialGraph,
    /// Node↔relay sealed control — register/hole-punch/retainer (`0x0000_0800..=0x0000_08FF`, #1199).
    RelayControl,
    /// Relay↔relay mesh frames (`0x0000_0900..=0x0000_09FF`, #1200).
    RelayMesh,
    /// Experimental / vendor, never canonical (`>= 0x1000_0000`).
    Experimental,
    /// A currently-unallocated id, reserved for a future subsystem band (SPEC §4).
    Reserved,
}

impl MessageType {
    /// Core: connection handshake (SPEC §4 core band).
    pub const CORE_HANDSHAKE: MessageType = MessageType(BAND_CORE);
    /// Core: generic acknowledgement (SPEC §4 core band).
    pub const CORE_ACK: MessageType = MessageType(BAND_CORE + 1);
    /// Core: protocol-level error report (SPEC §4 core band).
    pub const CORE_ERROR: MessageType = MessageType(BAND_CORE + 2);
    /// Core: liveness keepalive (SPEC §4 core band).
    pub const CORE_KEEPALIVE: MessageType = MessageType(BAND_CORE + 3);

    /// Classify this id into its reserved [`MessageBand`] (SPEC §4). Total — every `u32` maps to a
    /// band, so a reader can always classify an id it does not otherwise recognize.
    #[must_use]
    pub fn band(self) -> MessageBand {
        match self.0 {
            0x0000_0000..=0x0000_00FF => MessageBand::Core,
            0x0000_0100..=0x0000_01FF => MessageBand::PeerRpc,
            0x0000_0200..=0x0000_02FF => MessageBand::DigChat,
            0x0000_0300..=0x0000_03FF => MessageBand::DigEmail,
            0x0000_0400..=0x0000_04FF => MessageBand::DigVideo,
            0x0000_0500..=0x0000_05FF => MessageBand::Presence,
            0x0000_0600..=0x0000_06FF => MessageBand::Ipc,
            0x0000_0700..=0x0000_07FF => MessageBand::SocialGraph,
            0x0000_0800..=0x0000_08FF => MessageBand::RelayControl,
            0x0000_0900..=0x0000_09FF => MessageBand::RelayMesh,
            0x1000_0000..=0xFFFF_FFFF => MessageBand::Experimental,
            _ => MessageBand::Reserved,
        }
    }
}

/// The compile-time contract a message type declares to plug into the registry (SPEC §4). A downstream
/// crate implements it for each of its payload types; dig-message never depends on that crate.
///
/// The [`Payload`](MessageKind::Payload) is a Chia-[`Streamable`] type so its bytes are byte-
/// deterministic across the Rust and wasm/JS targets (SPEC §1); [`TYPE_ID`](MessageKind::TYPE_ID) is
/// the reserved id from the owning subsystem's band ([`MessageBand`]).
pub trait MessageKind {
    /// The reserved [`MessageType`] id for this kind (from the subsystem's band, SPEC §4).
    const TYPE_ID: MessageType;

    /// The typed, byte-deterministic payload carried by this message type (SPEC §1, §4).
    type Payload: Streamable;
}

/// The outcome of dispatching a decoded payload (SPEC §4). Both variants are success — an unknown
/// one-shot dropping is the intended forward-compat behavior, not an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// A registered handler decoded and processed the payload.
    Handled,
    /// The type was unknown and the shape was one-shot/response, so the message was silently dropped
    /// (SPEC §4). No handler ran and no error is surfaced.
    Dropped,
}

/// A registered decode-and-handle closure: it decodes the payload bytes into the kind's Streamable
/// payload and processes it, propagating any decode/handler failure as a [`MessageError`].
type Handler = Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync>;

/// The runtime message-type table (SPEC §4). Maps a [`MessageType`] to its decode-and-handle closure,
/// populated additively by each subsystem at startup.
///
/// It is deliberately additive-only: re-registering an already-present id is refused with
/// [`MessageError::DuplicateType`] rather than silently overwriting, upholding the SPEC §4 rule that an
/// id, once assigned, is never renumbered or repurposed. Registering a NEW id never disturbs the
/// handlers already present.
#[derive(Default)]
pub struct MessageRegistry {
    handlers: HashMap<MessageType, Handler>,
}

impl MessageRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a [`MessageKind`] with the closure that processes its decoded payload.
    ///
    /// The stored handler decodes the on-wire bytes into `K::Payload` (Streamable) before invoking
    /// `handler`, so callers work with the typed payload, never raw bytes.
    ///
    /// # Errors
    /// [`MessageError::DuplicateType`] if the kind's [`MessageKind::TYPE_ID`] is already registered
    /// (SPEC §4 additive-only — never silently repurpose an id).
    pub fn register<K, F>(&mut self, handler: F) -> Result<()>
    where
        K: MessageKind,
        F: Fn(K::Payload) -> Result<()> + Send + Sync + 'static,
    {
        let type_id = K::TYPE_ID;
        if self.handlers.contains_key(&type_id) {
            return Err(MessageError::DuplicateType(type_id.0));
        }
        let handler: Handler = Box::new(move |bytes: &[u8]| {
            let payload =
                K::Payload::from_bytes(bytes).map_err(|e| MessageError::Codec(e.to_string()))?;
            handler(payload)
        });
        self.handlers.insert(type_id, handler);
        Ok(())
    }

    /// Whether a [`MessageType`] has a registered handler.
    #[must_use]
    pub fn contains(&self, message_type: MessageType) -> bool {
        self.handlers.contains_key(&message_type)
    }

    /// The number of registered types.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Whether no types are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Route a decoded payload to its registered handler, applying the SPEC §4 unknown-type rule.
    ///
    /// `payload` is the already-opened, decompressed type-payload bytes (the seal/decompression are
    /// WU2/§1.1 concerns upstream of dispatch). `shape` decides how an unknown type fails.
    ///
    /// # Errors
    /// - [`MessageError::UnsupportedType`] when the type is unregistered AND the shape is a request or
    ///   stream frame (so the caller can reply UNSUPPORTED_TYPE).
    /// - Whatever the registered handler returns (a decode failure or a handler-reported error).
    ///
    /// An unregistered type with a one-shot/response shape is NOT an error: it returns
    /// [`Dispatch::Dropped`] (silent drop). Dispatch NEVER panics on an unknown type.
    pub fn dispatch(
        &self,
        message_type: MessageType,
        shape: InteractionShape,
        payload: &[u8],
    ) -> Result<Dispatch> {
        match self.handlers.get(&message_type) {
            Some(handler) => handler(payload).map(|()| Dispatch::Handled),
            None => match shape {
                InteractionShape::Request | InteractionShape::StreamFrame => {
                    Err(MessageError::UnsupportedType(message_type.0))
                }
                InteractionShape::OneShot | InteractionShape::Response => Ok(Dispatch::Dropped),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_streamable_macro::Streamable;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// A minimal Streamable payload standing in for a real dig-chat text message in these tests.
    #[derive(Debug, Clone, PartialEq, Eq, Streamable)]
    struct ChatText {
        body: Vec<u8>,
    }

    /// A dig-chat text message kind, reserved in the dig-chat band (SPEC §4).
    struct ChatTextKind;
    impl MessageKind for ChatTextKind {
        const TYPE_ID: MessageType = MessageType(BAND_DIG_CHAT);
        type Payload = ChatText;
    }

    /// A second, distinct kind (peer-RPC ping) used to prove additive registration is non-disturbing.
    #[derive(Debug, Clone, PartialEq, Eq, Streamable)]
    struct Ping {
        nonce: u64,
    }
    struct PingKind;
    impl MessageKind for PingKind {
        const TYPE_ID: MessageType = MessageType(BAND_PEER_RPC);
        type Payload = Ping;
    }

    #[test]
    fn register_then_dispatch_decodes_and_routes_to_the_handler() {
        let seen = Arc::new(AtomicU32::new(0));
        let sink = Arc::clone(&seen);

        let mut registry = MessageRegistry::new();
        registry
            .register::<ChatTextKind, _>(move |msg: ChatText| {
                sink.store(msg.body.len() as u32, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();

        let payload = ChatText {
            body: vec![1, 2, 3, 4, 5],
        }
        .to_bytes()
        .unwrap();

        let outcome = registry
            .dispatch(ChatTextKind::TYPE_ID, InteractionShape::Request, &payload)
            .unwrap();

        assert_eq!(outcome, Dispatch::Handled);
        assert_eq!(
            seen.load(Ordering::SeqCst),
            5,
            "handler saw the decoded payload"
        );
    }

    #[test]
    fn unknown_type_request_returns_unsupported_type() {
        let registry = MessageRegistry::new();
        let unknown = MessageType(BAND_DIG_EMAIL + 0x42);
        assert_eq!(
            registry
                .dispatch(unknown, InteractionShape::Request, &[])
                .unwrap_err(),
            MessageError::UnsupportedType(unknown.0)
        );
    }

    #[test]
    fn unknown_type_stream_frame_returns_unsupported_type() {
        let registry = MessageRegistry::new();
        let unknown = MessageType(BAND_DIG_VIDEO + 7);
        assert_eq!(
            registry
                .dispatch(unknown, InteractionShape::StreamFrame, &[])
                .unwrap_err(),
            MessageError::UnsupportedType(unknown.0)
        );
    }

    #[test]
    fn unknown_type_one_shot_is_silently_dropped_not_an_error() {
        let registry = MessageRegistry::new();
        let unknown = MessageType(BAND_EXPERIMENTAL);
        assert_eq!(
            registry
                .dispatch(unknown, InteractionShape::OneShot, &[])
                .unwrap(),
            Dispatch::Dropped
        );
    }

    #[test]
    fn unknown_type_response_is_silently_dropped() {
        let registry = MessageRegistry::new();
        let unknown = MessageType(BAND_PRESENCE + 1);
        assert_eq!(
            registry
                .dispatch(unknown, InteractionShape::Response, &[])
                .unwrap(),
            Dispatch::Dropped
        );
    }

    #[test]
    fn registering_a_new_type_never_disturbs_existing_registrations() {
        let mut registry = MessageRegistry::new();
        registry
            .register::<ChatTextKind, _>(|_: ChatText| Ok(()))
            .unwrap();
        assert!(registry.contains(ChatTextKind::TYPE_ID));

        // Additively add a second, unrelated type.
        registry.register::<PingKind, _>(|_: Ping| Ok(())).unwrap();

        assert_eq!(registry.len(), 2);
        assert!(
            registry.contains(ChatTextKind::TYPE_ID),
            "the first type is undisturbed"
        );
        assert!(registry.contains(PingKind::TYPE_ID));
    }

    #[test]
    fn re_registering_the_same_id_is_refused_additive_only() {
        let mut registry = MessageRegistry::new();
        registry
            .register::<ChatTextKind, _>(|_: ChatText| Ok(()))
            .unwrap();
        assert_eq!(
            registry
                .register::<ChatTextKind, _>(|_: ChatText| Ok(()))
                .unwrap_err(),
            MessageError::DuplicateType(ChatTextKind::TYPE_ID.0)
        );
        assert_eq!(
            registry.len(),
            1,
            "the failed re-registration left the table unchanged"
        );
    }

    #[test]
    fn a_handler_decode_failure_propagates_and_never_panics() {
        let mut registry = MessageRegistry::new();
        registry.register::<PingKind, _>(|_: Ping| Ok(())).unwrap();
        // A `Ping` is a u64 (8 bytes); a 3-byte frame cannot decode.
        let err = registry
            .dispatch(PingKind::TYPE_ID, InteractionShape::Request, &[1, 2, 3])
            .unwrap_err();
        assert!(matches!(err, MessageError::Codec(_)));
    }

    #[test]
    fn a_handler_reported_error_propagates() {
        let mut registry = MessageRegistry::new();
        registry
            .register::<PingKind, _>(|_: Ping| Err(MessageError::UnsupportedType(0)))
            .unwrap();
        let payload = Ping { nonce: 9 }.to_bytes().unwrap();
        assert!(registry
            .dispatch(PingKind::TYPE_ID, InteractionShape::OneShot, &payload)
            .is_err());
    }

    #[test]
    fn every_reserved_band_classifies_at_its_boundaries() {
        let cases = [
            (BAND_CORE, MessageBand::Core),
            (BAND_CORE + 0xFF, MessageBand::Core),
            (BAND_PEER_RPC, MessageBand::PeerRpc),
            (BAND_PEER_RPC + 0xFF, MessageBand::PeerRpc),
            (BAND_DIG_CHAT, MessageBand::DigChat),
            (BAND_DIG_CHAT + 0xFF, MessageBand::DigChat),
            (BAND_DIG_EMAIL, MessageBand::DigEmail),
            (BAND_DIG_VIDEO, MessageBand::DigVideo),
            (BAND_PRESENCE, MessageBand::Presence),
            (BAND_IPC, MessageBand::Ipc),
            (BAND_IPC + 0xFF, MessageBand::Ipc),
            (BAND_SOCIAL_GRAPH, MessageBand::SocialGraph),
            (BAND_SOCIAL_GRAPH + 0xFF, MessageBand::SocialGraph),
            (BAND_RELAY_CONTROL, MessageBand::RelayControl),
            (BAND_RELAY_CONTROL + 0xFF, MessageBand::RelayControl),
            (BAND_RELAY_MESH, MessageBand::RelayMesh),
            (BAND_RELAY_MESH + 0xFF, MessageBand::RelayMesh),
            (BAND_EXPERIMENTAL, MessageBand::Experimental),
            (0xFFFF_FFFF, MessageBand::Experimental),
        ];
        for (id, expected) in cases {
            assert_eq!(MessageType(id).band(), expected, "id {id:#010x}");
        }
    }

    #[test]
    fn unallocated_ids_classify_as_reserved() {
        // Just past the last named subsystem band (relay-mesh ends at 0x09FF) and below experimental.
        for id in [0x0000_0A00, 0x0000_1000, 0x00FF_FFFF, 0x0FFF_FFFF] {
            assert_eq!(
                MessageType(id).band(),
                MessageBand::Reserved,
                "id {id:#010x}"
            );
        }
    }

    #[test]
    fn named_core_type_constants_land_in_the_core_band() {
        for mt in [
            MessageType::CORE_HANDSHAKE,
            MessageType::CORE_ACK,
            MessageType::CORE_ERROR,
            MessageType::CORE_KEEPALIVE,
        ] {
            assert_eq!(mt.band(), MessageBand::Core);
        }
    }
}
