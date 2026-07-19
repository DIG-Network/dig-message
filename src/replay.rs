//! Anti-replay protection (SPEC §5.6) — the FRESHNESS property the seal + signature do NOT provide.
//!
//! The seal gives confidentiality + AEAD integrity, the BLS signature gives sender-auth; this adds the
//! third required property: a captured, valid, signed message cannot be replayed. The scheme (pinned):
//!
//! - **Freshness window** — reject any `timestamp_ms` outside `[now − FRESHNESS_WINDOW_MS, now +
//!   FRESHNESS_WINDOW_MS]` (default ±5 min).
//! - **Sliding-window dedup** — per `(sender DID, sender_epoch)` keep O(1) state: a `highest` counter +
//!   a fixed [`REPLAY_WINDOW`]-bit window. `counter > highest` → accept + advance; within the window &
//!   unseen → accept (in-window reorder); already-seen or below the window → REJECT. The bitmap is
//!   fixed-size, so a counter flood cannot grow per-sender state.
//! - **Memory bound** — the tracked-sender table is a bounded LRU capped at [`MAX_TRACKED_SENDERS`],
//!   evicting the least-recently-seen first, so a Sybil flood cannot exhaust memory.
//!
//! Fail-closed: a message failing the check is dropped, never delivered ([`ReplayGuard::check_and_admit`]
//! returns `false`).

use std::collections::HashMap;

use chia_protocol::Bytes32;

use crate::constants::{FRESHNESS_WINDOW_MS, MAX_TRACKED_SENDERS, REPLAY_WINDOW};

/// The number of `u64` words backing the fixed [`REPLAY_WINDOW`]-bit sliding window.
const WINDOW_WORDS: usize = REPLAY_WINDOW / 64;

/// The dedup key: the ordered `(sender DID, sender_epoch)` pair (SPEC §5.6 / §5.6a). For the self case
/// the pair is `(X, X)` at a single epoch — a valid, independent counter stream.
type SenderKey = (Bytes32, u32);

/// Per-sender O(1) anti-replay state: the highest counter seen + a fixed sliding-window bitmap where
/// bit `i` marks `highest − i` as seen (bit 0 = `highest` itself). `last_seen_ms` drives LRU eviction.
#[derive(Clone)]
struct SenderWindow {
    highest: u64,
    /// Bit `i` (i in `0..REPLAY_WINDOW`) set ⇒ counter `highest − i` already accepted.
    bits: [u64; WINDOW_WORDS],
    last_seen_ms: u64,
    started: bool,
}

impl SenderWindow {
    fn new() -> Self {
        Self {
            highest: 0,
            bits: [0; WINDOW_WORDS],
            last_seen_ms: 0,
            started: false,
        }
    }

    fn get_bit(&self, offset: u64) -> bool {
        let i = offset as usize;
        (self.bits[i / 64] >> (i % 64)) & 1 == 1
    }

    fn set_bit(&mut self, offset: u64) {
        let i = offset as usize;
        self.bits[i / 64] |= 1 << (i % 64);
    }

    /// Shift the whole window left by `diff` bits (offsets grow as `highest` advances). Bits shifted
    /// past [`REPLAY_WINDOW`] fall off; the new low `diff` offsets start unseen.
    fn shift_left(&mut self, diff: u64) {
        if diff as usize >= REPLAY_WINDOW {
            self.bits = [0; WINDOW_WORDS];
            return;
        }
        let shift = diff as usize;
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        let mut out = [0u64; WINDOW_WORDS];
        for i in (0..WINDOW_WORDS).rev() {
            let mut v = 0u64;
            if i >= word_shift {
                v = self.bits[i - word_shift] << bit_shift;
                if bit_shift > 0 && i > word_shift {
                    v |= self.bits[i - word_shift - 1] >> (64 - bit_shift);
                }
            }
            out[i] = v;
        }
        self.bits = out;
    }

    /// Apply the sliding-window dedup for `counter`. Returns `true` (accept) + updates state, or
    /// `false` (replay/too-old) leaving state unchanged.
    fn admit(&mut self, counter: u64) -> bool {
        if !self.started {
            self.started = true;
            self.highest = counter;
            self.set_bit(0);
            return true;
        }
        if counter > self.highest {
            let diff = counter - self.highest;
            self.shift_left(diff);
            self.highest = counter;
            self.set_bit(0);
            true
        } else {
            let offset = self.highest - counter;
            if offset as usize >= REPLAY_WINDOW || self.get_bit(offset) {
                false
            } else {
                self.set_bit(offset);
                true
            }
        }
    }
}

/// The bounded per-receiver anti-replay table (SPEC §5.6). Tracks each sender's sliding window under a
/// hard [`MAX_TRACKED_SENDERS`] LRU cap.
#[derive(Default)]
pub struct ReplayGuard {
    senders: HashMap<SenderKey, SenderWindow>,
}

impl ReplayGuard {
    /// An empty guard.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of currently-tracked senders (≤ [`MAX_TRACKED_SENDERS`]).
    #[must_use]
    pub fn tracked_senders(&self) -> usize {
        self.senders.len()
    }

    /// Check freshness + dedup for a message and, on accept, record it (SPEC §5.6).
    ///
    /// Returns `true` (deliver) only when `timestamp_ms` is within the freshness window AND `counter`
    /// is new for `(sender, sender_epoch)`. Returns `false` (drop) for a stale timestamp, a duplicate
    /// counter, or a counter below the sliding window. State is advanced only on accept.
    #[must_use]
    pub fn check_and_admit(
        &mut self,
        sender: Bytes32,
        sender_epoch: u32,
        counter: u64,
        timestamp_ms: u64,
        now_ms: u64,
    ) -> bool {
        // Freshness window (SPEC §5.6): |timestamp_ms − now| ≤ FRESHNESS_WINDOW_MS.
        let lower = now_ms.saturating_sub(FRESHNESS_WINDOW_MS);
        let upper = now_ms.saturating_add(FRESHNESS_WINDOW_MS);
        if timestamp_ms < lower || timestamp_ms > upper {
            return false;
        }

        let key = (sender, sender_epoch);
        if !self.senders.contains_key(&key) {
            self.evict_if_full();
        }
        let window = self.senders.entry(key).or_insert_with(SenderWindow::new);
        if window.admit(counter) {
            window.last_seen_ms = window.last_seen_ms.max(timestamp_ms);
            true
        } else {
            false
        }
    }

    /// Evict the least-recently-seen sender when at the [`MAX_TRACKED_SENDERS`] cap, so a Sybil/nonce
    /// flood cannot exhaust memory (SPEC §5.6). Admission of a genuinely new sender still requires a
    /// valid BLS signature upstream, making forged distinct senders cryptographically costly.
    fn evict_if_full(&mut self) {
        if self.senders.len() < MAX_TRACKED_SENDERS {
            return;
        }
        if let Some(victim) = self
            .senders
            .iter()
            .min_by_key(|(_, w)| w.last_seen_ms)
            .map(|(k, _)| *k)
        {
            self.senders.remove(&victim);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender(n: u8) -> Bytes32 {
        Bytes32::new([n; 32])
    }

    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn first_message_is_accepted() {
        let mut g = ReplayGuard::new();
        assert!(g.check_and_admit(sender(1), 0, 0, NOW, NOW));
    }

    #[test]
    fn duplicate_counter_is_rejected() {
        let mut g = ReplayGuard::new();
        assert!(g.check_and_admit(sender(1), 0, 5, NOW, NOW));
        assert!(!g.check_and_admit(sender(1), 0, 5, NOW, NOW));
    }

    #[test]
    fn monotonic_advance_accepts() {
        let mut g = ReplayGuard::new();
        for c in 0..100 {
            assert!(g.check_and_admit(sender(1), 0, c, NOW, NOW), "counter {c}");
        }
    }

    #[test]
    fn in_window_reorder_accepts_then_rejects_replay() {
        let mut g = ReplayGuard::new();
        assert!(g.check_and_admit(sender(1), 0, 10, NOW, NOW));
        // Earlier-but-in-window counters accepted out of order.
        assert!(g.check_and_admit(sender(1), 0, 7, NOW, NOW));
        assert!(g.check_and_admit(sender(1), 0, 3, NOW, NOW));
        // Replaying any of them is rejected.
        assert!(!g.check_and_admit(sender(1), 0, 7, NOW, NOW));
        assert!(!g.check_and_admit(sender(1), 0, 10, NOW, NOW));
    }

    #[test]
    fn counter_below_the_window_is_rejected() {
        let mut g = ReplayGuard::new();
        assert!(g.check_and_admit(sender(1), 0, REPLAY_WINDOW as u64 + 100, NOW, NOW));
        // A counter more than REPLAY_WINDOW below `highest` is too old.
        assert!(!g.check_and_admit(sender(1), 0, 1, NOW, NOW));
    }

    #[test]
    fn far_future_jump_clears_and_accepts() {
        let mut g = ReplayGuard::new();
        assert!(g.check_and_admit(sender(1), 0, 5, NOW, NOW));
        // A jump beyond the window width resets the bitmap; the new highest is accepted.
        let far = 5 + REPLAY_WINDOW as u64 * 3;
        assert!(g.check_and_admit(sender(1), 0, far, NOW, NOW));
        // The old counter 5 is now far below the window -> rejected.
        assert!(!g.check_and_admit(sender(1), 0, 5, NOW, NOW));
    }

    #[test]
    fn stale_timestamp_rejected() {
        let mut g = ReplayGuard::new();
        assert!(!g.check_and_admit(sender(1), 0, 0, NOW - FRESHNESS_WINDOW_MS - 1, NOW));
    }

    #[test]
    fn future_timestamp_beyond_window_rejected() {
        let mut g = ReplayGuard::new();
        assert!(!g.check_and_admit(sender(1), 0, 0, NOW + FRESHNESS_WINDOW_MS + 1, NOW));
    }

    #[test]
    fn timestamp_at_window_edges_accepted() {
        let mut g = ReplayGuard::new();
        assert!(g.check_and_admit(sender(1), 0, 0, NOW - FRESHNESS_WINDOW_MS, NOW));
        assert!(g.check_and_admit(sender(2), 0, 0, NOW + FRESHNESS_WINDOW_MS, NOW));
    }

    #[test]
    fn distinct_senders_have_independent_counters() {
        let mut g = ReplayGuard::new();
        assert!(g.check_and_admit(sender(1), 0, 0, NOW, NOW));
        // Same counter from a different sender is independent, not a replay.
        assert!(g.check_and_admit(sender(2), 0, 0, NOW, NOW));
    }

    #[test]
    fn distinct_epochs_are_independent() {
        let mut g = ReplayGuard::new();
        assert!(g.check_and_admit(sender(1), 0, 0, NOW, NOW));
        assert!(g.check_and_admit(sender(1), 1, 0, NOW, NOW));
    }

    #[test]
    fn self_pair_is_a_valid_independent_stream() {
        // SPEC §5.6a: the (sender, recipient) pair may be (X, X). Here the dedup key is (sender,
        // epoch); a self-addressed sender tracks normally.
        let mut g = ReplayGuard::new();
        let me = sender(7);
        assert!(g.check_and_admit(me, 0, 0, NOW, NOW));
        assert!(g.check_and_admit(me, 0, 1, NOW, NOW));
        assert!(!g.check_and_admit(me, 0, 0, NOW, NOW));
    }

    #[test]
    fn per_sender_state_is_bounded_under_a_counter_flood() {
        // A huge counter flood from ONE sender never grows per-sender state beyond the fixed bitmap.
        let mut g = ReplayGuard::new();
        for c in (0..10_000).step_by(1) {
            let _ = g.check_and_admit(sender(1), 0, c, NOW, NOW);
        }
        assert_eq!(g.tracked_senders(), 1, "one sender = one bounded entry");
    }
}
