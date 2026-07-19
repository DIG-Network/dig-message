# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.4.0] - 2026-07-19

### Features
- **stream:** WU4 streaming state machine + per-frame seal (SPEC §3, #1162) — OPEN/OPEN_ACK/DATA/CREDIT/CLOSE/CLOSE_ACK/RESET with ordered delivery, credit backpressure, bidirectional half-close, and cancel; every frame sealed with a fresh ephemeral (per-frame forward secrecy, no nonce reuse); per-peer concurrent-stream cap (MAX_CONCURRENT_STREAMS) + RESET-on-failed-verify.

## [0.3.3] - 2026-07-19

### Bug Fixes
- **release:** Sync + commit Cargo.lock on version bump (unblocks publish) (#9)

## [0.3.2] - 2026-07-19

### Documentation
- **readme:** Document the full export interface + usage (#8)

## [0.3.1] - 2026-07-19

### Bug Fixes
- **seal:** Restrict seal_with_ephemeral visibility (nonce-reuse footgun) (#6)

## [0.3.0] - 2026-07-19

### Features
- **seal:** WU2 e2e DHKEM-G1 auth-seal + BLS G2 sig + replay/expiry pipeline (#1160) (#4)

## [0.2.0] - 2026-07-19

### Features
- **registry:** Extensible message-type registry — bands + MessageKind + MessageRegistry (WU3 #1161) (#3)

## [0.1.0] - 2026-07-19

### Features
- **envelope:** Crate scaffold + envelope + framing + compression + KAT harness (WU1 #1159) (#2)

### Documentation
- **spec:** Normative dig-message base-protocol SPEC skeleton (#796) (#1)

### Chores
- Initial commit — dig-message base message protocol scaffold (epic #796)


