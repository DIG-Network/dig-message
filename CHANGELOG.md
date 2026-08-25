# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.7.0] - 2026-08-25

### Build
- **deps:** Hold dig-identity in step with dig-nat 0.21, release 0.7.0 (#14)

## [0.6.1] - 2026-08-20

### Bug Fixes
- **ci:** Name this crate, not the one the workflows were copied from (#13)

## [0.6.0] - 2026-08-08

### Chores
- **deps:** Bump dig-identity 0.4 -> 0.6 and the chia family 0.26 -> 0.36 (#12)

## [0.5.1] - 2026-07-19

### Bug Fixes
- **dig-message:** Sender-binding hard-drop + dup-OPEN consistency + expiry-DROP spec (#11)

## [0.5.0] - 2026-07-19

### Features
- **registry:** Reserve social-graph, relay-control, relay-mesh bands (#10)

## [0.4.0] - 2026-07-19

### Features
- **stream:** WU4 streaming state machine + per-frame seal (SPEC §3) (#7)

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


