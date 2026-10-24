# TODO

- [x] CTX-0001 / #4: metadata checks, review, first publication, redacted snapshot, protection.
- [x] CTX-0002 / #3: W-131/W-137 approved transcript/history/snapshot/KV contract and privacy review.
- [x] CTX-0003 / #2: bounded isolated storage, migration/recovery/retention/deletion evidence.
- [x] CTX-0004 / #1: independent privacy/security tests and Core W-146 parity.
- [x] CTX-0007 / #16: CI runs the Rust product gates and the contract status is current.

0001 -> 0002 -> 0003 -> 0004. Narrow scopes and assign owners. No default raw transcript or arbitrary filesystem. Metadata checks are not product evidence: CI runs `just product` (fmt, clippy, tests) on every push and pull request, and `just ci-contract` fails if that step disappears.
