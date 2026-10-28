# TODO

- [x] CTX-0001 / #4: metadata checks, review, first publication, redacted snapshot, protection.
- [x] CTX-0002 / #3: W-131/W-137 approved transcript/history/snapshot/KV contract and privacy review.
- [x] CTX-0003 / #2: bounded isolated storage, migration/recovery/retention/deletion evidence.
- [ ] CTX-0004 / #1: independent privacy/security tests and Core W-146 parity.

0001 -> 0002 -> 0003 -> 0004. Narrow scopes and assign owners. No default raw transcript or arbitrary filesystem. Metadata checks are not product evidence; activate source/platform/CodeQL gates before acceptance.

## Component split (bitty#2495)

- [x] CTX-0008: storage component server half (descriptor, journaled store, protocol v1, packaging).
- [x] CTX-1479 / bitty#2574: default-off Core host client (descriptor/digest, spawn, deadlines, gate, migration helper).
- [ ] CTX-0012: protocol design record, packaged smoke for the #2491 matrix, capability-gate follow-up recorded (in review, PR #21).
- [ ] Host enablement and wiring, component-side capability gate, parity and linked-dependency removal, migration execution, per-target artifacts (#2491).
