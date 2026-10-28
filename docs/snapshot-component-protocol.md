# Snapshot component protocol (bitty#2495)

Status: **implemented-only** for the component half, pending independent review.
This document records the protocol decisions for the `storage` native component
and the mapping onto the accepted component wire v1. The binary, descriptor,
journaled store, and stdio server are merged
([bitty-storage#18](https://github.com/bitty-terminal/bitty-storage/pull/18)).
A default-off Core host client landed separately in
[bitty#2574](https://github.com/bitty-terminal/bitty/pull/2574) (CTX-1479,
2026-10-23): descriptor and digest verification, cleared-environment spawn in
its own process group, handshake and per-exchange deadlines, fail-closed
crash/timeout handling, the `StorageComponentGate`, and an idempotent migration
helper. That host is build-gated and not wired into the composition root, and no
user-facing enable exists. Component-side capability enforcement, host
enablement, parity-driven dependency removal, migration execution, restore
re-derivation, and per-target release artifacts are not implemented.

This is a design record for a code repository, not a `*-docs` corpus document.
The codec in [`src/component/protocol.rs`](../src/component/protocol.rs) is
authoritative for byte layout; this document is authoritative for semantics,
bounds, and the decisions that the layout alone cannot express. A change to
either must update the other in the same pull request.

## Purpose and scope

`bitty-storage` is the installable `storage` component of the native-component
boundary (DIR-030). It is a stdio coprocess: the host spawns `bitty-storage`,
writes length-prefixed frames on stdin, and reads frames from stdout. It
exposes one journaled key/value namespace store with snapshot commit, paged
read, and one-step rollback.

In scope:

- the process model and the Core/component authority split;
- framing, field encoding, and bounded payloads;
- the mapping to `bitty-network-wire` component wire v1;
- snapshot commit, read, and rollback semantics;
- the cross-process lock, crash recovery, and repair posture;
- the capability gate: who owns it, what the component can enforce today, and
  the extension required to enforce it in-process.

Out of scope: the descriptor installer, host enablement and wiring, XDG
migration execution, retention policy, transcript or history schemas, the Lua
surface, and restore re-derivation. Those stay with the owning tasks named in
[Remaining work](#remaining-work).

## Normative sources

This design must not weaken:

- [Storage and History Boundary (W-131)](https://github.com/bitty-terminal/bitty-docs/blob/main/docs/development/storage-and-history-boundary.md):
  distinct storage objects, Core-owned capability gate and budgets, atomic
  commit, user-only files, no generic database, no arbitrary filesystem
  authority, no default raw-output persistence.
- [ADR 0016](https://github.com/bitty-terminal/bitty-docs/blob/main/docs/decisions/adrs/ADR-0016-execution-graphics-accessibility-storage-platform-boundaries.md)
  binding constraints 8 and 9, and
  [ADR 0015](https://github.com/bitty-terminal/bitty-docs/blob/main/docs/decisions/adrs/ADR-0015-small-core-extraction-boundaries.md).
- [Native Component Boundary (DIR-030)](https://github.com/bitty-terminal/bitty-docs/blob/main/docs/development/native-component-boundary.md):
  coprocess lifecycle, `Hello`/`HelloAck`, descriptor and digest verification,
  bounded frame, no `PATH`, capability grants re-checked by the component,
  crash/backoff ownership.
- [History and Storage Policy (W-137)](https://github.com/bitty-terminal/bitty-plugins-docs/blob/main/extensibility/history-and-storage-policy.md):
  deny-by-default capability policy, no private first-party bypass, no
  filesystem shortcut, explicit scope and bound on every read.
- The security corpus, in particular `P0-AC-012`, `P0-AC-014`, `P0-AC-015`,
  `P0-AC-016`, `P0-AC-019`, and `P0-AC-026`.

Concrete capability identifiers are parked to `W-139`; this document names the
mechanism, never a final grant string.

## Process model and authority split

Core owns policy and lifecycle. The component owns durable byte mechanics.

| Concern                                         | Owner     | Where it lives                                                |
| ----------------------------------------------- | --------- | ------------------------------------------------------------- |
| Install, descriptor and digest verification     | Core      | Landed default-off (`bitty#2574` / CTX-1479)                  |
| Spawn, handshake and exchange deadlines         | Core      | Landed default-off; restart/backoff, idle stop, wiring remain |
| Capability grant, consent, safe-mode denial     | Core      | `StorageComponentGate` landed; consent and attribution remain |
| Storage root choice                             | Core      | `--root PATH` at spawn                                        |
| Namespace open, lock, commit, read, rollback    | Component | This repository                                               |
| Restore re-derivation and validation-before-use | Core      | Follow-up                                                     |
| Retention, purge policy, migration              | Core      | Migration helper landed; execution on enablement remains      |

The wire never carries a filesystem path, argv, environment, URL, or command
language. A request names a namespace, a key, and opaque bytes. The host chooses
the root; the component validates the namespace and key grammar and derives
every path from that root.

The two storage objects that exist today keep their own policy above the
component: session snapshots stay whole-file, versioned, Core-validated
artifacts (1 MiB cap); per-plugin KV keeps the published `bitty.store` ceilings
(64 KiB total, 8 KiB per value, 256 entries, depth 16). The component's bounds
are transport bounds, not a replacement for those policy ceilings. The store is
one namespace per object so the objects never share a schema or lifecycle.

## Framing and field encoding

The codec reuses component wire v1 exactly:

```text
frame   = length:u32be payload[length]
payload = tag:u8 fields...
```

- `length` is `1..=MAX_FRAME_BYTES` (256 KiB). Zero and over-limit lengths are
  rejected from the four-byte header alone; no payload byte is read or
  allocated.
- Integers are big-endian fixed width. `bool` is `0x00` or `0x01`; any other
  byte is rejected.
- A string is `len:u32be` plus validated UTF-8; bytes are `len:u32be` plus raw
  bytes; a list is `count:u32be` plus bounded elements. Every length and count
  is checked against its field bound before the slice is taken.
- Decoding fails closed on truncation, trailing bytes, unknown tags, invalid
  UTF-8, zero request ids, and grammar violations. Encoding applies the same
  bounds, so a peer cannot emit a frame the other side refuses.

## Mapping to `bitty-network-wire` component wire v1

The accepted component wire v1 lives in the `bitty-network-wire` crate
([bitty-network](https://github.com/bitty-terminal/bitty-network)). Its
**codec** fits storage and is reused byte-for-byte: the same four-byte
big-endian length prefix, the same 256 KiB frame cap, the same field encoding,
the same `Hello`/`HelloAck` field order, the same connection-level error id
`0`, and the same `Shutdown` tag `0x3F`.

Its **message set** does not fit, and storage does not pretend otherwise:

| v1 message            | Closest storage use    | Decision                                                                 |
| --------------------- | ---------------------- | ------------------------------------------------------------------------ |
| `Hello` `0x01`        | handshake              | Reused verbatim. `component = "storage"`, `protocol = [1, 1]`.           |
| `HelloAck` `0x02`     | handshake answer       | Reused verbatim. `protocol = 1`, `component = "storage"`, crate version. |
| `HttpRequest` `0x10`  | open, commit, rollback | Not reused. See the decision below.                                      |
| `RequestBody` `0x11`  | commit payload         | Not reused. A body stream is not a bounded row batch.                    |
| `ResponseHead` `0x20` | snapshot header        | Not reused. `status:u16` and header pairs cannot carry typed revisions.  |
| `ResponseBody` `0x21` | snapshot rows          | Not reused. Row framing and page accounting would be re-invented.        |
| `Error` `0x2F`        | typed failure          | Tag and field order reused; the kind code space is component-local.      |
| `Cancel` `0x30`       | none                   | Unassigned. Requests are synchronous.                                    |
| `Shutdown` `0x3F`     | shutdown               | Reused verbatim.                                                         |
| (no v1 message)       | `ShutdownAck` `0x3E`   | Added so an explicit stop is distinguishable from a crash.               |

Storage assigns these tags:

| Tag    | Message           | Direction | Fields                                                                                                                      |
| ------ | ----------------- | --------- | --------------------------------------------------------------------------------------------------------------------------- |
| `0x01` | `Hello`           | host→comp | `min:u16 max:u16 component:str version:str`                                                                                 |
| `0x02` | `HelloAck`        | comp→host | `protocol:u16 component:str version:str`                                                                                    |
| `0x10` | `OpenNamespace`   | host→comp | `request:u64 namespace:str`                                                                                                 |
| `0x11` | `ReadSnapshot`    | host→comp | `request:u64 namespace:str start_row:u32 max_rows:u32 max_bytes:u32`                                                        |
| `0x12` | `CommitBatch`     | host→comp | `request:u64 namespace:str expected_revision:u64 upserts:list<Row> deletes:list<str>`                                       |
| `0x13` | `Rollback`        | host→comp | `request:u64 namespace:str expected_revision:u64`                                                                           |
| `0x3F` | `Shutdown`        | host→comp | none                                                                                                                        |
| `0x20` | `NamespaceOpened` | comp→host | `request:u64 namespace:str revision:u64 rows:u32 bytes:u64`                                                                 |
| `0x21` | `SnapshotChunk`   | comp→host | `request:u64 namespace:str revision:u64 start_row:u32 rows:list<Row> total_rows:u32 total_bytes:u64 done:bool`              |
| `0x22` | `Committed`       | comp→host | `request:u64 namespace:str revision:u64 rows_written:u32 rows_removed:u32 bytes_written:u64 total_rows:u32 total_bytes:u64` |
| `0x23` | `RolledBack`      | comp→host | `request:u64 namespace:str revision:u64 restored_revision:u64 total_rows:u32 total_bytes:u64`                               |
| `0x2F` | `Error`           | comp→host | `request:u64 kind:u8 message:str`                                                                                           |
| `0x3E` | `ShutdownAck`     | comp→host | none                                                                                                                        |

`Row` is `key:str value:bytes`. Tags `0x40..=0x4F` stay reserved for the v1
WebSocket range and decode as unknown. Tag `0x30` is deliberately unassigned:
the server is synchronous, so there is nothing to cancel.

### Why the v1 message set was not reused

- **No path-shaped surface.** Encoding a commit as `PUT bitty://<namespace>`
  would introduce a URL grammar, a path-like identifier, and a second decoder
  for revision fencing in query or header fields. W-131 and W-137 forbid a
  path-shaped storage surface; the wire must not grow one as a convenience.
- **Typed outcomes.** Storage must distinguish `stale_revision`, `locked`,
  `corrupt_state`, `unsupported`, and `uncertain`. v1's `ErrorKind` is
  network-specific (`denied`, `offline`, `timeout`, `budget`, `tls`,
  `protocol`, `component_lost`, `internal`) and its decoder rejects unknown
  codes. Reusing it would either collapse distinct recovery semantics or force
  a released crate from another repository to change for storage's benefit.
- **Accounting.** `Committed` and `RolledBack` carry revision, row, and byte
  accounting that a host uses to maintain leases and budgets. `ResponseHead`
  has only a status code and string header pairs.
- **No implicit success.** v1 GET/PUT semantics treat a response head as the
  outcome. Storage needs one explicit durable-commit acknowledgement and one
  distinct "may have committed" kind; see [Atomic commit](#atomic-commit).

The `bitty-a11y` component made the same call in its own protocol. The schema
is selected per process: a host that checks `HelloAck.component` before sending
any operation cannot confuse the storage tag block with `HttpRequest`. If a
shared multiplexer ever carries both schemas on one stream, tag ranges must
become disjoint; that is recorded as an open point rather than assumed away.

What would change this decision: a future `bitty-network-wire` version that
defines a generic request envelope with typed metadata and an extensible error
registry. Storage would then migrate as a protocol version bump, not a silent
reinterpretation of existing tags.

## Handshake

`Hello` must be the first frame. The server checks three things in order:

1. `component == "storage"`. A mismatch is a connection-level `protocol`
   error and exit 3.
2. `[min, max]` intersects `[1, 1]` via `negotiate`. A non-intersecting or
   inverted range is a connection-level `protocol` error and exit 3.
3. The negotiated version is echoed in `HelloAck` with the component name and
   `CARGO_PKG_VERSION`.

Any other first frame is `handshake required`; a repeated `Hello` after the
handshake is `unexpected message`. Both are connection-level failures that end
the process. A clean EOF before `Hello` exits 0, so a host that spawns and
immediately reaps the component is not an error.

## Request semantics

### OpenNamespace

Creates the namespace directory when absent and takes the non-blocking
exclusive lock (see [Cross-process lock](#cross-process-lock)). Opening an
already-open namespace in the same connection re-checks attachment and returns
the current revision. The reply reports `revision` (`0` when never committed),
`rows`, and `bytes`.

### ReadSnapshot

Returns one page of the current committed snapshot in key order. `max_rows = 0`
means 128 rows; `max_bytes = 0` means 240 KiB. A request may not raise those
caps: the codec rejects a larger `max_rows` or `max_bytes` as a protocol
violation before the server sees it, so the connection ends instead of the cap
being silently clamped. A single row larger than the requested byte cap is a
request-scoped `budget` error; the server never returns an empty non-final page,
which would let a host loop forever. `done` is true on the page that reaches the
end; a `start_row` at or past the end returns an empty page with `done = true`.
Reads never mutate the namespace.

### CommitBatch

Deletes run before upserts, so a key present in both lists ends with the
upserted value. Deleting an absent key is a successful no-op and still counts
in `rows_removed`, because it is the host's declared intent.

`expected_revision` fences the write: `0` for a namespace that has never
committed, otherwise the revision the host last read. A mismatch is
`stale_revision` and changes nothing. Caps are checked before any durable
write: at most 128 upserts, 128 deletes, 128 KiB per value, 240 KiB of encoded
batch bytes, and 4096 rows and 1 MiB in the resulting snapshot.

`Committed` is a success response only. It means the batch is durable: the
journal, previous image, snapshot rename, and parent-directory fsync completed,
and the namespace path still named the opened directory at the final
attachment check. A request rejected before publication returns `Error` and
performs no mutation.

### Rollback

One-step restore of the previous revision, published as a new monotonic
revision. `expected_revision` fences it like a commit. The `previous` slot must
name exactly `current - 1`:

- absent: `invalid_request` / `no_previous`;
- equal to, newer than, or skipping the current revision: `corrupt_state`.

A rollback therefore never acknowledges a no-op and never restores an image
older than one step. Repeating it toggles between the last two states, because
each rollback publishes a new revision and shifts the `previous` slot. Revision
`0` is never rollback-able: the first commit removes any stale `previous`
image, so a namespace that has committed exactly once answers `no_previous`.

### Shutdown

`Shutdown` drops every namespace handle (releasing locks), writes
`ShutdownAck`, and exits 0. Stdin EOF does the same without the ack. A protocol
violation exits 3; a failure to open the root exits 4; a usage error exits 2.

## Bounded payloads

Every bound is enforced on both encode and decode. The checks that matter for
memory safety run before allocation or copying:

| Bound                      | Value   | Enforced                                          |
| -------------------------- | ------- | ------------------------------------------------- |
| `MAX_FRAME_BYTES`          | 256 KiB | From the 4-byte header, before the payload buffer |
| `MAX_NAMESPACES`           | 64      | Before opening a new handle                       |
| `MAX_NAMESPACE_NAME_BYTES` | 64      | Per field, before slicing                         |
| `MAX_KEY_BYTES`            | 128     | Per field, before slicing                         |
| `MAX_VALUE_BYTES`          | 128 KiB | Per value, before slicing                         |
| `MAX_ROWS`                 | 4096    | Snapshot total, before publication                |
| `MAX_SNAPSHOT_BYTES`       | 1 MiB   | Encoded snapshot and journal target               |
| `MAX_BATCH_ROWS`           | 128     | Upserts and deletes, per batch                    |
| `MAX_BATCH_BYTES`          | 240 KiB | Encoded batch, before publication                 |
| `MAX_READ_ROWS`            | 128     | One page                                          |
| `MAX_READ_BYTES`           | 240 KiB | One page's row bytes                              |
| `MAX_ERROR_MESSAGE_BYTES`  | 256     | Static diagnostics only                           |

The frame cap is checked from the header alone; a declared 4 GiB frame never
causes a 4 GiB allocation. Per-field lengths are checked before the frame slice
is taken, so a hostile count cannot drive a large `Vec`. Reads are paged so a
1 MiB snapshot never requires an over-frame response, and the commit path
rewrites the whole bounded snapshot per batch, so hosts must batch hot-path
changes rather than commit per write.

## Atomic commit

Each namespace directory has four fixed members:

```text
<root>/<namespace>/
  snapshot   current committed state
  previous   state before the last commit (rollback source)
  journal    write-ahead target for the in-flight commit
  lock       OS advisory lock held for the connection lifetime
```

The commit sequence is:

1. Encode the candidate snapshot and publish it as `journal`
   (temp + fsync + rename). The journal is the durable intent record.
2. Atomically rewrite `previous` from the current snapshot. The prior
   `previous` image (or its absence) is captured first, so a failed step 3 can
   restore it instead of leaving revision N in both slots.
3. Atomically rewrite `snapshot` from the candidate.
4. Remove `journal` durably (fsync of the namespace directory).

Failure classes are part of the contract:

- **Rejected before publication** (`invalid_request`, `budget`,
  `stale_revision`, `locked`, `corrupt_state`, `unsupported`, and a pre-rename
  `io`): nothing changed. The committed revision and its N-1 rollback image are
  both unchanged.
- **`io`**: a pre-rename durable-write or state-read failure that was fully
  rolled back. Retrying the same revision is safe.
- **`uncertain`**: a rename may already be visible, its directory entry may not
  be confirmed durable, cleanup or rollback-image restoration was incomplete,
  or the namespace path no longer names the opened directory. The server evicts
  the cached handle. The host must reopen and reread the revision before any
  retry; retrying from a cached revision can apply a second revision.

There is no in-flight transaction to abort. `Rollback` is an explicit new
revision, not a cancellation.

## Cross-process lock

`OpenNamespace` opens `lock` with `O_NOFOLLOW`, verifies it is a regular file
with one link, and takes a non-blocking exclusive `flock`. The lock is held for
the connection lifetime and released by the kernel on crash or exit.

A second component opening the same namespace gets a request-scoped `locked`
error and can still serve other namespaces. After the first component exits,
the lock is available and the second component's retry succeeds.

The opened lock inode and the current `lock` entry are compared by device and
inode after `flock`, so a replacement between `openat` and `flock` is refused
rather than locking a detached inode. This is detection at two instants, not a
seal: a process that can replace members inside the namespace directory can also
replace the lock. The namespace directory itself is the lock's trust boundary.

## Crash recovery and repair

`snapshot` is replaced by atomic rename, so a torn snapshot is never observed.
On open, the store reads `snapshot` and `journal`:

- **No journal**: decode `snapshot`, or start empty when absent.
- **Journal revision at or below `snapshot` revision**: the commit already
  became visible. Remove the journal durably and keep the snapshot.
- **Journal revision above `snapshot` revision, or the snapshot is missing or
  undecodable**: complete the interrupted commit. Rewrite `previous` from the
  current snapshot first (or remove a stale `previous` on a first commit), then
  publish the journal target as `snapshot`, check attachment, and remove the
  journal durably.
- **Valid journal, failing replay**: return `uncertain` and retain the journal,
  because the target may become visible on the next open. Retrying recovery later
  is safe; pretending the commit failed is not.
- **Corrupt snapshot with no valid journal**: `corrupt_state`. The component
  does not auto-repair, reset, or silently start empty.

Over-bound and malformed are different outcomes. A member larger than its cap
(`snapshot` or `previous` above `MAX_SNAPSHOT_BYTES`, `journal` above
`JOURNAL_MAX_BYTES`) is rejected by the capped read before any decode and maps
to `budget` (3); a valid journal does not override that read failure. A member
within its cap whose magic, format version, lengths, ordering, or checksum is
invalid maps to `corrupt_state` (8). Neither is auto-repaired: the host must
restore from backup or delete the namespace under its own policy in both cases.

The repair path is host-owned. A host that gets `corrupt_state` must restore the
namespace from its own backup or delete it under an explicit user policy; the
component has no repair command and no hidden reset. A host that gets
`uncertain` reopens the namespace, rereads the revision, and only then decides
whether the batch was applied. Any future repair tool must keep this property:
never delete the only durable copy of a namespace without evidence that the user
asked for it.

## Capability gate

Core owns the gate. W-131 and DIR-030 make Core the policy authority for
capability grants, consent, safe mode, and budgets; a component only executes
and re-checks the grant it is handed, never widening it.

**Current state:** protocol v1 carries no grant field. `Hello` is the v1 shape
(`min`, `max`, `component`, `version`), so the component cannot refuse a request
on capability grounds. The Core host client that landed in `bitty#2574` enforces
the policy gate before it resolves an install, creates a root, or spawns a
process: `StorageComponentGate` requires `preferred`, denies safe mode, and
requires a capability grant. That host is default-off and unwired, so there is no
user path that reaches the component today. The component's own denial surface
is still identity and protocol negotiation only: wrong component name,
non-intersecting version range, and any frame before `Hello`.

**Required extension (not implemented here).** Before the host is enabled or
wired into the composition root, the handshake must carry the grant explicitly,
in the same way `bitty-a11y` extended its `Hello` with a mode byte:

- `Hello.mode:u8` with bit `0x01` = safe mode and bit `0x02` = storage
  persistence granted. The host sets the bits from its own capability decision;
  the component never infers a grant from the environment.
- `HelloAck.capabilities:u8` echoes the effective bits. A deprived session
  (safe mode, no grant, or both) completes the handshake with zero capabilities.
- A deprived session answers `OpenNamespace`, `ReadSnapshot`, and every mutating
  request with a request-scoped `denied` error (the next additive kind code,
  12), and still answers `Shutdown`. It must not open, read, or create a
  namespace.
- The test matrix adds capability denial for open, read, commit, and rollback,
  plus grant-without-consent and safe-mode-with-grant cases to the live suite,
  and a host-side test that the grant is computed from the W-137 capability and
  never from the component's argv or environment.

Until that lands, a host that spawns the component without an in-process grant
check would serve requests the policy layer never allowed. The residual risk is
accepted only while the landed host stays default-off and unwired, so no user
path spawns the component; it is not acceptable for an enabled host. The
`Hello.mode` extension and its denial tests are therefore a prerequisite for
enablement, not for the already-merged client skeleton.

## Error kinds

Codes are stable within protocol v1 and additive. Existing codes never move.

| Code | Kind                | Retry guidance                                                             |
| ---- | ------------------- | -------------------------------------------------------------------------- |
| 1    | `protocol`          | Connection-level; the process exits. Restart, do not retry the frame.      |
| 2    | `invalid_request`   | Fix the request; no state changed.                                         |
| 3    | `budget`            | Reduce the batch, value, or page; no state changed.                        |
| 4    | `unsupported`       | Platform or operation unavailable; do not retry.                           |
| 5    | `unknown_namespace` | Open the namespace first.                                                  |
| 6    | `stale_revision`    | Reopen or reread, rebuild the batch, retry with the current revision.      |
| 7    | `locked`            | Another component owns the namespace; retry after it exits.                |
| 8    | `corrupt_state`     | Host repair or restore; never auto-reset.                                  |
| 9    | `io`                | Pre-rename failure, fully rolled back; retrying the same revision is safe. |
| 10   | `internal`          | Fail the request; report the defect.                                       |
| 11   | `uncertain`         | Reopen and reread the revision before any retry.                           |

A v1 host that predates `uncertain` receives code 11 as unknown and must fail
closed as a generic failure, not retry from a cached revision. `internal` stays
at 10 so the addition cannot renumber it.

## Verification

Existing live coverage (`cargo test --workspace --locked`):

- handshake then clean shutdown;
- commit durability across a clean restart and a `SIGKILL` after an
  acknowledged commit;
- stale-revision rejection with unchanged state;
- commit/read/rollback round trip, including rollback without a previous
  revision;
- bounded paging and ordered rows;
- namespace, row, and byte bounds;
- two components contending for one namespace lock, with recovery after exit;
- empty, malformed, path-shaped, and oversized frames;
- the same live suite against the packed binary (CI sets
  `BITTY_STORAGE_COMPONENT_BIN`), including a symlinked lock and a commit after
  namespace replacement.

Store-level coverage constructs snapshot and journal bytes independently to
prove recovery across a crash between journal publication and the snapshot
rename, failed replay as `uncertain`, restoration of the N-1 image, and the
`previous` revision invariant.

Packaged protocol smoke for the release matrix:

```bash
just component-package
python3 scripts/component_smoke.py \
  --archive dist/x86_64-unknown-linux-gnu.tar.gz \
  --expect-target x86_64-unknown-linux-gnu
```

`scripts/component_smoke.py` validates the archive members, the descriptor, and
the executable digest, then drives the packaged binary through handshake,
commit, paged read, rollback, stale revision, budget refusal, garbage/empty/
oversized frame refusal, cross-process lock contention, crash-after-ack
recovery, and clean shutdown. It is stdlib-only Python 3, bounds every read
before allocating, and is the entry point the #2491 matrix should call per
target. It is not a substitute for the Rust suite: it proves the packaged
artifact speaks the protocol, not that every internal recovery branch is
correct.

`--expect-target` checks only the archive basename. It does not prove which
platform built the binary, so the #2491 matrix must run it on the matching host
and treat a name mismatch as a packaging error, not as target verification.

## Remaining work

- Host enablement and wiring: put the landed `bitty#2574` / CTX-1479 client
  behind the injected gate in the composition root, add the user-facing enable,
  consent, attribution, an idle-stop policy, and crash restart/backoff.
  Descriptor install, streamed digest verification, spawn with a cleared
  environment and process group, handshake and per-exchange deadlines,
  crash/timeout fail-closed behavior, and the `StorageComponentGate` already
  landed there; they are not open work.
- Component-side capability enforcement: the `Hello.mode`/grant extension and
  its denial tests described above. This gates enablement, not the merged host
  skeleton.
- Parity: run the linked `bitty_storage::StorageBackend` path and the component
  path against the same fixtures, then remove Core's direct dependency.
- Migration execution: run the landed idempotent `migrate_linked_file` helper
  for existing XDG session and plugin-KV state under a host-owned, resumable
  path with no loss on interruption, and leave the linked files untouched.
- Restore re-derivation and validation-before-use stay in Core and must be
  preserved when the component becomes the storage path.
- Per-target artifacts: the #2491 matrix, Windows path-grammar hardening, and
  the install catalog. No tag or publication is created by this slice.
- Performance: the commit path rewrites the whole bounded snapshot. Hosts must
  batch; a future benchmark owns any threshold claim.
- Tag-range separation if a shared multiplexer ever carries both the `net` and
  `storage` schemas on one stream.

## References

- [bitty#2495](https://github.com/bitty-terminal/bitty/issues/2495): component
  split, snapshot service.
- [bitty-storage#18](https://github.com/bitty-terminal/bitty-storage/pull/18):
  merged component server half.
- [bitty#2491](https://github.com/bitty-terminal/bitty/issues/2491): per-target
  release matrix.
- [bitty-network](https://github.com/bitty-terminal/bitty-network):
  `bitty-network-wire` component wire v1 codec.
- [W-131](https://github.com/bitty-terminal/bitty-docs/blob/main/docs/development/storage-and-history-boundary.md),
  [W-137](https://github.com/bitty-terminal/bitty-plugins-docs/blob/main/extensibility/history-and-storage-policy.md),
  [DIR-030](https://github.com/bitty-terminal/bitty-docs/blob/main/docs/development/native-component-boundary.md).
