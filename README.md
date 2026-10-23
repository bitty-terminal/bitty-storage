# bitty-storage

Bounded isolated storage mechanics crate (landed CTX-0003, pending independent verification CTX-0004). Session snapshot codec, atomic durable commits, per-plugin KV backend, and transcript/history descriptor types behind the accepted W-131/W-137 contracts. Core retains capture, restore re-derivation, validation-before-mutation, and generation fencing; this crate implements the byte mechanics one-way (Core never imports it).

Prerequisite: W-131 / bitty-docs CTX-0267 accepted (commit 21d63dc); W-137 plugin contract accepted (bitty-plugins-docs PR #138, commit 002c7ce). Separate transcript, command history, session snapshots and plugin KV. Terminal Truth remains volatile; capture is opt-in and secret-minimizing.

CTX-0001 -> CTX-0002 -> CTX-0003 -> CTX-0004 maps to Issues #4 -> #3 -> #2 -> #1. CTX-0001 (bootstrap) is complete: metadata gates, independent review, first publication, redacted CarryCtx snapshot and branch protection are recorded. CTX-0002 (contract readiness) is accepted on the W-131/W-137 acceptances plus recorded privacy review; CTX-0003 implementation is landed here.

## Executable component boundary (bitty#2495)

The crate is also the installable `storage` native component. It is a stdio
coprocess in the DIR-030 shape: the host spawns `bitty-storage --root PATH`,
sends length-prefixed frames on stdin, and reads frames from stdout. stderr
carries diagnostics only. The component wraps journaled namespaces under the
host-selected root; it carries no installer, no download source, no capability
policy, no XDG migration, and no Core dependency.

- Descriptor: [`bitty-component.toml`](bitty-component.toml) — name `storage`,
  version `0.0.1`, protocol `[1, 1]`, executable `bitty-storage`.
- Parser: `bitty_storage::component::descriptor` — closed `[component]` table,
  strict `X.Y.Z`, `[a-z][a-z0-9-]{0,31}` name, `bitty-<name>` executable, 64
  lowercase hex digits, and a `validate_for_install` check that refuses the
  packaging placeholder digest.
- Store: `bitty_storage::component::store` — one locked directory per
  namespace with `snapshot`, `previous`, `journal`, and `lock` members.
- Server: `bitty_storage::component::server` — handshake, request dispatch,
  bounded pages, atomic commits, previous-revision rollback, clean shutdown.
- Binary: `bitty-storage` (`--root PATH`; `--version`; `--check-manifest PATH`).

### Wire protocol v1

`frame = length:u32be payload[length]`, `payload = tag:u8 fields...`; integers
are big-endian, strings/bytes/list lengths are `u32be` and bounded. The frame
cap is 256 KiB and is checked from the four-byte header before any payload
read or allocation. Tags are fixed; unknown tags, trailing bytes, zero request
ids, and invalid namespace/key grammar fail closed.

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

A `Row` is `key:str value:bytes`; rows are ordered by key in snapshots and
responses. Requests are synchronous. `Committed` is a success response only: it
means the batch is durable (journal and snapshot renames plus parent-directory
fsync) and the namespace still named the opened directory at the final
attachment check. A request rejected before publication returns `Error`, never
`Committed`, and performs no mutation: validation, stale-revision, bounds,
locking, and pre-rename I/O failures leave the committed revision, its rows,
and the previous-rollback image unchanged. A failure after publication is
reported with the distinct `uncertain` kind (code 11): a rename may already be
visible, its directory entry may not be confirmed durable, cleanup, recovery,
or rollback-image restoration may be incomplete, or the namespace path may no
longer name the opened directory. The host must reopen the namespace and read
its revision before retrying; retrying blindly can apply a second revision.
`rollback` is a one-step restore of the previous revision as a new monotonic
revision, not an abort of an in-flight request; repeating it toggles. It
accepts only a `previous` image whose revision is exactly `current - 1`: an
absent slot returns `no_previous`, and an image whose revision is equal to or
newer than the current snapshot, or skips a revision, returns `corrupt_state`.
A rollback therefore always publishes older content as a new revision and can
never acknowledge a no-op. `expected_revision` fences every commit and
rollback, so a stale host cannot overwrite newer state.

Wire error kinds are stable within protocol v1 and additive: `protocol` 1,
`invalid_request` 2, `budget` 3, `unsupported` 4, `unknown_namespace` 5,
`stale_revision` 6, `locked` 7, `corrupt_state` 8, `io` 9, `internal` 10, and
`uncertain` 11. `io` from a commit or rollback means a pre-rename failure whose
state was fully rolled back, so retrying the same revision is safe (from
open/read it is an ordinary I/O failure). `uncertain` is the only kind that
requires reopen-and-reread before a retry. Existing codes never move: a v1 host
that predates `uncertain` receives 11 (or any newer kind) as unknown and must
fail closed as a generic failure instead of retrying from a cached revision.

Properties the implementation enforces:

- **No path surface.** A request names a namespace, a key, and opaque bytes.
  Namespace and key grammars reject `/`, `\`, `:`, controls, non-ASCII, and
  `..`; the host chooses the root at spawn time. On Linux/Android the root and
  namespace directories are opened once and every state operation is
  `openat`/`renameat`/`unlinkat` relative to that directory fd, with
  `O_NOFOLLOW` on the final component and `O_CREAT|O_EXCL` temp creation.
  `snapshot`, `previous`, `journal`, and `lock` are each validated as regular
  files before use; symlinks, FIFOs, devices, and directories are refused.
  A replaced namespace or racing ancestor therefore cannot redirect a read,
  write, rename, or unlink outside the opened directory.
- **Attachment identity is the opened inode; the path check is detection
  only.** After open, the server's authority is the namespace directory fd.
  It stats the root-relative namespace path and compares `(st_dev, st_ino)`
  with that fd before acknowledging recovery and after publication. Those
  stats detect a rename, removal, or replacement visible at that instant. They
  are best-effort detection, not an atomic binding between the pathname and
  the stdio acknowledgement: a replacement that races the final check or the
  response write is not detected, and the response still describes only the
  opened inode. A detected detached namespace returns `uncertain`, never a
  success, and the server evicts the cached handle; the client must reopen
  (which re-resolves the pathname) and reread the revision before retrying. A
  success therefore guarantees the operation ran against the opened directory
  inode; it does not guarantee the pathname still names that inode when the
  host reads the response.
- **Atomic commit with a journal.** The candidate snapshot is published as
  `journal` first (temp+fsync+rename), then `previous`, then `snapshot`; the
  journal is removed last. The prior `previous` image (or its absence) is
  captured before the `previous` rewrite. A pre-rename failure in the
  `previous`/`snapshot` steps restores that image, removes the journal durably,
  and leaves the old snapshot intact, so a request reported as `io` was not
  applied and the N-1 rollback image is unchanged. If the restoration cannot
  be confirmed, the result is `uncertain` (never `io`) and the journal is
  retained so recovery completes the commit. A crash after journal publication
  is replayed on the next open. Once a rename may have happened, any failed
  cleanup, recovery, restoration, or attachment check returns `uncertain` and
  retains recovery evidence where possible. Reopen and inspect the revision
  before retrying; no power-loss behavior beyond successful file and directory
  fsync is claimed.
- **Crash recovery.** `snapshot` is replaced by atomic rename, so a partial
  image is never observed. A journal whose target is newer than the snapshot
  is replayed; recovery first completes the `previous` rewrite, so the restored
  rollback slot is exactly the pre-commit revision (N-1). An equal-or-older
  journal is discarded; malformed state fails closed with `corrupt_state`. A
  failure while replaying a valid journal (writing `previous`/`snapshot`,
  attachment, or journal removal) returns `uncertain` and keeps the journal,
  because the target may become visible on the next open. A corrupt snapshot
  with no valid journal is not auto-repaired or silently reset: the namespace
  stays unavailable with a typed `corrupt_state`, and the host must restore it
  from backup or delete it under its own policy.
- **Cross-process locking.** Opening a namespace takes a non-blocking
  exclusive OS `flock` held for the connection lifetime. A second component
  gets a typed `locked` error and the kernel releases the lock on crash. The
  lock member is opened `O_NOFOLLOW`, verified regular with a single link, and
  compared by device/inode with the current `lock` entry after locking, so a
  symlinked or hardlinked lock and a replacement between `openat` and `flock`
  are refused. Those checks are detection points; a later replacement cannot
  retarget the inode this handle already locked. The namespace directory is
  the lock's trust boundary: a process that can replace members inside it can
  also replace the lock.
- **Bounded everything.** 64 open namespaces, 4096 rows per namespace, 1 MiB
  per snapshot, 128 KiB per value, 128 upserts/deletes and 240 KiB of batch
  bytes per commit, 128 rows and 240 KiB per read page, and a 256 KiB frame.
  Reads are paged, so a full snapshot never needs an over-frame response. The
  commit path rewrites the whole bounded snapshot per batch; hosts should
  batch hot-path changes (the issue's performance rule), and no benchmark is
  claimed by this task.
- **Clean shutdown.** `Shutdown` or stdin EOF drops every namespace handle
  (releasing locks), writes `ShutdownAck` for an explicit `Shutdown`, and
  exits 0. Protocol violations exit 3; a root/server failure exits 4.
- **Platform posture.** The anchored backend is Linux/Android only. Other
  platforms fail closed at `StorageRoot::new` with `unsupported`; there is no
  path-based fallback. Linux x86_64 is the packaged target for this task, and
  Windows namespace-grammar hardening (trailing-dot aliasing) is tracked
  before any Windows enablement.

Generic (non-component) atomic helpers keep normal path semantics: a symlinked
final state directory is followed, and a missing parent on load is
`NotFound` (clean start), not an I/O error. After opening that parent once,
every operation is still fd-relative, so an ancestor replaced after the open
cannot redirect the commit.

### Packaging

```bash
just component-package       # build Linux x86_64 and pack dist/x86_64-unknown-linux-gnu.tar.gz
just component-package-test  # package-shape test without cargo, network, or R2
```

`scripts/package-component.sh` builds (or accepts `--binary`) one Rust target
and writes exactly `<target>.tar.gz`, `<target>.tar.gz.sha256`, and
`SHA256SUMS`. The archive contains exactly `bitty-component.toml` (with the
target binary's real digest) and `bitty-storage` (`bitty-storage.exe` on
Windows). It validates the canonical record, the Cargo version, the target
name, and every existing archive's full descriptor plus its exact member list
(two regular files: descriptor and platform executable) before writing, so a
mixed-version, mixed-identity, duplicate-member, or non-regular archive cannot
be published. Only Linux x86_64 is built and tested in this task; #2491 owns
the per-platform matrix and catalog rows. No tag is created and nothing is
uploaded to R2.

### Verification

```bash
just product                                  # fmt, clippy -D warnings, all tests
cargo test --test component_server --locked   # live protocol lifecycle
cargo test --test component_store --locked    # journal recovery and locking
cargo test --test component_descriptor --locked
```

The live suite covers a real commit/read/rollback lifecycle, a clean restart,
a SIGKILL after an acknowledged commit, stale revisions, bounded paging,
namespace/row/byte limits, oversize and malformed frames, path-shaped wire
names, two components contending for one namespace lock, a symlinked lock
(both existing and absent outside targets), and a namespace replaced after
open. Set `BITTY_STORAGE_COMPONENT_BIN` to run the same suite against a packed
release binary. The store suite constructs snapshot and journal bytes
independently to prove recovery across a crash between journal publication and
the snapshot rename, proves a failed replay is `uncertain` and retriable after
the filesystem is repaired, and exercises symlinks and hardlinks for the state
members and lock. It also proves that a failed snapshot publication restores
the N-1 rollback image (or keeps it absent), that an unconfirmed restoration is
`uncertain` with the journal retained, and that a `previous` image which is
equal to, newer than, or skips the current revision is `corrupt_state` rather
than a no-op rollback risk. The atomic-write suite proves a pre-planted temp
symlink is never followed and cannot create or modify an outside fixture; it
also covers post-rename directory-sync uncertainty, symlinked generic state
directories, and missing-parent loads. Windows path-commit behavior is covered
by a Windows-only test; the local and CI matrix still builds only Linux
x86_64.

### Remaining for the Core host client

- Resolve/install the descriptor, verify name/version/protocol/executable and
  the streamed SHA-256, choose the storage root, and spawn the binary from its
  version directory.
- Own the handshake and request deadlines, capability grants, consent,
  safe-mode denial, XDG-state migration, and restore re-derivation (none live
  in this component).
- Treat `Error`/EOF/exit-3 as `component_lost`, fail in-flight work, restart
  with the existing backoff policy, and place the component in its own
  process group/session so a crash is cleaned up by killing the group. Treat
  the `uncertain` kind (11) as reopen-and-reread before any retry, and treat
  unknown error kinds as a generic failure rather than retryable.
- Run parity tests against the in-process crate and remove the direct linked
  dependency after parity; synchronize the canonical docs and add the
  remaining target matrix (#2491).
