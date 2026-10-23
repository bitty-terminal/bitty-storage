//! Journaled, path-contained namespace storage for the component server.
//!
//! Each namespace is one directory under the host-chosen storage root with
//! four fixed members:
//!
//! ```text
//! <root>/<namespace>/
//!   snapshot   current committed state (atomic temp+rename, mode 0600)
//!   previous   state before the last commit (rollback source)
//!   journal    write-ahead target for the in-flight commit
//!   lock       OS advisory lock held for this namespace's lifetime
//! ```
//!
//! # Commit protocol
//!
//! 1. Serialize the candidate snapshot and publish it as `journal`
//!    (temp+fsync+rename). The journal is the durable intent record.
//! 2. Atomically rewrite `previous` from the current snapshot.
//! 3. Atomically rewrite `snapshot` from the candidate.
//! 4. Remove `journal` durably (fsync of the namespace directory).
//!
//! A crash after step 1 but before step 3 is repaired on the next open by
//! replaying the journal. A crash after step 3 leaves a journal that is
//! older than or equal to the snapshot, so recovery removes it without
//! rewriting state. A pre-rename failure in steps 2 or 3 removes the journal
//! durably and leaves the previous snapshot in place, so the request is
//! reported as `io` and was not applied. Once a rename may have happened,
//! every failure to confirm cleanup, recovery, or attachment is `uncertain`:
//! the new snapshot may already be visible, and the caller must reopen and
//! reread the revision before retrying.
//!
//! # Authority boundary
//!
//! The wire protocol never carries a path. Namespace names are validated to
//! `[a-z0-9][a-z0-9._-]{0,63}` with no `..`. On Linux/Android the root and
//! namespace directories are opened once and every state operation is
//! `openat`/`renameat`/`unlinkat` relative to that directory fd, with
//! `O_NOFOLLOW` on the final component and `O_CREAT|O_EXCL` temp creation.
//! A racing namespace or ancestor replacement therefore cannot redirect a
//! read, write, rename, or unlink outside the opened directory. State files
//! must be regular files; symlinks, FIFOs, devices, and directories are
//! refused before use. Other platforms fail closed with `Unsupported` rather
//! than falling back to path-based state operations.
//!
//! Namespace identity is the inode of the namespace directory opened by
//! `OpenNamespace`; every state operation stays relative to that fd. The
//! server additionally stats the root-relative namespace path and compares
//! `(st_dev, st_ino)` with the opened fd before acknowledging a recovery and
//! after publication. That check detects a rename, removal, or replacement
//! that is visible at the stat instant. It is **best-effort detection, not an
//! atomic binding** between the pathname and the stdio acknowledgement: a
//! replacement that races the final check or the response write is not
//! detected, and the response then still describes only the opened inode. A
//! detected detached namespace returns `uncertain` and the server evicts the
//! cached handle; the client must reopen, which re-resolves the pathname, and
//! reread the revision before retrying. A successful response therefore
//! guarantees that the operation ran against the opened directory inode; it
//! never guarantees that the pathname still names that inode when the host
//! reads the response.

use crate::component::protocol::valid_namespace_name;

/// Store failure category (stable; the server maps it to a wire error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreErrorKind {
    /// A namespace or key violates its grammar.
    InvalidName,
    /// A row, byte, snapshot, or journal bound was exceeded.
    Bound,
    /// Another process holds the namespace lock.
    Locked,
    /// Snapshot or journal bytes are malformed or fail their checksum.
    Corrupt,
    /// A filesystem operation failed (no path or content in the message).
    Io,
    /// A post-rename commit, recovery, cleanup, or attachment result could
    /// not be confirmed. Callers must reopen and reread the revision before
    /// retrying.
    Uncertain,
    /// Rollback was requested but no previous revision exists.
    NoPrevious,
    /// `expected_revision` does not match the current revision.
    StaleRevision,
    /// The platform has no fs-at/anchored backend here.
    Unsupported,
    /// Internal invariant failure.
    Internal,
}

/// Content-free store error (safe for stderr and bounded wire diagnostics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    kind: StoreErrorKind,
    message: &'static str,
}

impl StoreError {
    const fn new(kind: StoreErrorKind, message: &'static str) -> Self {
        Self { kind, message }
    }

    /// Failure category.
    #[must_use]
    pub const fn kind(&self) -> StoreErrorKind {
        self.kind
    }

    /// Bounded static diagnostic.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }

    pub(crate) fn invalid_name() -> Self {
        Self::new(StoreErrorKind::InvalidName, "invalid namespace or key name")
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn bound() -> Self {
        Self::new(StoreErrorKind::Bound, "storage bound exceeded")
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn corrupt() -> Self {
        Self::new(StoreErrorKind::Corrupt, "storage state is corrupt")
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn io() -> Self {
        Self::new(StoreErrorKind::Io, "storage i/o failed")
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn uncertain() -> Self {
        Self::new(
            StoreErrorKind::Uncertain,
            "storage outcome uncertain; reopen namespace",
        )
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn locked() -> Self {
        Self::new(StoreErrorKind::Locked, "namespace is locked")
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn no_previous() -> Self {
        Self::new(StoreErrorKind::NoPrevious, "no previous revision")
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn stale() -> Self {
        Self::new(StoreErrorKind::StaleRevision, "revision conflict")
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub(crate) fn unsupported() -> Self {
        Self::new(
            StoreErrorKind::Unsupported,
            "storage backend is unsupported on this platform",
        )
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for StoreError {}

/// A validated namespace name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceName(String);

impl NamespaceName {
    /// Parses a namespace name (same grammar as the wire codec).
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorKind::InvalidName`] for an empty, over-long,
    /// non-ASCII, separator-bearing, or dot-segment name.
    pub fn parse(value: &str) -> Result<Self, StoreError> {
        if !valid_namespace_name(value) {
            return Err(StoreError::invalid_name());
        }
        Ok(Self(value.to_owned()))
    }

    /// Name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One page of a committed snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPage {
    /// Revision the rows belong to.
    pub revision: u64,
    /// Zero-based row index of the first returned row.
    pub start_row: u32,
    /// Rows in key order.
    pub rows: Vec<crate::component::protocol::Row>,
    /// Rows in the whole snapshot.
    pub total_rows: u32,
    /// Row-value bytes in the whole snapshot.
    pub total_bytes: u64,
    /// Whether this page reaches the end.
    pub done: bool,
}

/// Result of one atomic batch commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitOutcome {
    /// New revision.
    pub revision: u64,
    /// Upserts applied.
    pub rows_written: u32,
    /// Deletes applied (including absent keys, which are no-ops).
    pub rows_removed: u32,
    /// Row-value bytes written by the batch.
    pub bytes_written: u64,
    /// Row count after the commit.
    pub total_rows: u32,
    /// Row-value bytes after the commit.
    pub total_bytes: u64,
}

/// Result of restoring the previous revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollbackOutcome {
    /// New revision created by the rollback.
    pub revision: u64,
    /// Revision whose contents were restored.
    pub restored_revision: u64,
    /// Row count after the rollback.
    pub total_rows: u32,
    /// Row-value bytes after the rollback.
    pub total_bytes: u64,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "store/anchored.rs"]
mod anchored;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use anchored::{Namespace, StorageRoot};

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[path = "store/unsupported.rs"]
mod unsupported;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub use unsupported::{Namespace, StorageRoot};
