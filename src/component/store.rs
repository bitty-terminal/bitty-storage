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
//! 4. Remove `journal` (best effort; a replay is idempotent).
//!
//! A crash after step 1 but before step 3 is repaired on the next open by
//! replaying the journal. A crash after step 3 leaves a journal that is
//! older than or equal to the snapshot, so recovery removes it without
//! rewriting state. A failed step 2 or 3 removes the journal and leaves the
//! previous snapshot in place, so an unacknowledged commit is not applied.
//!
//! # Authority boundary
//!
//! The wire protocol never carries a path. Namespace names are validated to
//! `[a-z0-9][a-z0-9._-]{0,63}` with no `..`, joined to a canonical root, and
//! the created directory is re-canonicalized and checked to stay inside that
//! root. Snapshot, journal, previous, and lock names are fixed constants;
//! keys are data, never filenames. Symlinked namespace directories and state
//! files are refused.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::component::protocol::{
    MAX_BATCH_BYTES, MAX_BATCH_ROWS, MAX_KEY_BYTES, MAX_READ_BYTES, MAX_READ_ROWS, MAX_ROWS,
    MAX_SNAPSHOT_BYTES, MAX_VALUE_BYTES, Row, valid_key, valid_namespace_name,
};

/// Snapshot file magic (format version follows separately).
const SNAPSHOT_MAGIC: &[u8] = b"bitty-storage-snapshot\n";
/// Journal file magic (format version follows separately).
const JOURNAL_MAGIC: &[u8] = b"bitty-storage-journal\n";
/// On-disk format version for both files.
const FORMAT_VERSION: u32 = 1;
/// Fixed snapshot member name.
const SNAPSHOT_FILE: &str = "snapshot";
/// Fixed previous-revision member name.
const PREVIOUS_FILE: &str = "previous";
/// Fixed journal member name.
const JOURNAL_FILE: &str = "journal";
/// Fixed lock member name.
const LOCK_FILE: &str = "lock";

/// Maximum journal bytes: journal header, a whole snapshot, and checksum.
pub const JOURNAL_MAX_BYTES: usize = JOURNAL_MAGIC.len() + 4 + 8 + 4 + MAX_SNAPSHOT_BYTES + 8;

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
    /// Rollback was requested but no previous revision exists.
    NoPrevious,
    /// `expected_revision` does not match the current revision.
    StaleRevision,
    /// The platform has no advisory-lock mechanism here.
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

    fn invalid_name() -> Self {
        Self::new(StoreErrorKind::InvalidName, "invalid namespace or key name")
    }

    fn bound() -> Self {
        Self::new(StoreErrorKind::Bound, "storage bound exceeded")
    }

    fn corrupt() -> Self {
        Self::new(StoreErrorKind::Corrupt, "storage state is corrupt")
    }

    fn io() -> Self {
        Self::new(StoreErrorKind::Io, "storage i/o failed")
    }

    fn locked() -> Self {
        Self::new(StoreErrorKind::Locked, "namespace is locked")
    }

    fn no_previous() -> Self {
        Self::new(StoreErrorKind::NoPrevious, "no previous revision")
    }

    fn stale() -> Self {
        Self::new(StoreErrorKind::StaleRevision, "revision conflict")
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

/// Closed namespace snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    revision: u64,
    rows: BTreeMap<String, Vec<u8>>,
}

impl Snapshot {
    /// Empty state at revision `0`.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Current revision (`0` means never committed).
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Row count.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Sum of row-value bytes.
    #[must_use]
    pub fn value_bytes(&self) -> u64 {
        self.rows.values().map(|value| value.len() as u64).sum()
    }

    /// Rows in key order.
    #[must_use]
    pub const fn rows(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.rows
    }

    /// Encodes the snapshot with magic, version, revision, rows, checksum.
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorKind::Bound`] when the encoded image exceeds
    /// [`MAX_SNAPSHOT_BYTES`].
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(self.rows.len())
                .map_err(|_| StoreError::bound())?
                .to_be_bytes(),
        );
        for (key, value) in &self.rows {
            let key_len = u32::try_from(key.len()).map_err(|_| StoreError::bound())?;
            let value_len = u32::try_from(value.len()).map_err(|_| StoreError::bound())?;
            out.extend_from_slice(&key_len.to_be_bytes());
            out.extend_from_slice(key.as_bytes());
            out.extend_from_slice(&value_len.to_be_bytes());
            out.extend_from_slice(value);
        }
        let checksum = checksum(&out);
        out.extend_from_slice(&checksum.to_be_bytes());
        if out.len() > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::bound());
        }
        Ok(out)
    }

    /// Decodes and fully validates a snapshot image.
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorKind::Corrupt`] for bad magic, version, lengths,
    /// ordering, grammar, trailing bytes, or checksum, and
    /// [`StoreErrorKind::Bound`] for an over-bound image or row.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::bound());
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(SNAPSHOT_MAGIC.len())? != SNAPSHOT_MAGIC {
            return Err(StoreError::corrupt());
        }
        if cursor.u32()? != FORMAT_VERSION {
            return Err(StoreError::corrupt());
        }
        let revision = cursor.u64()?;
        if revision == 0 {
            return Err(StoreError::corrupt());
        }
        let count = cursor.u32()? as usize;
        if count > MAX_ROWS {
            return Err(StoreError::bound());
        }
        let mut rows = BTreeMap::new();
        let mut previous_key: Option<String> = None;
        let mut value_bytes = 0usize;
        for _ in 0..count {
            let key_len = cursor.u32()? as usize;
            if key_len == 0 || key_len > MAX_KEY_BYTES {
                return Err(StoreError::corrupt());
            }
            let key = std::str::from_utf8(cursor.take(key_len)?)
                .map_err(|_| StoreError::corrupt())?
                .to_owned();
            if !valid_key(&key) {
                return Err(StoreError::corrupt());
            }
            if let Some(previous) = &previous_key {
                if key <= *previous {
                    return Err(StoreError::corrupt());
                }
            }
            previous_key = Some(key.clone());
            let value_len = cursor.u32()? as usize;
            if value_len > MAX_VALUE_BYTES {
                return Err(StoreError::bound());
            }
            let value = cursor.take(value_len)?.to_vec();
            value_bytes = value_bytes.saturating_add(value_len);
            if value_bytes > MAX_SNAPSHOT_BYTES {
                return Err(StoreError::bound());
            }
            rows.insert(key, value);
        }
        let stored = cursor.u64()?;
        if !cursor.is_empty() {
            return Err(StoreError::corrupt());
        }
        if checksum(&bytes[..bytes.len() - 8]) != stored {
            return Err(StoreError::corrupt());
        }
        Ok(Self { revision, rows })
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
    pub rows: Vec<Row>,
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

/// Canonical storage root chosen by the host.
#[derive(Debug, Clone)]
pub struct StorageRoot {
    path: PathBuf,
}

impl StorageRoot {
    /// Creates (when absent) and canonicalizes the storage root.
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorKind::Io`] when the directory cannot be created or
    /// resolved, and [`StoreErrorKind::InvalidName`] when the resolved root
    /// is not a directory.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        std::fs::create_dir_all(&path).map_err(|_| StoreError::io())?;
        let path = std::fs::canonicalize(&path).map_err(|_| StoreError::io())?;
        let metadata = std::fs::metadata(&path).map_err(|_| StoreError::io())?;
        if !metadata.is_dir() {
            return Err(StoreError::invalid_name());
        }
        Ok(Self { path })
    }

    /// Canonical root path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Opens and exclusively locks one namespace, recovering a published
    /// journal first.
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorKind::InvalidName`] for a bad name or symlinked
    /// namespace, [`StoreErrorKind::Locked`] when another process holds the
    /// lock, [`StoreErrorKind::Corrupt`] for malformed state, and
    /// [`StoreErrorKind::Io`] for filesystem failures.
    pub fn open_namespace(&self, name: &NamespaceName) -> Result<Namespace, StoreError> {
        let dir = self.path.join(name.as_str());
        let mut created = false;
        match std::fs::symlink_metadata(&dir) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(StoreError::invalid_name());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match std::fs::create_dir(&dir) {
                    Ok(()) => created = true,
                    // Lost the create race to another opener; the canonical
                    // containment check below still decides.
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(_) => return Err(StoreError::io()),
                }
            }
            Err(_) => return Err(StoreError::io()),
        }
        let canonical = std::fs::canonicalize(&dir).map_err(|_| StoreError::io())?;
        if !canonical.starts_with(&self.path) {
            return Err(StoreError::invalid_name());
        }
        #[cfg(unix)]
        if created {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o700));
        }

        let lock = lock_namespace(&canonical.join(LOCK_FILE))?;
        let snapshot = recover(&canonical)?;
        Ok(Namespace {
            name: name.clone(),
            dir: canonical,
            _lock: lock,
            snapshot,
        })
    }
}

/// One open, locked namespace.
#[derive(Debug)]
pub struct Namespace {
    name: NamespaceName,
    dir: PathBuf,
    _lock: File,
    snapshot: Snapshot,
}

impl Namespace {
    /// Namespace name.
    #[must_use]
    pub fn name(&self) -> &NamespaceName {
        &self.name
    }

    /// Current revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.snapshot.revision()
    }

    /// Current row count.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.snapshot.row_count()
    }

    /// Current row-value bytes.
    #[must_use]
    pub fn value_bytes(&self) -> u64 {
        self.snapshot.value_bytes()
    }

    /// Reads one bounded page of the committed snapshot.
    ///
    /// `max_rows` and `max_bytes` of `0` mean the protocol defaults. A page
    /// that cannot fit one row inside `max_bytes` is a [`StoreErrorKind::Bound`]
    /// rather than a silent empty page.
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorKind::Bound`] when a request parameter exceeds
    /// [`MAX_READ_ROWS`] / [`MAX_READ_BYTES`] or the next row cannot fit.
    pub fn read_page(
        &self,
        start_row: u32,
        max_rows: u32,
        max_bytes: u32,
    ) -> Result<SnapshotPage, StoreError> {
        let row_cap = if max_rows == 0 {
            MAX_READ_ROWS
        } else {
            max_rows as usize
        };
        if row_cap > MAX_READ_ROWS {
            return Err(StoreError::bound());
        }
        let byte_cap = if max_bytes == 0 {
            MAX_READ_BYTES
        } else {
            max_bytes as usize
        };
        if byte_cap > MAX_READ_BYTES {
            return Err(StoreError::bound());
        }

        let total_rows =
            u32::try_from(self.snapshot.rows.len()).map_err(|_| StoreError::bound())?;
        let total_bytes = self.snapshot.value_bytes();
        let start = start_row as usize;
        let mut rows = Vec::new();
        let mut used = 0usize;
        let mut more = false;
        for (index, (key, value)) in self.snapshot.rows.iter().enumerate().skip(start) {
            if rows.len() >= row_cap {
                more = true;
                break;
            }
            let cost = key.len() + value.len();
            if used + cost > byte_cap {
                if rows.is_empty() {
                    return Err(StoreError::bound());
                }
                more = true;
                break;
            }
            rows.push(Row {
                key: key.clone(),
                value: value.clone(),
            });
            used += cost;
            more = index + 1 != self.snapshot.rows.len();
        }
        Ok(SnapshotPage {
            revision: self.snapshot.revision(),
            start_row,
            rows,
            total_rows,
            total_bytes,
            done: !more,
        })
    }

    /// Atomically applies one batch at `expected_revision`.
    ///
    /// Deletes run before upserts, so a key present in both lists ends up
    /// with the upserted value. Present and absent deletes both count as
    /// applied; absent keys are successful no-ops.
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorKind::StaleRevision`] when the expected revision
    /// differs, [`StoreErrorKind::InvalidName`] for a bad key,
    /// [`StoreErrorKind::Bound`] for a row/byte cap, and
    /// [`StoreErrorKind::Io`] for a failed durable write.
    pub fn commit(
        &mut self,
        expected_revision: u64,
        upserts: Vec<Row>,
        deletes: Vec<String>,
    ) -> Result<CommitOutcome, StoreError> {
        if expected_revision != self.snapshot.revision {
            return Err(StoreError::stale());
        }
        if upserts.len() > MAX_BATCH_ROWS || deletes.len() > MAX_BATCH_ROWS {
            return Err(StoreError::bound());
        }
        let rows_written = u32::try_from(upserts.len()).map_err(|_| StoreError::bound())?;
        let rows_removed = u32::try_from(deletes.len()).map_err(|_| StoreError::bound())?;
        let mut batch_bytes = 0usize;
        for row in &upserts {
            if !valid_key(&row.key) {
                return Err(StoreError::invalid_name());
            }
            if row.value.len() > MAX_VALUE_BYTES {
                return Err(StoreError::bound());
            }
            batch_bytes = batch_bytes.saturating_add(row.key.len() + row.value.len() + 8);
        }
        for key in &deletes {
            if !valid_key(key) {
                return Err(StoreError::invalid_name());
            }
            batch_bytes = batch_bytes.saturating_add(key.len() + 4);
        }
        if batch_bytes > MAX_BATCH_BYTES {
            return Err(StoreError::bound());
        }

        let mut candidate_rows = self.snapshot.rows.clone();
        for key in &deletes {
            candidate_rows.remove(key);
        }
        let mut bytes_written = 0u64;
        for row in upserts {
            bytes_written = bytes_written.saturating_add(row.value.len() as u64);
            candidate_rows.insert(row.key, row.value);
        }
        if candidate_rows.len() > MAX_ROWS {
            return Err(StoreError::bound());
        }
        let revision = self
            .snapshot
            .revision
            .checked_add(1)
            .ok_or_else(StoreError::bound)?;
        let candidate = Snapshot {
            revision,
            rows: candidate_rows,
        };
        let candidate_bytes = candidate.encode()?;
        let current_bytes = self.snapshot.encode()?;
        self.publish(
            &candidate_bytes,
            &current_bytes,
            self.snapshot.revision == 0,
        )?;
        self.snapshot = candidate;
        Ok(CommitOutcome {
            revision,
            rows_written,
            rows_removed,
            bytes_written,
            total_rows: u32::try_from(self.snapshot.rows.len()).map_err(|_| StoreError::bound())?,
            total_bytes: self.snapshot.value_bytes(),
        })
    }

    /// Restores the previous revision as a new revision.
    ///
    /// One-step undo only: after a rollback the previous slot holds the state
    /// that was current before the rollback, so repeating rollback toggles.
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorKind::StaleRevision`] on a revision mismatch,
    /// [`StoreErrorKind::NoPrevious`] when no previous revision exists,
    /// [`StoreErrorKind::Corrupt`] for an invalid previous image, and
    /// [`StoreErrorKind::Io`] for a failed durable write.
    pub fn rollback(&mut self, expected_revision: u64) -> Result<RollbackOutcome, StoreError> {
        if expected_revision != self.snapshot.revision {
            return Err(StoreError::stale());
        }
        let previous_bytes = read_regular(&self.dir.join(PREVIOUS_FILE), MAX_SNAPSHOT_BYTES)?
            .ok_or_else(StoreError::no_previous)?;
        let previous = Snapshot::decode(&previous_bytes)?;
        let revision = self
            .snapshot
            .revision
            .checked_add(1)
            .ok_or_else(StoreError::bound)?;
        let candidate = Snapshot {
            revision,
            rows: previous.rows.clone(),
        };
        let candidate_bytes = candidate.encode()?;
        let current_bytes = self.snapshot.encode()?;
        self.publish(&candidate_bytes, &current_bytes, false)?;
        self.snapshot = candidate;
        Ok(RollbackOutcome {
            revision,
            restored_revision: previous.revision,
            total_rows: u32::try_from(self.snapshot.rows.len()).map_err(|_| StoreError::bound())?,
            total_bytes: self.snapshot.value_bytes(),
        })
    }

    /// Publishes `journal -> previous -> snapshot`, with cleanup on a
    /// pre-snapshot failure. A journal-removal failure is harmless because a
    /// replay of the same target is idempotent.
    fn publish(
        &self,
        candidate_bytes: &[u8],
        current_bytes: &[u8],
        first_commit: bool,
    ) -> Result<(), StoreError> {
        let journal = Journal::encode(candidate_bytes)?;
        let journal_path = self.dir.join(JOURNAL_FILE);
        let previous_path = self.dir.join(PREVIOUS_FILE);
        let snapshot_path = self.dir.join(SNAPSHOT_FILE);

        let result = (|| {
            write_atomic(&journal_path, &journal, JOURNAL_MAX_BYTES)?;
            if first_commit {
                // A prior namespace lifetime may have left a previous image;
                // revision 0 must not be rollback-able.
                let _ = std::fs::remove_file(&previous_path);
            } else {
                write_atomic(&previous_path, current_bytes, MAX_SNAPSHOT_BYTES)?;
            }
            write_atomic(&snapshot_path, candidate_bytes, MAX_SNAPSHOT_BYTES)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&journal_path);
            return result;
        }
        let _ = std::fs::remove_file(&journal_path);
        Ok(())
    }
}

// ── journal ─────────────────────────────────────────────────────────────────

struct Journal;

impl Journal {
    fn encode(snapshot_bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
        let mut out = Vec::new();
        out.extend_from_slice(JOURNAL_MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        let revision = snapshot_revision(snapshot_bytes)?;
        out.extend_from_slice(&revision.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(snapshot_bytes.len())
                .map_err(|_| StoreError::bound())?
                .to_be_bytes(),
        );
        out.extend_from_slice(snapshot_bytes);
        let checksum = checksum(&out);
        out.extend_from_slice(&checksum.to_be_bytes());
        if out.len() > JOURNAL_MAX_BYTES {
            return Err(StoreError::bound());
        }
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Snapshot, StoreError> {
        if bytes.len() > JOURNAL_MAX_BYTES {
            return Err(StoreError::bound());
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(JOURNAL_MAGIC.len())? != JOURNAL_MAGIC {
            return Err(StoreError::corrupt());
        }
        if cursor.u32()? != FORMAT_VERSION {
            return Err(StoreError::corrupt());
        }
        let target_revision = cursor.u64()?;
        let payload_len = cursor.u32()? as usize;
        if payload_len == 0 || payload_len > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::corrupt());
        }
        let payload = cursor.take(payload_len)?;
        let stored = cursor.u64()?;
        if !cursor.is_empty() {
            return Err(StoreError::corrupt());
        }
        if checksum(&bytes[..bytes.len() - 8]) != stored {
            return Err(StoreError::corrupt());
        }
        let snapshot = Snapshot::decode(payload)?;
        if snapshot.revision != target_revision {
            return Err(StoreError::corrupt());
        }
        Ok(snapshot)
    }
}

fn snapshot_revision(bytes: &[u8]) -> Result<u64, StoreError> {
    let offset = SNAPSHOT_MAGIC.len() + 4;
    if bytes.len() < offset + 8 {
        return Err(StoreError::corrupt());
    }
    let revision = u64::from_be_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .map_err(|_| StoreError::corrupt())?,
    );
    Ok(revision)
}

// ── recovery ────────────────────────────────────────────────────────────────

fn recover(dir: &Path) -> Result<Snapshot, StoreError> {
    let journal_path = dir.join(JOURNAL_FILE);
    let snapshot_path = dir.join(SNAPSHOT_FILE);
    let journal_bytes = read_regular(&journal_path, JOURNAL_MAX_BYTES)?;
    let snapshot_bytes = read_regular(&snapshot_path, MAX_SNAPSHOT_BYTES)?;

    let current = snapshot_bytes.as_deref().map(Snapshot::decode).transpose();

    let Some(journal_bytes) = journal_bytes else {
        return match current {
            Ok(snapshot) => Ok(snapshot.unwrap_or_else(Snapshot::empty)),
            Err(error) => Err(error),
        };
    };
    let target = Journal::decode(&journal_bytes)?;
    match &current {
        Ok(Some(snapshot)) if snapshot.revision >= target.revision => {
            let _ = std::fs::remove_file(&journal_path);
            return Ok(snapshot.clone());
        }
        _ => {}
    }
    // A valid journal is the durable intent, so complete it even when the
    // snapshot is missing or unreadable (atomic renames prevent a torn
    // snapshot, but a corrupt file must not strand a committed target).
    let target_bytes = target.encode()?;
    write_atomic(&snapshot_path, &target_bytes, MAX_SNAPSHOT_BYTES)?;
    let _ = std::fs::remove_file(&journal_path);
    Ok(target)
}

// ── filesystem helpers ──────────────────────────────────────────────────────

fn write_atomic(path: &Path, bytes: &[u8], cap: usize) -> Result<(), StoreError> {
    crate::atomic_io::save_bytes_atomic(path, bytes, cap).map_err(|_| StoreError::io())
}

fn read_regular(path: &Path, cap: usize) -> Result<Option<Vec<u8>>, StoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(StoreError::corrupt());
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(StoreError::io()),
    }
    match crate::atomic_io::load_bytes_capped(path, cap) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(crate::atomic_io::LoadError::NotFound) => Ok(None),
        Err(crate::atomic_io::LoadError::TooLarge { .. }) => Err(StoreError::bound()),
        Err(crate::atomic_io::LoadError::Io(_)) => Err(StoreError::io()),
    }
}

fn checksum(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(StoreError::corrupt)?;
        if end > self.bytes.len() {
            return Err(StoreError::corrupt());
        }
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| StoreError::corrupt())?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, StoreError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| StoreError::corrupt())?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

// ── locking ─────────────────────────────────────────────────────────────────

fn lock_namespace(path: &Path) -> Result<File, StoreError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        // Share mode 0 makes the open itself exclusive on Windows.
        options.share_mode(0);
    }
    let file = options.open(path).map_err(|error| {
        if is_lock_conflict(&error) {
            StoreError::locked()
        } else {
            StoreError::io()
        }
    })?;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::fs::{FlockOperation, flock};
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(errno) if errno == rustix::io::Errno::WOULDBLOCK => {
                return Err(StoreError::locked());
            }
            Err(_) => return Err(StoreError::io()),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
    {
        let _ = &file;
        return Err(StoreError::new(
            StoreErrorKind::Unsupported,
            "namespace locking is unsupported on this platform",
        ));
    }
    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    {
        Ok(file)
    }
}

#[cfg(windows)]
fn is_lock_conflict(error: &io::Error) -> bool {
    // ERROR_SHARING_VIOLATION: another handle opened the lock with no share.
    error.raw_os_error() == Some(32)
}

#[cfg(not(windows))]
fn is_lock_conflict(_error: &io::Error) -> bool {
    false
}
