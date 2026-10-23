//! Anchored namespace backend (Linux/Android).
//!
//! The root and each namespace directory stay open as directory fds. All
//! state operations are `*at` relative to the namespace fd, final components
//! use `O_NOFOLLOW`, and temp files use `O_CREAT|O_EXCL`; see `crate::fs_at`.

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::PathBuf;

use crate::component::protocol::{
    MAX_BATCH_BYTES, MAX_BATCH_ROWS, MAX_KEY_BYTES, MAX_READ_BYTES, MAX_READ_ROWS, MAX_ROWS,
    MAX_SNAPSHOT_BYTES, MAX_VALUE_BYTES, Row, valid_key,
};
use crate::fs_at;

use super::{
    CommitOutcome, NamespaceName, RollbackOutcome, SnapshotPage, StoreError, StoreErrorKind,
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

/// Canonical storage root chosen by the host, held as a directory fd.
#[derive(Debug)]
pub struct StorageRoot {
    root: File,
}

impl StorageRoot {
    /// Creates and opens the storage root by walking each path component
    /// relative to an already-open directory fd. Symlinked ancestors and
    /// parent-directory components are refused.
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorKind::Io`] when the directory cannot be created or
    /// resolved, and [`StoreErrorKind::InvalidName`] when the resolved root
    /// is not a directory or its final component is a symlink.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        let root = fs_at::create_and_open_dir_tree(&path).map_err(map_namespace_error)?;
        Ok(Self { root })
    }

    /// Opens and exclusively locks one namespace, recovering a published
    /// journal first.
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorKind::InvalidName`] for a bad name or symlinked
    /// namespace, [`StoreErrorKind::Corrupt`] for a symlinked or non-regular
    /// state member, [`StoreErrorKind::Locked`] when another process holds
    /// the lock, [`StoreErrorKind::Io`] for pre-replay filesystem failures,
    /// and [`StoreErrorKind::Uncertain`] when a valid journal could not be
    /// fully replayed or the namespace stopped being attached. An uncertain
    /// open must be retried as a fresh open after the filesystem condition is
    /// repaired.
    pub fn open_namespace(&self, name: &NamespaceName) -> Result<Namespace, StoreError> {
        let namespace = name.as_str();
        fs_at::create_dir_at(&self.root, namespace).map_err(map_namespace_error)?;
        let dir = fs_at::open_dir_at(&self.root, namespace).map_err(map_namespace_error)?;
        // Validate every fixed state member before any content is read. A
        // symlink, FIFO, device, or directory is refused even for `previous`,
        // which is not read on the open path.
        for member in [SNAPSHOT_FILE, PREVIOUS_FILE, JOURNAL_FILE] {
            fs_at::regular_or_absent(&dir, member).map_err(map_state_error)?;
        }
        let lock = fs_at::open_lock_at(&dir, LOCK_FILE).map_err(map_lock_error)?;
        for stem in [JOURNAL_FILE, PREVIOUS_FILE, SNAPSHOT_FILE] {
            fs_at::clean_temp_siblings_at(&dir, stem).map_err(|_| StoreError::io())?;
        }
        let snapshot = recover_then_check_attached(&dir, &self.root, namespace, || {})?;
        let root = self.root.try_clone().map_err(|_| StoreError::io())?;
        Ok(Namespace {
            name: name.clone(),
            root,
            dir,
            _lock: lock,
            snapshot,
        })
    }
}

/// One open, locked namespace anchored to its directory fd.
#[derive(Debug)]
pub struct Namespace {
    name: NamespaceName,
    root: File,
    dir: File,
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

    /// Best-effort attachment check: returns `Uncertain` when the namespace
    /// directory fd is no longer the directory currently named under the
    /// storage root (renamed, removed, or replaced by a symlink/other entry).
    /// The stat pair is a detection point, not a lease: the pathname can be
    /// replaced again immediately after this call returns. The caller must
    /// reopen and reread rather than retrying against this handle.
    pub(crate) fn ensure_attached(&self) -> Result<(), StoreError> {
        match fs_at::directory_matches(&self.root, self.name.as_str(), &self.dir) {
            Ok(true) => Ok(()),
            Ok(false) => Err(StoreError::uncertain()),
            Err(_) => Err(StoreError::uncertain()),
        }
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
        self.ensure_attached()?;
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
    /// [`StoreErrorKind::Bound`] for a row/byte cap,
    /// [`StoreErrorKind::Io`] for a pre-rename durable-write failure, and
    /// [`StoreErrorKind::Uncertain`] when publication, cleanup, recovery, or
    /// attachment durability cannot be confirmed. The public server evicts an
    /// uncertain namespace; callers must reopen before retrying.
    pub fn commit(
        &mut self,
        expected_revision: u64,
        upserts: Vec<Row>,
        deletes: Vec<String>,
    ) -> Result<CommitOutcome, StoreError> {
        self.ensure_attached()?;
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
        self.publish_then_check_attached(
            &candidate_bytes,
            &current_bytes,
            self.snapshot.revision == 0,
            || {},
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
    /// [`StoreErrorKind::Corrupt`] for an invalid previous image,
    /// [`StoreErrorKind::Io`] for a pre-rename durable-write failure, and
    /// [`StoreErrorKind::Uncertain`] when publication, cleanup, recovery, or
    /// attachment durability cannot be confirmed. Callers must reopen before
    /// retrying.
    pub fn rollback(&mut self, expected_revision: u64) -> Result<RollbackOutcome, StoreError> {
        self.ensure_attached()?;
        if expected_revision != self.snapshot.revision {
            return Err(StoreError::stale());
        }
        let previous_bytes = read_state(&self.dir, PREVIOUS_FILE, MAX_SNAPSHOT_BYTES)?
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
        self.publish_then_check_attached(&candidate_bytes, &current_bytes, false, || {})?;
        self.snapshot = candidate;
        Ok(RollbackOutcome {
            revision,
            restored_revision: previous.revision,
            total_rows: u32::try_from(self.snapshot.rows.len()).map_err(|_| StoreError::bound())?,
            total_bytes: self.snapshot.value_bytes(),
        })
    }

    /// Publishes `journal -> previous -> snapshot`. Any failed cleanup after
    /// publication is uncertain: recovery may still need the journal to
    /// establish the committed state.
    fn publish(
        &self,
        candidate_bytes: &[u8],
        current_bytes: &[u8],
        first_commit: bool,
    ) -> Result<(), StoreError> {
        let journal = Journal::encode(candidate_bytes)?;
        let result: Result<(), StoreError> = (|| {
            fs_at::write_atomic_unique(
                &self.dir,
                JOURNAL_FILE,
                &journal,
                JOURNAL_MAX_BYTES,
                "journal",
            )
            .map_err(map_write_error)?;
            if first_commit {
                // A prior namespace lifetime may have left a previous image;
                // revision 0 must not be rollback-able.
                match fs_at::remove_file_durably_at(&self.dir, PREVIOUS_FILE) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => return Err(StoreError::uncertain()),
                }
            } else {
                fs_at::write_atomic_unique(
                    &self.dir,
                    PREVIOUS_FILE,
                    current_bytes,
                    MAX_SNAPSHOT_BYTES,
                    "previous",
                )
                .map_err(map_write_error)?;
            }
            fs_at::write_atomic_unique(
                &self.dir,
                SNAPSHOT_FILE,
                candidate_bytes,
                MAX_SNAPSHOT_BYTES,
                "snapshot",
            )
            .map_err(map_write_error)?;
            Ok(())
        })();
        if result.is_err() {
            if result
                .as_ref()
                .is_err_and(|error| error.kind() != StoreErrorKind::Uncertain)
            {
                if let Err(cleanup) = fs_at::remove_file_durably_at(&self.dir, JOURNAL_FILE) {
                    if cleanup.kind() != io::ErrorKind::NotFound {
                        return Err(StoreError::uncertain());
                    }
                }
            }
            return result;
        }
        self.ensure_attached()
            .map_err(|_| StoreError::uncertain())?;
        match fs_at::remove_file_durably_at(&self.dir, JOURNAL_FILE) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::uncertain()),
        }
        self.ensure_attached().map_err(|_| StoreError::uncertain())
    }

    fn publish_then_check_attached(
        &self,
        candidate_bytes: &[u8],
        current_bytes: &[u8],
        first_commit: bool,
        after_publish: impl FnOnce(),
    ) -> Result<(), StoreError> {
        self.publish(candidate_bytes, current_bytes, first_commit)?;
        after_publish();
        self.ensure_attached().map_err(|_| StoreError::uncertain())
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

fn recover(dir: &File, root: &File, namespace: &str) -> Result<Snapshot, StoreError> {
    let journal_bytes = read_state(dir, JOURNAL_FILE, JOURNAL_MAX_BYTES)?;
    let snapshot_bytes = match read_state(dir, SNAPSHOT_FILE, MAX_SNAPSHOT_BYTES) {
        Ok(bytes) => bytes,
        // A durable journal names a target that may already be installed.
        // Without the snapshot bytes we cannot tell whether it became
        // visible, so an I/O failure must not invite a blind retry from a
        // cached revision. Structural failures keep their typed kind.
        Err(error) if journal_bytes.is_some() && error.kind() == StoreErrorKind::Io => {
            return Err(StoreError::uncertain());
        }
        Err(error) => return Err(error),
    };

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
            ensure_namespace_attached(root, namespace, dir)?;
            fs_at::remove_file_durably_at(dir, JOURNAL_FILE)
                .map_err(|_| StoreError::uncertain())?;
            return Ok(snapshot.clone());
        }
        _ => {}
    }
    // Complete step 2 of the interrupted commit before publishing step 3, so
    // `previous` names the pre-commit state after recovery and a later
    // rollback cannot skip a revision. The write is idempotent when step 2
    // already ran. With no snapshot (first commit), a stale `previous` from a
    // prior namespace lifetime must be removed so revision 1 is not
    // rollback-able to unrelated state. An unreadable snapshot leaves
    // `previous` untouched because the pre-commit state is unknowable.
    //
    // The journal is already the durable intent, so every failure while
    // completing it is uncertain: the target may become visible on the next
    // open even though this recovery attempt failed. Only pre-replay reads
    // and journal decoding keep their typed corrupt/io classification.
    match (&current, snapshot_bytes.as_deref()) {
        (Ok(Some(_)), Some(bytes)) => {
            fs_at::write_atomic_unique(dir, PREVIOUS_FILE, bytes, MAX_SNAPSHOT_BYTES, "previous")
                .map_err(|_| StoreError::uncertain())?;
        }
        (Ok(None), _) => match fs_at::remove_file_at(dir, PREVIOUS_FILE) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::uncertain()),
        },
        _ => {}
    }
    // A valid journal is the durable intent, so complete it even when the
    // snapshot is missing or unreadable (atomic renames prevent a torn
    // snapshot, but a corrupt file must not strand a committed target).
    let target_bytes = target.encode()?;
    fs_at::write_atomic_unique(
        dir,
        SNAPSHOT_FILE,
        &target_bytes,
        MAX_SNAPSHOT_BYTES,
        "snapshot",
    )
    .map_err(|_| StoreError::uncertain())?;
    ensure_namespace_attached(root, namespace, dir)?;
    fs_at::remove_file_durably_at(dir, JOURNAL_FILE).map_err(|_| StoreError::uncertain())?;
    Ok(target)
}

fn recover_then_check_attached(
    dir: &File,
    root: &File,
    namespace: &str,
    after_recovery: impl FnOnce(),
) -> Result<Snapshot, StoreError> {
    let snapshot = recover(dir, root, namespace)?;
    after_recovery();
    ensure_namespace_attached(root, namespace, dir)?;
    Ok(snapshot)
}

fn ensure_namespace_attached(root: &File, namespace: &str, dir: &File) -> Result<(), StoreError> {
    match fs_at::directory_matches(root, namespace, dir) {
        Ok(true) => Ok(()),
        Ok(false) => Err(StoreError::uncertain()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(StoreError::uncertain()),
        Err(_) => Err(StoreError::uncertain()),
    }
}

// ── error mapping ───────────────────────────────────────────────────────────

fn map_namespace_error(error: io::Error) -> StoreError {
    match error.kind() {
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => StoreError::invalid_name(),
        _ => StoreError::io(),
    }
}

fn map_state_error(error: io::Error) -> StoreError {
    match error.kind() {
        io::ErrorKind::InvalidInput => StoreError::corrupt(),
        io::ErrorKind::InvalidData => StoreError::bound(),
        _ => StoreError::io(),
    }
}

fn map_lock_error(error: io::Error) -> StoreError {
    match error.kind() {
        io::ErrorKind::WouldBlock => StoreError::locked(),
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => StoreError::corrupt(),
        _ => StoreError::io(),
    }
}

fn map_write_error(error: io::Error) -> StoreError {
    if fs_at::is_uncertain_durability_error(&error) {
        return StoreError::uncertain();
    }
    match error.kind() {
        io::ErrorKind::InvalidInput => StoreError::bound(),
        _ => StoreError::io(),
    }
}

fn read_state(dir: &File, name: &str, cap: usize) -> Result<Option<Vec<u8>>, StoreError> {
    fs_at::read_file_at(dir, name, cap).map_err(map_state_error)
}

// ── codec helpers ───────────────────────────────────────────────────────────

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::store::NamespaceName;

    #[test]
    fn replacement_after_publish_is_uncertain_not_acknowledged() {
        let root_path = std::env::temp_dir().join(format!("attached-race-{}", std::process::id()));
        let detached = std::env::temp_dir().join(format!("detached-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root_path);
        let _ = std::fs::remove_dir_all(&detached);
        std::fs::create_dir_all(&root_path).unwrap();
        std::fs::create_dir_all(&detached).unwrap();
        let root = StorageRoot::new(&root_path).unwrap();
        let mut namespace = root
            .open_namespace(&NamespaceName::parse("race").unwrap())
            .unwrap();
        namespace
            .commit(0, Vec::new(), Vec::new())
            .expect("initial commit");
        let candidate = Snapshot {
            revision: 2,
            rows: BTreeMap::new(),
        }
        .encode()
        .unwrap();
        let current = Snapshot {
            revision: 1,
            rows: BTreeMap::new(),
        }
        .encode()
        .unwrap();

        let error = namespace
            .publish_then_check_attached(&candidate, &current, false, || {
                std::fs::rename(root_path.join("race"), root_path.join("race-detached")).unwrap();
                std::os::unix::fs::symlink(&detached, root_path.join("race")).unwrap();
            })
            .expect_err("replacement after publish must not be acknowledged");
        assert_eq!(error.kind(), StoreErrorKind::Uncertain);
        assert!(root_path.join("race-detached/snapshot").exists());
        let _ = std::fs::remove_dir_all(root_path);
        let _ = std::fs::remove_dir_all(detached);
    }

    #[test]
    fn replacement_after_open_recovery_is_uncertain_not_acknowledged() {
        let root_path = std::env::temp_dir().join(format!("recovery-race-{}", std::process::id()));
        let detached_path =
            std::env::temp_dir().join(format!("recovery-detached-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root_path);
        let _ = std::fs::remove_dir_all(&detached_path);
        std::fs::create_dir_all(&root_path).unwrap();
        std::fs::create_dir_all(&detached_path).unwrap();
        let root = StorageRoot::new(&root_path).unwrap();
        let name = NamespaceName::parse("recovery").unwrap();
        let opened = root.open_namespace(&name).unwrap();
        drop(opened);
        let dir = fs_at::open_dir_at(&root.root, name.as_str()).unwrap();

        let result = recover_then_check_attached(&dir, &root.root, name.as_str(), || {
            std::fs::rename(
                root_path.join("recovery"),
                root_path.join("recovery-detached"),
            )
            .unwrap();
            std::os::unix::fs::symlink(&detached_path, root_path.join("recovery")).unwrap();
        });
        assert_eq!(
            result
                .expect_err("must not acknowledge replaced namespace")
                .kind(),
            StoreErrorKind::Uncertain
        );
        let _ = std::fs::remove_dir_all(root_path);
        let _ = std::fs::remove_dir_all(detached_path);
    }
}
