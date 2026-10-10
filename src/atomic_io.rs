//! Atomic, durable file commit mechanics.
//!
//! Ported from the Core session save path and the plugin-store durable
//! commit: temp-plus-rename writes with fsync, stale-temp hygiene, and
//! capped loads. All errors are content-free (kinds, counts, and paths
//! only) so they are safe for logs.
//!
//! # Core duplication decision (storage#13, CTX-0006): option 2
//!
//! Core keeps its own `write_atomic_durably` in
//! `crates/bitty-runtime/src/plugin_runtime/fs.rs` as the install-path
//! special case: it is generic over the Core-owned `FileSystem` trait
//! (`NativeFileSystem` plus `FakeFileSystem` for fault injection) and is
//! called only by `write_index_with_fs` in `resolution.rs` for the plugin
//! index file. This crate keeps the generic std-only implementation here
//! (`save_bytes_atomic` plus `write_atomic_durably` below). There is no
//! shared trait and no dependency edge in either direction: this crate
//! never imports Core, and Core library crates never import this crate
//! (composition-root wiring lives in `bitty-terminal/src/storage_backends.rs`
//! behind the Core-owned `SessionFileBackend` and `KvCommitBackend` seams,
//! proven by the W-146 rewire). A mirror trait published here would duplicate
//! the seam without removing the function duplication, so option 1 (Core owns
//! a generic atomic-write trait implemented here) is rejected.
//!
//! # Temp-sweep parity analysis against the Core copy
//!
//! The commit contract is identical on both sides: write the temp, fsync the
//! temp, rename the temp onto the destination, remove the temp on any
//! failure, and never modify or delete the destination on failure (the
//! TERM-RUN-003 and PLUG-REG-010 guarantee). The intentional differences are:
//!
//! - Filesystem abstraction: Core commits through `FileSystem` so tests can
//!   inject write, sync, and rename failures via `FakeFileSystem`; this crate
//!   commits through `std::fs` directly because it takes no Core dependency
//!   and needs no injection seam. Identical behavior is pinned from opposite
//!   sides: Core asserts operation ordering through recorded writes, syncs,
//!   renames, and removals, while this crate asserts the resulting filesystem
//!   outcomes (destination preserved, temp gone).
//! - Temp naming: Core uses one transaction temp per index write with a
//!   process-global sequence; this crate uses [`unique_temp_sibling_for`]
//!   (process id plus thread id plus sequence) so concurrent savers of one
//!   path never share a temp, and keeps [`temp_sibling_for`] only as the
//!   legacy single-writer name. Both sides generate a fresh temp per call.
//! - Stale-temp sweep: only [`save_bytes_atomic`] sweeps, via
//!   [`clean_temp_siblings`] before writing, age-gated by
//!   [`STALE_TEMP_AGE_SECS`] so a concurrent saver's live temp is never
//!   removed, matching both the legacy and the unique temp prefixes, and
//!   never sweeping after the rename. The low-level [`write_atomic_durably`]
//!   on either side performs no sweep. Core has no sweep layer for its index
//!   path today: that is the F5 drift. The required Core-side follow-up is
//!   tracked from #1629 (not done here; Core is untouched): either add a
//!   pre-write sweep for the index temp prefix or record the omission as an
//!   explicit install-path decision. Any Core sweep must run before writing,
//!   never after the rename.
//! - Durability: this crate syncs the temp file before the rename and then
//!   best-effort syncs the parent directory after the rename; Core syncs the
//!   temp file before the rename through `FileSystem::sync_file` with no
//!   directory sync. Success on both sides means the temp bytes reached disk
//!   before the rename.
//! - Permissions: this crate creates the temp with mode 0600 on Unix and
//!   re-asserts it before the first byte; Core writes through
//!   `NativeFileSystem::write_file` under the store directory permissions.
//!   This side holds secret-capable session and KV payloads, so the tighter
//!   mode stays here.
//! - Caps: this crate rejects over-cap payloads in [`save_bytes_atomic`]
//!   before touching the filesystem; Core rejects over-ceiling indexes
//!   during encoding before calling its commit. Both fail closed pre-write.
//! - Errors: this crate reports [`IoError`] and [`LoadError`] without
//!   contents; Core maps failures to content-free denials. A failed commit
//!   on either side leaves the previous destination intact.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ceiling::{MAX_SESSION_FILE_BYTES, SESSION_FILE_NAME};

/// Monotonic suffix for concurrent temp siblings of one destination.
static WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Minimum temp-sibling age before the pre-write sweep treats it as crash
/// litter. Live writers hold their temps for milliseconds, so an hour keeps
/// the sweep from ever deleting a concurrent saver's live temp while still
/// reclaiming crashed-save litter on later saves.
pub const STALE_TEMP_AGE_SECS: u64 = 3_600;

/// Filesystem failure with the operation context only (never contents).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoError {
    context: &'static str,
    message: String,
}

impl IoError {
    #[must_use]
    pub fn new(context: &'static str, message: String) -> Self {
        Self { context, message }
    }

    #[must_use]
    pub fn context(&self) -> &'static str {
        self.context
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.context, self.message)
    }
}

impl std::error::Error for IoError {}

fn io_error(context: &'static str, err: std::io::Error) -> IoError {
    IoError::new(context, err.to_string())
}

/// Temp sibling for an atomic save (`<file>.tmp.<pid>`).
#[must_use]
pub fn temp_sibling_for(path: &Path) -> PathBuf {
    let name = path.file_name().map_or_else(
        || SESSION_FILE_NAME.into(),
        |n| n.to_string_lossy().into_owned(),
    );
    path.with_file_name(format!("{name}.tmp.{}", std::process::id()))
}

/// Unique temp sibling for concurrent writers
/// (`<file>.tmp-<pid>-<thread>-<seq>`).
///
/// Process id plus thread id plus a process-global atomic counter makes
/// the name unique per writer with std only: two threads in one process
/// saving the same path never share a temp file, so neither truncates
/// nor renames the other's bytes.
#[must_use]
pub fn unique_temp_sibling_for(path: &Path) -> PathBuf {
    let Some(parent) = path.parent() else {
        return temp_sibling_for(path);
    };
    let file_name = path.file_name().map_or_else(
        || SESSION_FILE_NAME.into(),
        |n| n.to_string_lossy().into_owned(),
    );
    parent.join(format!(
        "{file_name}.tmp-{}-{:?}-{}",
        std::process::id(),
        std::thread::current().id(),
        WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Removes stale `<file>.tmp.*` siblings best-effort (crashed-save litter).
///
/// Age-gated: only temps older than [`STALE_TEMP_AGE_SECS`] are removed, so
/// the sweep never deletes a concurrent saver's live temp. Callers sweep
/// BEFORE writing, never after the rename: a post-rename sweep would race
/// a concurrent saver's live temp sibling.
pub fn clean_temp_siblings(path: &Path) {
    let Some(parent) = path.parent() else {
        return;
    };
    let stem = path.file_name().map_or_else(
        || SESSION_FILE_NAME.into(),
        |n| n.to_string_lossy().into_owned(),
    );
    let dot_prefix = format!("{stem}.tmp.");
    let dash_prefix = format!("{stem}.tmp-");
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.starts_with(&dot_prefix) || name.starts_with(&dash_prefix)) {
            continue;
        }
        // Fail-closed toward keeping: unknown age (missing/clocked-skewed
        // mtime) is treated as live, never as litter.
        let stale = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .map(|mtime| {
                now.duration_since(mtime)
                    .is_ok_and(|age| age.as_secs() >= STALE_TEMP_AGE_SECS)
            })
            .unwrap_or(false);
        if stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Writes `bytes` to `temp`, fsyncs, then atomically renames onto
/// `destination`. A failed commit removes the temp and leaves the previous
/// destination untouched (partial writes are never observable).
pub fn write_atomic_durably(destination: &Path, data: &[u8], temp: &Path) -> Result<(), IoError> {
    if let Some(parent) = destination.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| io_error("create destination dir", e))?;
        }
    }
    let write_result = (|| -> Result<(), std::io::Error> {
        use std::io::Write as _;
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt as _;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(temp)?
        };
        #[cfg(not(unix))]
        let mut file = std::fs::File::create(temp)?;
        #[cfg(unix)]
        {
            // Defense in depth: the mode is already 0600 from create;
            // re-assert before the first byte so the sync covers both.
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(temp, destination)?;
        if let Some(parent) = destination.parent() {
            if !parent.as_os_str().is_empty() {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = std::fs::remove_file(temp);
        return Err(io_error("atomic commit", err));
    }
    Ok(())
}

/// Writes `bytes` atomically to `path` (temp + fsync + rename, mode 0600).
///
/// Rejects over-cap payloads before touching the filesystem, sweeps
/// aged crashed-save litter before writing (live concurrent temps are
/// never swept), and commits through a per-writer unique temp so
/// concurrent savers of the same path cannot collide.
pub fn save_bytes_atomic(path: &Path, bytes: &[u8], cap: usize) -> Result<(), IoError> {
    if bytes.len() > cap {
        return Err(IoError::new(
            "payload exceeds ceiling",
            format!("{} > {cap}", bytes.len()),
        ));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| io_error("create destination dir", e))?;
        }
    }
    clean_temp_siblings(path);
    let temp = unique_temp_sibling_for(path);
    // Our name is unique among live writers; dropping a stale twin only
    // covers a pid-reusing predecessor's litter under the same name.
    let _ = std::fs::remove_file(&temp);
    let result = write_atomic_durably(path, bytes, &temp);
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Reads a file with a hard size cap.
///
/// Streams through `take(cap + 1)` so a large or hostile file never
/// causes an unbounded allocation: at most `cap + 1` bytes are buffered
/// and at most `cap + 1` bytes are read. An over-cap file is rejected
/// fail-closed after the first excess byte; the reported `actual`
/// saturates at `cap + 1` and means "over cap", never an exact size.
pub fn load_bytes_capped(path: &Path, cap: usize) -> Result<Vec<u8>, LoadError> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            LoadError::NotFound
        } else {
            LoadError::Io(err.to_string())
        }
    })?;
    let limit = (cap as u64).saturating_add(1);
    let mut take = file.take(limit);
    let mut bytes = Vec::new();
    take.read_to_end(&mut bytes)
        .map_err(|err| LoadError::Io(err.to_string()))?;
    if bytes.len() > cap {
        // Over cap: stop after the first excess byte. `actual` saturates
        // at `cap + 1` ("over cap") so a multi-GB file never triggers
        // multi-GB I/O just to report its size.
        return Err(LoadError::TooLarge {
            actual: cap.saturating_add(1),
            limit: cap,
        });
    }
    Ok(bytes)
}

/// Capped-load outcome: missing files are a quiet clean start, never an
/// error payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// No file exists: the caller starts clean.
    NotFound,
    /// File exceeds the cap (whole file rejected). `actual` saturates at
    /// `limit + 1` and means "over cap", never the exact file size.
    TooLarge { actual: usize, limit: usize },
    /// Filesystem failure (message only, never contents).
    Io(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "file not found"),
            Self::TooLarge { actual, limit } => {
                write!(f, "file too large ({actual} > {limit})")
            }
            Self::Io(msg) => write!(f, "io error ({msg})"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Session-file commit: atomic write capped at
/// [`MAX_SESSION_FILE_BYTES`](crate::ceiling::MAX_SESSION_FILE_BYTES).
pub fn save_session_bytes(path: &Path, bytes: &[u8]) -> Result<(), IoError> {
    save_bytes_atomic(path, bytes, MAX_SESSION_FILE_BYTES)
}

/// Session-file load capped at
/// [`MAX_SESSION_FILE_BYTES`](crate::ceiling::MAX_SESSION_FILE_BYTES).
pub fn load_session_bytes(path: &Path) -> Result<Vec<u8>, LoadError> {
    load_bytes_capped(path, MAX_SESSION_FILE_BYTES)
}
