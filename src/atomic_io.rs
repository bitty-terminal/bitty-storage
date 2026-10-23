//! Atomic, durable file commit mechanics.
//!
//! Ported from the Core session save path and the plugin-store durable
//! commit: temp-plus-rename writes with fsync, stale-temp hygiene, and
//! capped loads. All errors are content-free (kinds and counts only) so they
//! are safe for logs.
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
//! # Path-containment hardening (component server)
//!
//! On Linux/Android the commit path opens the destination parent once as a
//! directory fd and performs `openat`/`renameat` relative to it:
//!
//! - the temp is created `O_CREAT|O_EXCL|O_NOFOLLOW` (an existing symlink,
//!   regular file, FIFO, or device is refused, never followed/truncated);
//! - `write_atomic_durably` requires the temp to share the destination parent;
//! - the pre-write sweep and capped load are also `*at`-anchored, and a load
//!   rejects a symlink/non-regular final component;
//! - a racing namespace/ancestor replacement therefore cannot redirect the
//!   commit outside the opened directory. The component store additionally
//!   verifies the namespace fd is still the directory named under the root
//!   before serving or mutating it.
//!
//! On other platforms the low-level helper uses exclusive creation
//! (`create_new`) but remains path-based; the executable component store is
//! Linux/Android-only and fails closed elsewhere, so this path is limited to
//! the crate's generic FileBackend/KV users.
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
//!   commits through `std::fs` plus `*at` directory-fd calls on Linux/Android
//!   because it takes no Core dependency and needs no injection seam.
//!   Identical behavior is pinned from opposite sides: Core asserts operation
//!   ordering through recorded writes, syncs, renames, and removals, while
//!   this crate asserts the resulting filesystem outcomes (destination
//!   preserved, temp gone).
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
//!   syncs the parent directory after the rename; Core syncs the
//!   temp file before the rename through `FileSystem::sync_file` with no
//!   directory sync. Success on both sides means the temp bytes reached disk
//!   before the rename.
//! - Permissions: this crate creates the temp with mode 0600 (Linux/Android
//!   through the anchored `openat`); the non-Linux helper re-asserts 0600
//!   before the first byte. Core writes through
//!   `NativeFileSystem::write_file` under the store directory permissions.
//!   This side holds secret-capable session and KV payloads, so the tighter
//!   mode stays here.
//! - Caps: this crate rejects over-cap payloads in [`save_bytes_atomic`]
//!   before touching the filesystem; Core rejects over-ceiling indexes
//!   during encoding before calling its commit. Both fail closed pre-write.
//! - Errors: this crate reports [`IoError`] and [`LoadError`] without
//!   contents; Core maps failures to content-free denials. A pre-rename
//!   failure leaves the destination intact. Once rename succeeds,
//!   a later directory-sync failure is reported as uncertain because the new
//!   destination may already be visible.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ceiling::{MAX_SESSION_FILE_BYTES, SESSION_FILE_NAME};
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::fs_at;

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
    uncertain: bool,
}

impl IoError {
    #[must_use]
    pub fn new(context: &'static str, message: String) -> Self {
        Self {
            context,
            message,
            uncertain: false,
        }
    }

    fn uncertain(context: &'static str, message: String) -> Self {
        Self {
            context,
            message,
            uncertain: true,
        }
    }

    #[must_use]
    pub fn context(&self) -> &'static str {
        self.context
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether rename may have installed the new destination but durability
    /// could not be confirmed. Do not blindly retry from a cached snapshot.
    #[must_use]
    pub const fn is_uncertain(&self) -> bool {
        self.uncertain
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

#[cfg(any(target_os = "linux", target_os = "android"))]
fn atomic_error(err: std::io::Error) -> IoError {
    if fs_at::is_uncertain_commit_error(&err) {
        IoError::uncertain("atomic commit", err.to_string())
    } else {
        io_error("atomic commit", err)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parent_dir_owned(path: &Path) -> PathBuf {
    parent_dir(path).to_path_buf()
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
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let parent = parent_dir(path);
        let Ok(dir) = fs_at::open_dir_path(parent) else {
            return;
        };
        let stem = path.file_name().map_or_else(
            || SESSION_FILE_NAME.into(),
            |name| name.to_string_lossy().into_owned(),
        );
        let _ = fs_at::clean_temp_siblings_at(&dir, &stem);
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        clean_temp_siblings_path(path);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn clean_temp_siblings_path(path: &Path) {
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
/// `destination`. A pre-rename failure preserves the old destination. A
/// post-rename directory-sync failure returns an error with
/// [`IoError::is_uncertain`] set because the rename may already be visible.
///
/// On Linux/Android the destination parent is opened as a directory fd and
/// the temp is created `O_CREAT|O_EXCL|O_NOFOLLOW`, so a pre-planted symlink
/// or a racing parent replacement cannot redirect the write. `temp` must
/// share the destination parent. Other platforms use exclusive creation only
/// (the component store itself is Linux/Android-only and fails closed
/// elsewhere).
pub fn write_atomic_durably(destination: &Path, data: &[u8], temp: &Path) -> Result<(), IoError> {
    if let Some(parent) = destination.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| io_error("create destination dir", e))?;
        }
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        write_atomic_durably_at(destination, data, temp)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        write_atomic_durably_path(destination, data, temp)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn write_atomic_durably_at(destination: &Path, data: &[u8], temp: &Path) -> Result<(), IoError> {
    let destination_parent = parent_dir_owned(destination);
    let temp_parent = parent_dir_owned(temp);
    if destination_parent != temp_parent {
        return Err(IoError::new(
            "atomic commit",
            "temp must share destination parent".to_owned(),
        ));
    }
    let dir = fs_at::open_dir_path(&destination_parent)
        .map_err(|error| io_error("open destination dir", error))?;
    let destination_name = destination
        .file_name()
        .ok_or_else(|| IoError::new("atomic commit", "destination has no file name".to_owned()))?;
    let temp_name = temp
        .file_name()
        .ok_or_else(|| IoError::new("atomic commit", "temp has no file name".to_owned()))?;
    fs_at::write_atomic_named(&dir, destination_name, temp_name, data, usize::MAX)
        .map_err(atomic_error)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn write_atomic_durably_path(destination: &Path, data: &[u8], temp: &Path) -> Result<(), IoError> {
    let mut renamed = false;
    let write_result = (|| -> Result<(), std::io::Error> {
        use std::io::Write as _;
        // `create_new` is O_CREAT|O_EXCL, so an existing symlink or regular
        // file at the temp name is refused instead of followed/truncated.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(temp, destination)?;
        renamed = true;
        if let Some(parent) = destination.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::File::open(parent)?.sync_all()?;
            }
        }
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = std::fs::remove_file(temp);
        return Err(if renamed {
            IoError::uncertain("atomic commit", err.to_string())
        } else {
            io_error("atomic commit", err)
        });
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
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let parent = parent_dir_owned(path);
        let dir = fs_at::open_dir_path(&parent)
            .map_err(|error| io_error("open destination dir", error))?;
        let name = path.file_name().ok_or_else(|| {
            IoError::new("atomic commit", "destination has no file name".to_owned())
        })?;
        let stem = name.to_string_lossy().into_owned();
        let _ = fs_at::clean_temp_siblings_at(&dir, &stem);
        fs_at::write_atomic_unique(&dir, name, bytes, cap, &stem).map_err(atomic_error)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        clean_temp_siblings_path(path);
        let temp = unique_temp_sibling_for(path);
        let result = write_atomic_durably_path(path, bytes, &temp);
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }
}

/// Reads a file with a hard size cap.
///
/// Streams through `take(cap + 1)` so a large or hostile file never
/// causes an unbounded allocation: at most `cap + 1` bytes are buffered
/// and at most `cap + 1` bytes are read. An over-cap file is rejected
/// fail-closed after the first excess byte; the reported `actual`
/// saturates at `cap + 1` and means "over cap", never an exact size.
pub fn load_bytes_capped(path: &Path, cap: usize) -> Result<Vec<u8>, LoadError> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        load_bytes_capped_at(path, cap)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        load_bytes_capped_path(path, cap)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn load_bytes_capped_at(path: &Path, cap: usize) -> Result<Vec<u8>, LoadError> {
    let parent = parent_dir_owned(path);
    let dir = fs_at::open_dir_path(&parent).map_err(|error| LoadError::Io(error.to_string()))?;
    let name = path
        .file_name()
        .ok_or_else(|| LoadError::Io("path has no file name".to_owned()))?;
    match fs_at::read_file_at(&dir, name, cap) {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(LoadError::NotFound),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => Err(LoadError::TooLarge {
            actual: cap.saturating_add(1),
            limit: cap,
        }),
        Err(error) => Err(LoadError::Io(error.to_string())),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn load_bytes_capped_path(path: &Path, cap: usize) -> Result<Vec<u8>, LoadError> {
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
