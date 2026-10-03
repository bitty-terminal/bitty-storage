//! Atomic, durable file commit mechanics.
//!
//! Ported from the Core session save path and the plugin-store durable
//! commit: temp-plus-rename writes with fsync, stale-temp hygiene, and
//! capped loads. All errors are content-free (kinds, counts, and paths
//! only) so they are safe for logs.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ceiling::{MAX_SESSION_FILE_BYTES, SESSION_FILE_NAME};

/// Monotonic suffix for concurrent temp siblings of one destination.
static WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
/// (`<file>.tmp-<pid>-<seq>`).
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
        "{file_name}.tmp-{}-{}",
        std::process::id(),
        WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Removes stale `<file>.tmp.*` siblings best-effort (crashed-save litter).
///
/// Callers sweep BEFORE writing, never after the rename: a post-rename
/// sweep would delete a concurrent saver's live temp sibling.
pub fn clean_temp_siblings(path: &Path) {
    let Some(parent) = path.parent() else {
        return;
    };
    let prefix = path.file_name().map_or_else(
        || format!("{SESSION_FILE_NAME}.tmp."),
        |n| format!("{}.tmp.", n.to_string_lossy()),
    );
    // The `-` variant covers `unique_temp_sibling_for` litter as well:
    // both temp shapes share the `<file>.tmp` prefix.
    let dash_prefix = prefix.trim_end_matches('.');
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&prefix) || name.starts_with(dash_prefix) {
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
/// Rejects over-cap payloads before touching the filesystem and sweeps
/// crashed-save litter before writing.
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
    let temp = temp_sibling_for(path);
    let _ = std::fs::remove_file(&temp);
    let result = write_atomic_durably(path, bytes, &temp);
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Reads a file with a hard size cap.
///
/// A metadata pre-check avoids an unbounded allocation against a hostile
/// file; the post-read length check stays as the backstop for growth
/// between the check and the read.
pub fn load_bytes_capped(path: &Path, cap: usize) -> Result<Vec<u8>, LoadError> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.len() > cap as u64 {
            return Err(LoadError::TooLarge {
                actual: usize::try_from(meta.len()).unwrap_or(usize::MAX),
                limit: cap,
            });
        }
    }
    let bytes = std::fs::read(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            LoadError::NotFound
        } else {
            LoadError::Io(err.to_string())
        }
    })?;
    if bytes.len() > cap {
        return Err(LoadError::TooLarge {
            actual: bytes.len(),
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
    /// File exceeds the cap (whole file rejected).
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
