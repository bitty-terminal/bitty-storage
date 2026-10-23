//! Directory-fd anchored filesystem operations (Linux/Android).
//!
//! The component store never trusts a path after the namespace directory has
//! been opened. Every operation below is relative to an already-open directory
//! fd, uses `O_NOFOLLOW` on the final component, and creates temporary files
//! with `O_CREAT|O_EXCL` so a pre-planted symlink is never followed. A racing
//! rename or replacement of an ancestor therefore cannot redirect a read,
//! write, rename, or unlink outside the opened directory.
//!
//! Pathname checks here (`directory_matches`, the lock replacement check) are
//! detection points, not leases or acknowledgements. They prove the
//! device/inode identity at the instant of the `statat` call; a racing
//! rename/replacement after that call is not prevented by them. The fd
//! anchoring remains in force either way, so a late replacement can only
//! detach the pathname, never redirect already-issued operations.
//!
//! This module is deliberately Linux/Android only. Other platforms fail
//! closed in `component::store` rather than falling back to path-based state
//! operations for the component.

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::mem::MaybeUninit;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rustix::fs::{
    AtFlags, FileType, FlockOperation, Mode, OFlags, RawDir, flock, fstat, fsync, mkdirat, open,
    openat, renameat, statat, unlinkat,
};
use rustix::io::Errno;
use rustix::path::Arg;

/// Minimum temp-sibling age before the anchored sweep treats it as crash
/// litter. Live writers hold their temps for milliseconds.
pub(crate) const STALE_TEMP_AGE_SECS: u64 = 3_600;

/// Bounded retries when an attacker has pre-created a candidate temp name.
const TEMP_ATTEMPTS: usize = 16;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct DirectorySyncFailure;

impl std::fmt::Display for DirectorySyncFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("directory fsync failed after mutation")
    }
}

impl std::error::Error for DirectorySyncFailure {}

/// Returns whether a mutation (rename or unlink) completed but the following
/// directory fsync failed, so its durability could not be confirmed.
pub(crate) fn is_uncertain_durability_error(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<DirectorySyncFailure>())
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

/// Opens a directory path itself with `O_DIRECTORY|O_NOFOLLOW`. Used once for
/// the host-chosen storage root; every later operation is `*at` relative.
pub(crate) fn open_dir_path(path: &Path) -> io::Result<File> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(map_final_component_error)?;
    Ok(File::from(fd))
}

/// Opens a directory path for the crate's generic (non-component) helpers.
///
/// A final symlink to a directory is followed, matching normal path semantics
/// for caller-owned state directories (`FileBackend`, session, KV). Every
/// later operation is still fd-relative, so replacing an ancestor after this
/// open cannot redirect those operations. The component store never uses this
/// opener; it stays no-follow and anchored through [`open_dir_path`].
pub(crate) fn open_dir_path_following(path: &Path) -> io::Result<File> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| match error {
        Errno::LOOP | Errno::MLINK | Errno::NOTDIR => invalid("symlink or non-directory"),
        other => other.into(),
    })?;
    Ok(File::from(fd))
}

/// Creates and opens a directory path by walking each component from an
/// already-open `/` or `.` directory. Symlinked components and `..` are
/// refused; no canonicalize-then-open window exists.
pub(crate) fn create_and_open_dir_tree(path: &Path) -> io::Result<File> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(invalid("unsafe root path"));
    }
    let mut current = if path.is_absolute() {
        open_dir_path(Path::new("/"))?
    } else {
        open_dir_path(Path::new("."))?
    };
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                create_dir_at(&current, name)?;
                current = open_dir_at(&current, name)?;
            }
            Component::ParentDir | Component::Prefix(_) => unreachable!("validated above"),
        }
    }
    Ok(current)
}

/// Opens one child directory without following a symlink.
pub(crate) fn open_dir_at<P: Arg + Copy>(parent: &File, name: P) -> io::Result<File> {
    let fd = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(map_final_component_error)?;
    Ok(File::from(fd))
}

/// Creates one child directory mode 0700; an existing entry is accepted and
/// validated by the following `open_dir_at`.
pub(crate) fn create_dir_at<P: Arg + Copy>(parent: &File, name: P) -> io::Result<()> {
    match mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(Errno::EXIST) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Returns `true` when `name` is a regular file, `false` when absent, and
/// `InvalidInput` for a symlink or any other non-regular entry. No open is
/// performed, so a FIFO or device cannot block or have side effects here.
pub(crate) fn regular_or_absent<P: Arg + Copy>(parent: &File, name: P) -> io::Result<bool> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            if FileType::from_raw_mode(stat.st_mode).is_file() {
                Ok(true)
            } else {
                Err(invalid("state member is not a regular file"))
            }
        }
        Err(Errno::NOENT) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Opens and exclusively `flock`s the namespace lock member.
///
/// `O_NOFOLLOW` (without `O_EXCL`) rejects a symlink without creating its
/// target. The opened object is verified as a regular file with one link
/// before the lock is taken. After locking, the opened fd and the current
/// `lock` entry are compared by device/inode so a replacement between `openat`
/// and `flock` is refused instead of locking a detached inode. That pair is a
/// best-effort detection point: a later replacement is not prevented, but the
/// lock already held on the opened inode keeps its exclusion semantics for
/// this namespace handle. Contention is reported as `WouldBlock`.
pub(crate) fn open_lock_at<P: Arg + Copy>(parent: &File, name: P) -> io::Result<File> {
    open_lock_at_with(parent, name, || {})
}

fn open_lock_at_with<P: Arg + Copy>(
    parent: &File,
    name: P,
    after_open: impl FnOnce(),
) -> io::Result<File> {
    let fd = openat(
        parent,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::from_raw_mode(0o600),
    )
    .map_err(map_final_component_error)?;
    let file = File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("lock member is not a regular file"));
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        return Err(invalid("lock member must not have hard links"));
    }
    after_open();
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {
            let opened = fstat(&file)?;
            let named = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if opened.st_dev != named.st_dev || opened.st_ino != named.st_ino {
                return Err(invalid("lock member was replaced while opening"));
            }
            Ok(file)
        }
        Err(error) => Err(error.into()),
    }
}

/// Reads one regular file relative to `parent`, capped at `cap` bytes.
///
/// `O_NOFOLLOW|O_NONBLOCK` prevents symlink following and FIFO blocking; the
/// fd metadata check rejects every non-regular object before any byte is
/// consumed. `None` means the entry is absent.
pub(crate) fn read_file_at<P: Arg + Copy>(
    parent: &File,
    name: P,
    cap: usize,
) -> io::Result<Option<Vec<u8>>> {
    let fd = match openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(map_final_component_error(error)),
    };
    let file = File::from(fd);
    if !file.metadata()?.is_file() {
        return Err(invalid("state member is not a regular file"));
    }
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    let mut reader = file.take(limit);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "state member exceeds ceiling",
        ));
    }
    Ok(Some(bytes))
}

/// Removes one child entry without following it. `NotFound` is returned as
/// such so callers can distinguish an absent member.
pub(crate) fn remove_file_at<P: Arg + Copy>(parent: &File, name: P) -> io::Result<()> {
    unlinkat(parent, name, AtFlags::empty()).map_err(Into::into)
}

/// Removes one child and confirms the directory entry update with fsync.
pub(crate) fn remove_file_durably_at<P: Arg + Copy>(parent: &File, name: P) -> io::Result<()> {
    remove_file_at(parent, name)?;
    fsync(parent).map_err(|_| io::Error::other(DirectorySyncFailure))
}

/// Whether the directory fd `dir` is still the directory currently named
/// `name` under `root` (same device and inode, still a real directory).
///
/// This is a best-effort detection point, not a guarantee about when a
/// response is written: a rename/replacement after the `statat` returns is not
/// observed. A detected mismatch (including a symlink replacement, which
/// `statat` does not follow) lets the caller fail closed instead of
/// acknowledging a write against an orphaned directory.
pub(crate) fn directory_matches<P: Arg + Copy>(
    root: &File,
    name: P,
    dir: &File,
) -> io::Result<bool> {
    let named = statat(root, name, AtFlags::SYMLINK_NOFOLLOW)?;
    let actual = fstat(dir)?;
    Ok(FileType::from_raw_mode(named.st_mode).is_dir()
        && named.st_dev == actual.st_dev
        && named.st_ino == actual.st_ino)
}

/// Atomically writes `data` to `name` through an explicitly supplied temp
/// name. The temp is created `O_CREAT|O_EXCL|O_NOFOLLOW`; an existing entry,
/// including a symlink, is never followed or truncated.
pub(crate) fn write_atomic_named<P: Arg + Copy, Q: Arg + Copy>(
    parent: &File,
    name: P,
    temp: Q,
    data: &[u8],
    cap: usize,
) -> io::Result<()> {
    write_atomic_named_with_sync(parent, name, temp, data, cap, |directory| {
        fsync(directory).map_err(io::Error::from)
    })
}

fn write_atomic_named_with_sync<P: Arg + Copy, Q: Arg + Copy>(
    parent: &File,
    name: P,
    temp: Q,
    data: &[u8],
    cap: usize,
    sync_directory: impl FnOnce(&File) -> io::Result<()>,
) -> io::Result<()> {
    if data.len() > cap {
        return Err(invalid("payload exceeds ceiling"));
    }
    let fd = openat(
        parent,
        temp,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(map_final_component_error)?;
    let mut file = File::from(fd);
    let result = (|| -> io::Result<()> {
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        renameat(parent, temp, parent, name)?;
        // If this fails the rename may already be visible, so report the
        // error and let callers classify the commit as uncertain.
        sync_directory(parent).map_err(|_| io::Error::other(DirectorySyncFailure))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unlinkat(parent, temp, AtFlags::empty());
    }
    result
}

/// Atomically writes `data` to `name` using a fresh exclusive temp name.
/// `AlreadyExists` from a pre-created candidate is retried a bounded number
/// of times; every other error is returned.
pub(crate) fn write_atomic_unique<P: Arg + Copy>(
    parent: &File,
    name: P,
    data: &[u8],
    cap: usize,
    stem: &str,
) -> io::Result<()> {
    let mut last = None;
    for _ in 0..TEMP_ATTEMPTS {
        let temp = temp_name(stem);
        match write_atomic_named(parent, name, temp.as_str(), data, cap) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temp name candidates exhausted",
        )
    }))
}

/// Removes aged `<stem>.tmp.*` siblings relative to `parent`, never following
/// a symlink and never deleting a directory. Age is checked with `statat`
/// `AT_SYMLINK_NOFOLLOW`; unknown or future mtimes are kept.
pub(crate) fn clean_temp_siblings_at(parent: &File, stem: &str) -> io::Result<()> {
    let dot_prefix = format!("{stem}.tmp.");
    let dash_prefix = format!("{stem}.tmp-");
    let now = now_secs();
    let mut buffer = vec![MaybeUninit::<u8>::uninit(); 8192];
    let mut entries = RawDir::new(parent, &mut buffer);
    while let Some(entry) = entries.next() {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.starts_with(&dot_prefix) || name.starts_with(&dash_prefix)) {
            continue;
        }
        let Ok(stat) = statat(parent, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        let Ok(mtime) = u64::try_from(stat.st_mtime) else {
            continue;
        };
        if now >= mtime && now - mtime >= STALE_TEMP_AGE_SECS {
            let _ = unlinkat(parent, entry.file_name(), AtFlags::empty());
        }
    }
    Ok(())
}

fn temp_name(stem: &str) -> String {
    format!(
        "{stem}.tmp-{}-{:?}-{}",
        std::process::id(),
        std::thread::current().id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn map_final_component_error(error: Errno) -> io::Error {
    match error {
        Errno::LOOP | Errno::MLINK | Errno::NOTDIR => invalid("symlink or non-directory"),
        other => other.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "fs-at-{name}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        root
    }

    #[test]
    fn directory_sync_failure_reports_renamed_but_uncertain_commit() {
        let root = scratch_dir("sync");
        let dir = open_dir_path(&root).unwrap();
        let error = write_atomic_named_with_sync(
            &dir,
            "snapshot",
            "snapshot.tmp",
            b"committed bytes",
            64,
            |_| Err(io::Error::other("injected directory fsync failure")),
        )
        .expect_err("directory sync error must be returned");
        assert!(is_uncertain_durability_error(&error));
        assert_eq!(
            std::fs::read(root.join("snapshot")).unwrap(),
            b"committed bytes"
        );
        assert!(!root.join("snapshot.tmp").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn hardlinked_lock_member_is_refused() {
        let root = scratch_dir("lock-hardlink");
        std::fs::write(root.join("lock"), b"lock").unwrap();
        std::fs::hard_link(root.join("lock"), root.join("lock-copy")).unwrap();
        let dir = open_dir_path(&root).unwrap();
        let error =
            open_lock_at(&dir, "lock").expect_err("a lock member with two links must be refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("hard links"),
            "diagnostic must name the hard-link refusal: {error}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lock_replaced_while_opening_is_refused() {
        let root = scratch_dir("lock-replaced");
        let dir = open_dir_path(&root).unwrap();
        let error = open_lock_at_with(&dir, "lock", || {
            std::fs::rename(root.join("lock"), root.join("lock-detached")).unwrap();
            std::fs::write(root.join("lock"), b"replacement").unwrap();
        })
        .expect_err("a lock replaced between openat and flock must be refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("replaced"),
            "diagnostic must name the replacement refusal: {error}"
        );
        assert_eq!(
            std::fs::read(root.join("lock")).unwrap(),
            b"replacement",
            "the check must not follow or rewrite the replacement"
        );
        assert_eq!(
            std::fs::read(root.join("lock-detached")).unwrap(),
            b"",
            "the originally opened lock must stay untouched"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
