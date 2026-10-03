//! Bounded isolated storage mechanics for Bitty.
//!
//! This crate implements persistence mechanics only: the session snapshot
//! file codec, atomic durable commits with stale-temp hygiene and capped
//! loads, the per-plugin KV filesystem backend, and the transcript/history
//! descriptor vocabulary. It never touches volatile Terminal Truth, never
//! persists raw terminal output by default, and takes no database,
//! serialization, PTY, or Core dependency (std only, JSON hand-rolled).
//!
//! # Core-owned backend seam
//!
//! Core owns the capability gate, the budgets, generation fencing, restore
//! re-derivation, and validation-before-mutation. This crate implements the
//! byte mechanics behind that gate through the [`StorageBackend`] seam:
//! Core validates first, then delegates the durable commit here. The
//! dependency is one-way (this crate never imports Core); Core integration
//! is a later task and must preserve every ceiling byte-for-byte, the
//! atomic-commit rule, safe/headless skips, and counts-only logging.
//!
//! Capture, apply, restore staging, fencing, and the Lua-side quota bridge
//! stay in Core. The segmented transcript and command history are
//! greenfield behind an explicit opt-in: only descriptor/record types and
//! retention-selection rules live here, no persistence implementation.

#![forbid(unsafe_code)]

pub mod atomic_io;
pub mod ceiling;
pub mod history;
pub mod kv;
pub mod session_codec;
pub mod transcript;

pub use atomic_io::{LoadError, load_bytes_capped, save_bytes_atomic};
pub use history::{CommandRecord, HistoryActor, validate_record};
pub use kv::{DeletionEvidence, JsonValue, KvStore, StoreError, StoreErrorCode};
pub use session_codec::{
    LayoutNode, PaneAttachment, PaneRoute, PresentationMode, SessionError, SessionSnapshot,
    WorkspaceSnapshot, decode_session, encode_session,
};
pub use transcript::{RetentionPolicy, SegmentDescriptor, TranscriptDeletionEvidence};

/// Core-owned durable-commit seam (validation-before-mutation stays Core).
///
/// A backend implements the byte commit for one storage object; Core runs
/// its own validation, capability, and safe/headless gates first and calls
/// through this seam only afterwards. Implementations must be atomic (a
/// failed commit leaves the previous state intact), bounded (every
/// [`ceiling`] bound enforced fail-closed), and content-free in errors.
/// Deletion must remove bytes and produce evidence; a post-purge
/// export/query returns nothing.
pub trait StorageBackend {
    /// Error type with content-free display (safe for logs).
    type Error: std::error::Error;

    /// Atomically commits `bytes` as the whole object state.
    fn commit(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;

    /// Loads the whole object state with a hard size cap. A missing file
    /// is a quiet clean start, represented as `Ok(None)`.
    fn load(&self) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Authoritatively deletes the object state.
    fn delete(&mut self) -> Result<DeletionEvidence, Self::Error>;
}

/// File-backed [`StorageBackend`] over one bounded path.
///
/// Sessions and KV images share this commit/load/delete discipline; each
/// object keeps its own namespace, retention, and lifecycle (no universal
/// store).
#[derive(Debug)]
pub struct FileBackend {
    path: std::path::PathBuf,
    cap: usize,
}

impl FileBackend {
    /// Binds one bounded file location.
    #[must_use]
    pub fn new(path: std::path::PathBuf, cap: usize) -> Self {
        Self { path, cap }
    }

    /// Bound path.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl StorageBackend for FileBackend {
    type Error = atomic_io::IoError;

    fn commit(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        save_bytes_atomic(&self.path, bytes, self.cap)
    }

    fn load(&self) -> Result<Option<Vec<u8>>, Self::Error> {
        match load_bytes_capped(&self.path, self.cap) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(LoadError::NotFound) => Ok(None),
            Err(LoadError::TooLarge { actual, limit }) => Err(atomic_io::IoError::new(
                "file exceeds ceiling",
                format!("{actual} > {limit}"),
            )),
            Err(LoadError::Io(msg)) => Err(atomic_io::IoError::new("read failed", msg)),
        }
    }

    fn delete(&mut self) -> Result<DeletionEvidence, Self::Error> {
        let existed = self.path.exists();
        if existed {
            std::fs::remove_file(&self.path)
                .map_err(|e| atomic_io::IoError::new("delete failed", e.to_string()))?;
        }
        Ok(DeletionEvidence {
            keys_removed: 0,
            bytes_removed: 0,
            file_removed: existed,
        })
    }
}
