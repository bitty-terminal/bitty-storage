//! Fail-closed namespace backend for platforms without the anchored
//! directory-fd implementation.
//!
//! Linux x86_64 is the packaged target for this task. Returning
//! `Unsupported` from construction is deliberate: a path-based fallback would
//! re-introduce the symlink/ancestor races this backend exists to remove.

use std::path::PathBuf;

use crate::component::protocol::Row;

use super::{CommitOutcome, NamespaceName, RollbackOutcome, SnapshotPage, StoreError};

/// Unsupported storage root.
#[derive(Debug)]
pub struct StorageRoot;

impl StorageRoot {
    /// Fails closed on this platform.
    ///
    /// # Errors
    ///
    /// Always returns [`StoreErrorKind::Unsupported`](super::StoreErrorKind::Unsupported).
    pub fn new(_path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Err(StoreError::unsupported())
    }

    /// Fails closed on this platform.
    ///
    /// # Errors
    ///
    /// Always returns [`StoreErrorKind::Unsupported`](super::StoreErrorKind::Unsupported).
    pub fn open_namespace(&self, _name: &NamespaceName) -> Result<Namespace, StoreError> {
        Err(StoreError::unsupported())
    }
}

/// Unsupported namespace handle.
#[derive(Debug)]
pub struct Namespace;

impl Namespace {
    /// Always zero; no namespace can be opened on this platform.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        0
    }

    /// Always zero; no namespace can be opened on this platform.
    #[must_use]
    pub const fn row_count(&self) -> usize {
        0
    }

    /// Always zero; no namespace can be opened on this platform.
    #[must_use]
    pub const fn value_bytes(&self) -> u64 {
        0
    }

    /// Fails closed on this platform; no cached handle can exist because
    /// [`StorageRoot::open_namespace`] always returns `Unsupported`.
    pub(crate) fn ensure_attached(&self) -> Result<(), StoreError> {
        Err(StoreError::unsupported())
    }

    /// Fails closed on this platform.
    ///
    /// # Errors
    ///
    /// Always returns [`StoreErrorKind::Unsupported`](super::StoreErrorKind::Unsupported).
    pub fn read_page(
        &self,
        _start_row: u32,
        _max_rows: u32,
        _max_bytes: u32,
    ) -> Result<SnapshotPage, StoreError> {
        Err(StoreError::unsupported())
    }

    /// Fails closed on this platform.
    ///
    /// # Errors
    ///
    /// Always returns [`StoreErrorKind::Unsupported`](super::StoreErrorKind::Unsupported).
    pub fn commit(
        &mut self,
        _expected_revision: u64,
        _upserts: Vec<Row>,
        _deletes: Vec<String>,
    ) -> Result<CommitOutcome, StoreError> {
        Err(StoreError::unsupported())
    }

    /// Fails closed on this platform.
    ///
    /// # Errors
    ///
    /// Always returns [`StoreErrorKind::Unsupported`](super::StoreErrorKind::Unsupported).
    pub fn rollback(&mut self, _expected_revision: u64) -> Result<RollbackOutcome, StoreError> {
        Err(StoreError::unsupported())
    }
}
