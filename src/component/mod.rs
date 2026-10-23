//! Executable-component boundary for bounded storage mechanics.
//!
//! The crate still exposes the in-process [`StorageBackend`](crate::StorageBackend),
//! [`KvStore`](crate::KvStore), and session codec for Core's linked use; this
//! module adds the installable form required by the component split
//! (bitty#2495): a validated `bitty-component.toml`, a bounded v1 stdio wire
//! protocol, a journaled namespace store, and a server binary wrapping that
//! store. It carries no installer, no download source, no capability policy,
//! no XDG migration, and no platform packaging logic beyond the repository
//! script.
//!
//! ```text
//! Core host client  ──stdio frames──▶  bitty-storage  ──▶  journaled namespaces
//!   (remaining work)                    (this module)       (atomic temp+rename)
//! ```
//!
//! The wire schema names namespaces, keys, and opaque values only. It never
//! carries a filesystem path: the host chooses the storage root when it spawns
//! the component, and every namespace path is derived from that root after
//! strict name validation. Core owns installation, digest verification,
//! capability grants, consent, safe-mode denial, migration, and restore
//! re-derivation; this component commits exactly the batch it is handed.

pub mod descriptor;
pub mod protocol;
pub mod server;
pub mod store;

/// Component version reported by `HelloAck`, `--version`, and the descriptor.
pub const COMPONENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub use descriptor::{
    COMPONENT_EXECUTABLE, COMPONENT_NAME, COMPONENT_PROTOCOL_MAX, COMPONENT_PROTOCOL_MIN,
    ComponentDescriptor, DescriptorError, MAX_DESCRIPTOR_BYTES, PLACEHOLDER_SHA256,
};
pub use protocol::{
    ErrorKind, FrameReader, MAX_BATCH_BYTES, MAX_BATCH_ROWS, MAX_FRAME_BYTES, MAX_KEY_BYTES,
    MAX_NAMESPACE_NAME_BYTES, MAX_NAMESPACES, MAX_READ_BYTES, MAX_READ_ROWS, MAX_ROWS,
    MAX_SNAPSHOT_BYTES, MAX_VALUE_BYTES, Message, PROTOCOL_VERSION, Row, WireError, decode_message,
    encode_frame, encode_message, negotiate, write_frame,
};
pub use server::{SERVER_EXIT_INTERNAL, SERVER_EXIT_OK, SERVER_EXIT_PROTOCOL, serve_stdio};
pub use store::{
    CommitOutcome, Namespace, NamespaceName, RollbackOutcome, SnapshotPage, StorageRoot,
    StoreError, StoreErrorKind,
};
