//! Component server: exposes journaled namespaces over the v1 stdio protocol.
//!
//! The binary entry point (`bitty-storage` with `--root PATH`) calls
//! [`serve_stdio`]. Tests call [`serve`] with explicit streams. The server is
//! a thin, policy-free adapter: Core owns installation, digest verification,
//! capability grants, consent, safe-mode denial, XDG migration, and restore
//! re-derivation. This process accepts only what the wire schema permits
//! (namespaces, keys, opaque values) and delegates every durable decision to
//! the journaled store.
//!
//! # Request model
//!
//! Requests are synchronous and single-threaded: a `CommitBatch` is fully
//! durable (or rejected without mutation) before `Committed` is written.
//! There is no per-connection transaction staging, so `Rollback` is the
//! explicit one-step restore of the previous revision, not an abort of an
//! in-flight request. Namespace locks are held for the connection lifetime,
//! which gives one component process exclusive write access to each open
//! namespace even when another host starts a second component.
//!
//! # Shutdown
//!
//! `Shutdown` (or stdin EOF) drops every namespace handle, releasing the OS
//! locks, writes `ShutdownAck` for an explicit `Shutdown`, and exits 0.
//! Protocol violations exit 3; a server that cannot start exits 4. A
//! component crash cannot corrupt acknowledged state because every commit is
//! journaled before the snapshot rename and replayed on the next open.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use super::descriptor::COMPONENT_NAME;
use super::protocol::{
    CONNECTION_ID, ErrorKind, FrameReader, MAX_NAMESPACES, Message, Row, WireError, negotiate,
    write_frame,
};
use super::store::{Namespace, NamespaceName, StorageRoot, StoreError, StoreErrorKind};

/// Version reported in `HelloAck` and by `--version` (the crate version).
pub use super::COMPONENT_VERSION;

/// Clean shutdown (explicit `Shutdown` or stdin EOF).
pub const SERVER_EXIT_OK: u8 = 0;
/// Handshake or protocol violation; the peer is told why first when the
/// stream still permits a write.
pub const SERVER_EXIT_PROTOCOL: u8 = 3;
/// The server could not open its root or write the handshake.
pub const SERVER_EXIT_INTERNAL: u8 = 4;

const ERR_HANDSHAKE_REQUIRED: &str = "handshake required";
const ERR_PROTOCOL_VERSION: &str = "protocol version unsupported";
const ERR_COMPONENT_MISMATCH: &str = "component name mismatch";
const ERR_UNEXPECTED_MESSAGE: &str = "unexpected message";
const ERR_FRAME_TOO_LARGE: &str = "frame too large";
const ERR_INVALID_FRAME: &str = "invalid protocol frame";
const ERR_INVALID_NAMESPACE: &str = "invalid namespace";
const ERR_NAMESPACE_LIMIT: &str = "namespace limit reached";
const ERR_UNKNOWN_NAMESPACE: &str = "unknown namespace";
const ERR_STALE_REVISION: &str = "revision conflict";
const ERR_LOCKED: &str = "namespace is locked";
const ERR_CORRUPT_STATE: &str = "storage state is corrupt";
const ERR_BOUND: &str = "storage bound exceeded";
const ERR_NO_PREVIOUS: &str = "no previous revision";
const ERR_UNSUPPORTED: &str = "operation unsupported";
const ERR_IO: &str = "storage i/o failed";
const ERR_INTERNAL: &str = "internal error";

/// Serves the protocol on stdin/stdout over `root`.
#[must_use]
pub fn serve_stdio(root: StorageRoot) -> u8 {
    serve(root, io::stdin(), io::stdout())
}

/// Serves the protocol on explicit streams (tests and embedders).
///
/// Returns [`SERVER_EXIT_OK`], [`SERVER_EXIT_PROTOCOL`], or
/// [`SERVER_EXIT_INTERNAL`].
pub fn serve<R, W>(root: StorageRoot, input: R, output: W) -> u8
where
    R: Read,
    W: Write,
{
    let mut writer = FrameWriter::new(output);
    let mut reader = FrameReader::new(input);

    let protocol = match reader.read_message() {
        Ok(Some(Message::Hello {
            min,
            max,
            component,
            version: _,
        })) => {
            if component != COMPONENT_NAME {
                writer.connection_error(ErrorKind::Protocol, ERR_COMPONENT_MISMATCH);
                return SERVER_EXIT_PROTOCOL;
            }
            match negotiate(min, max) {
                Some(protocol) => protocol,
                None => {
                    writer.connection_error(ErrorKind::Protocol, ERR_PROTOCOL_VERSION);
                    return SERVER_EXIT_PROTOCOL;
                }
            }
        }
        Ok(Some(_)) => {
            writer.connection_error(ErrorKind::Protocol, ERR_HANDSHAKE_REQUIRED);
            return SERVER_EXIT_PROTOCOL;
        }
        Ok(None) => return SERVER_EXIT_OK,
        Err(error) => {
            writer.wire_error(&error);
            return SERVER_EXIT_PROTOCOL;
        }
    };

    if !writer.write(&Message::HelloAck {
        protocol,
        component: COMPONENT_NAME.to_owned(),
        version: COMPONENT_VERSION.to_owned(),
    }) {
        return SERVER_EXIT_INTERNAL;
    }

    let mut namespaces: BTreeMap<String, Namespace> = BTreeMap::new();
    let mut exit_code = SERVER_EXIT_OK;
    loop {
        match reader.read_message() {
            Ok(Some(message)) => match message {
                Message::OpenNamespace { request, namespace } => {
                    handle_open(&root, &mut namespaces, &mut writer, request, namespace)
                }
                Message::ReadSnapshot {
                    request,
                    namespace,
                    start_row,
                    max_rows,
                    max_bytes,
                } => handle_read(
                    &namespaces,
                    &mut writer,
                    request,
                    &namespace,
                    start_row,
                    max_rows,
                    max_bytes,
                ),
                Message::CommitBatch {
                    request,
                    namespace,
                    expected_revision,
                    upserts,
                    deletes,
                } => handle_commit(
                    &mut namespaces,
                    &mut writer,
                    request,
                    &namespace,
                    expected_revision,
                    upserts,
                    deletes,
                ),
                Message::Rollback {
                    request,
                    namespace,
                    expected_revision,
                } => handle_rollback(
                    &mut namespaces,
                    &mut writer,
                    request,
                    &namespace,
                    expected_revision,
                ),
                Message::Shutdown => {
                    namespaces.clear();
                    let _ = writer.write(&Message::ShutdownAck);
                    return SERVER_EXIT_OK;
                }
                Message::Hello { .. } => {
                    writer.connection_error(ErrorKind::Protocol, ERR_UNEXPECTED_MESSAGE);
                    exit_code = SERVER_EXIT_PROTOCOL;
                    break;
                }
                _ => {
                    writer.connection_error(ErrorKind::Protocol, ERR_UNEXPECTED_MESSAGE);
                    exit_code = SERVER_EXIT_PROTOCOL;
                    break;
                }
            },
            Ok(None) => break,
            Err(error) => {
                writer.wire_error(&error);
                exit_code = SERVER_EXIT_PROTOCOL;
                break;
            }
        }
    }

    // Dropping handles releases the OS locks even on an EOF path.
    namespaces.clear();
    exit_code
}

fn handle_open<W: Write>(
    root: &StorageRoot,
    namespaces: &mut BTreeMap<String, Namespace>,
    writer: &mut FrameWriter<W>,
    request: u64,
    namespace: String,
) {
    let name = match NamespaceName::parse(&namespace) {
        Ok(name) => name,
        Err(_) => {
            writer.request_error(request, ErrorKind::InvalidRequest, ERR_INVALID_NAMESPACE);
            return;
        }
    };
    if let Some(open) = namespaces.get(name.as_str()) {
        if open.ensure_attached().is_err() {
            namespaces.remove(name.as_str());
        } else {
            writer.write(&Message::NamespaceOpened {
                request,
                namespace,
                revision: open.revision(),
                rows: u32::try_from(open.row_count()).unwrap_or(u32::MAX),
                bytes: open.value_bytes(),
            });
            return;
        }
    }
    if namespaces.len() >= MAX_NAMESPACES {
        writer.request_error(request, ErrorKind::Budget, ERR_NAMESPACE_LIMIT);
        return;
    }
    match root.open_namespace(&name) {
        Ok(open) => {
            let opened = Message::NamespaceOpened {
                request,
                namespace: name.as_str().to_owned(),
                revision: open.revision(),
                rows: u32::try_from(open.row_count()).unwrap_or(u32::MAX),
                bytes: open.value_bytes(),
            };
            namespaces.insert(name.as_str().to_owned(), open);
            writer.write(&opened);
        }
        Err(error) => writer.store_error(request, &error),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_read<W: Write>(
    namespaces: &BTreeMap<String, Namespace>,
    writer: &mut FrameWriter<W>,
    request: u64,
    namespace: &str,
    start_row: u32,
    max_rows: u32,
    max_bytes: u32,
) {
    let Some(open) = namespaces.get(namespace) else {
        writer.request_error(request, ErrorKind::UnknownNamespace, ERR_UNKNOWN_NAMESPACE);
        return;
    };
    match open.read_page(start_row, max_rows, max_bytes) {
        Ok(page) => {
            writer.write(&Message::SnapshotChunk {
                request,
                namespace: namespace.to_owned(),
                revision: page.revision,
                start_row: page.start_row,
                rows: page.rows,
                total_rows: page.total_rows,
                total_bytes: page.total_bytes,
                done: page.done,
            });
        }
        Err(error) => writer.store_error(request, &error),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_commit<W: Write>(
    namespaces: &mut BTreeMap<String, Namespace>,
    writer: &mut FrameWriter<W>,
    request: u64,
    namespace: &str,
    expected_revision: u64,
    upserts: Vec<Row>,
    deletes: Vec<String>,
) {
    let Some(open) = namespaces.get_mut(namespace) else {
        writer.request_error(request, ErrorKind::UnknownNamespace, ERR_UNKNOWN_NAMESPACE);
        return;
    };
    let result = open.commit(expected_revision, upserts, deletes);
    evict_uncertain(namespaces, namespace, &result);
    match result {
        Ok(outcome) => {
            writer.write(&Message::Committed {
                request,
                namespace: namespace.to_owned(),
                revision: outcome.revision,
                rows_written: outcome.rows_written,
                rows_removed: outcome.rows_removed,
                bytes_written: outcome.bytes_written,
                total_rows: outcome.total_rows,
                total_bytes: outcome.total_bytes,
            });
        }
        Err(error) => writer.store_error(request, &error),
    }
}

fn handle_rollback<W: Write>(
    namespaces: &mut BTreeMap<String, Namespace>,
    writer: &mut FrameWriter<W>,
    request: u64,
    namespace: &str,
    expected_revision: u64,
) {
    let Some(open) = namespaces.get_mut(namespace) else {
        writer.request_error(request, ErrorKind::UnknownNamespace, ERR_UNKNOWN_NAMESPACE);
        return;
    };
    let result = open.rollback(expected_revision);
    evict_uncertain(namespaces, namespace, &result);
    match result {
        Ok(outcome) => {
            writer.write(&Message::RolledBack {
                request,
                namespace: namespace.to_owned(),
                revision: outcome.revision,
                restored_revision: outcome.restored_revision,
                total_rows: outcome.total_rows,
                total_bytes: outcome.total_bytes,
            });
        }
        Err(error) => writer.store_error(request, &error),
    }
}

fn store_error(error: &StoreError) -> (ErrorKind, &'static str) {
    match error.kind() {
        StoreErrorKind::InvalidName => (ErrorKind::InvalidRequest, ERR_INVALID_NAMESPACE),
        StoreErrorKind::Bound => (ErrorKind::Budget, ERR_BOUND),
        StoreErrorKind::Locked => (ErrorKind::Locked, ERR_LOCKED),
        StoreErrorKind::Corrupt => (ErrorKind::CorruptState, ERR_CORRUPT_STATE),
        StoreErrorKind::Io => (ErrorKind::Io, ERR_IO),
        StoreErrorKind::Uncertain => (
            ErrorKind::Uncertain,
            "commit outcome uncertain; reopen namespace",
        ),
        StoreErrorKind::NoPrevious => (ErrorKind::InvalidRequest, ERR_NO_PREVIOUS),
        StoreErrorKind::StaleRevision => (ErrorKind::StaleRevision, ERR_STALE_REVISION),
        StoreErrorKind::Unsupported => (ErrorKind::Unsupported, ERR_UNSUPPORTED),
        StoreErrorKind::Internal => (ErrorKind::Internal, ERR_INTERNAL),
    }
}

fn evict_uncertain<T>(
    namespaces: &mut BTreeMap<String, Namespace>,
    namespace: &str,
    result: &Result<T, StoreError>,
) {
    if result
        .as_ref()
        .is_err_and(|error| error.kind() == StoreErrorKind::Uncertain)
    {
        namespaces.remove(namespace);
    }
}

struct FrameWriter<W> {
    writer: W,
    failed: bool,
}

impl<W: Write> FrameWriter<W> {
    fn new(writer: W) -> Self {
        Self {
            writer,
            failed: false,
        }
    }

    fn write(&mut self, message: &Message) -> bool {
        if self.failed {
            return false;
        }
        match write_frame(&mut self.writer, message).and_then(|()| {
            self.writer
                .flush()
                .map_err(|error| WireError::Io(error.kind()))
        }) {
            Ok(()) => true,
            Err(_) => {
                self.failed = true;
                false
            }
        }
    }

    fn request_error(&mut self, request: u64, kind: ErrorKind, message: &'static str) {
        self.write(&Message::Error {
            request,
            kind,
            message: message.to_owned(),
        });
    }

    fn connection_error(&mut self, kind: ErrorKind, message: &'static str) {
        self.request_error(CONNECTION_ID, kind, message);
    }

    fn store_error(&mut self, request: u64, error: &StoreError) {
        let (kind, message) = store_error(error);
        self.request_error(request, kind, message);
    }

    fn wire_error(&mut self, error: &WireError) {
        let (kind, message) = match error {
            WireError::TooLarge { .. } => (ErrorKind::Protocol, ERR_FRAME_TOO_LARGE),
            _ => (ErrorKind::Protocol, ERR_INVALID_FRAME),
        };
        self.connection_error(kind, message);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::component::protocol::decode_message;

    #[test]
    fn open_after_path_replacement_does_not_acknowledge_cached_inode() {
        let root_path =
            std::env::temp_dir().join(format!("server-open-replace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root_path);
        std::fs::create_dir_all(&root_path).unwrap();
        let root = StorageRoot::new(&root_path).unwrap();
        let mut namespaces = BTreeMap::new();
        let mut output = Vec::new();
        {
            let mut writer = FrameWriter::new(&mut output);
            handle_open(&root, &mut namespaces, &mut writer, 1, "test".to_owned());
        }
        namespaces
            .get_mut("test")
            .unwrap()
            .commit(0, Vec::new(), Vec::new())
            .unwrap();

        std::fs::rename(root_path.join("test"), root_path.join("detached")).unwrap();
        std::fs::create_dir(root_path.join("test")).unwrap();
        output.clear();
        {
            let mut writer = FrameWriter::new(&mut output);
            handle_open(&root, &mut namespaces, &mut writer, 2, "test".to_owned());
        }

        assert_eq!(namespaces.get("test").unwrap().revision(), 0);
        let message = decode_message(&output[4..]).unwrap();
        assert!(matches!(
            message,
            Message::NamespaceOpened {
                request: 2,
                revision: 0,
                ..
            }
        ));
        assert_eq!(
            namespaces.len(),
            1,
            "detached cached handle must be evicted"
        );
        let _ = std::fs::remove_dir_all(root_path);
    }

    #[test]
    fn uncertain_result_evicts_cached_snapshot_before_reopen() {
        let root_path =
            std::env::temp_dir().join(format!("server-uncertain-reopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root_path);
        std::fs::create_dir_all(&root_path).unwrap();
        let root = StorageRoot::new(&root_path).unwrap();
        let name = NamespaceName::parse("test").unwrap();
        let cached = root.open_namespace(&name).unwrap();
        let mut namespaces = BTreeMap::from([("test".to_owned(), cached)]);
        let uncertain: Result<(), StoreError> = Err(StoreError::uncertain());
        evict_uncertain(&mut namespaces, "test", &uncertain);
        assert!(!namespaces.contains_key("test"));

        let reopened = root
            .open_namespace(&name)
            .expect("reopen must reload disk state");
        assert_eq!(reopened.revision(), 0);
        let _ = std::fs::remove_dir_all(root_path);
    }
}
