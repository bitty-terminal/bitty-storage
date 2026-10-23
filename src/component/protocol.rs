//! Storage component wire protocol v1 (core host <-> `bitty-storage`).
//!
//! The component is a stdio coprocess: the host writes requests to its stdin
//! and reads framed messages from its stdout. stderr stays diagnostic and is
//! never protocol. This module is the authoritative schema and codec; it is
//! hand-written (`std` only), forbids panics on hostile input, and fails
//! closed on every bound.
//!
//! # Framing
//!
//! ```text
//! frame   = length:u32be payload[length]
//! payload = tag:u8 fields...
//! ```
//!
//! `length` is 1..=[`MAX_FRAME_BYTES`]. A larger or zero length is rejected
//! from the four-byte header alone; no payload byte is read or allocated.
//!
//! # Field encoding
//!
//! - Integers are big-endian fixed width (`u8`, `u16`, `u32`, `u64`).
//! - `bool` is one byte, `0x00` or `0x01`; any other value is rejected.
//! - `str` is `len:u32be` + UTF-8 bytes, every length bounded per field.
//! - `bytes` is `len:u32be` + raw bytes, bounded per field.
//! - Lists are `count:u32be` + elements, count bounded per field.
//!
//! # Messages
//!
//! | Tag    | Message         | Fields (in order)                                                              | Direction  |
//! |--------|-----------------|--------------------------------------------------------------------------------|------------|
//! | `0x01` | `Hello`         | `min:u16 max:u16 component:str version:str`                                     | host->comp |
//! | `0x02` | `HelloAck`      | `protocol:u16 component:str version:str`                                        | comp->host |
//! | `0x10` | `OpenNamespace` | `request:u64 namespace:str`                                                     | host->comp |
//! | `0x11` | `ReadSnapshot`  | `request:u64 namespace:str start_row:u32 max_rows:u32 max_bytes:u32`            | host->comp |
//! | `0x12` | `CommitBatch`   | `request:u64 namespace:str expected_revision:u64 upserts:list<Row> deletes:list<str>` | host->comp |
//! | `0x13` | `Rollback`      | `request:u64 namespace:str expected_revision:u64`                               | host->comp |
//! | `0x3F` | `Shutdown`      | (none)                                                                          | host->comp |
//! | `0x20` | `NamespaceOpened` | `request:u64 namespace:str revision:u64 rows:u32 bytes:u64`                   | comp->host |
//! | `0x21` | `SnapshotChunk` | `request:u64 namespace:str revision:u64 start_row:u32 rows:list<Row> total_rows:u32 total_bytes:u64 done:bool` | comp->host |
//! | `0x22` | `Committed`     | `request:u64 namespace:str revision:u64 rows_written:u32 rows_removed:u32 bytes_written:u64 total_rows:u32 total_bytes:u64` | comp->host |
//! | `0x23` | `RolledBack`    | `request:u64 namespace:str revision:u64 restored_revision:u64 total_rows:u32 total_bytes:u64` | comp->host |
//! | `0x2F` | `Error`         | `request:u64 kind:u8 message:str`                                               | comp->host |
//! | `0x3E` | `ShutdownAck`   | (none)                                                                          | comp->host |
//!
//! A `Row` is `key:str value:bytes`. Rows are ordered by key in snapshots and
//! in every response; a batch names the rows it replaces or removes, never a
//! whole-file image. `request` ids are non-zero and identify one exchange;
//! `Error.request == 0` marks a connection-level failure.
//!
//! # Authority and capability boundary
//!
//! This protocol carries **no filesystem paths, no descriptor passing, and no
//! command language**. A request names a namespace, a key, and opaque bytes;
//! the host chooses the storage root when it spawns the component. Namespace
//! and key grammars reject separators, dot segments, controls, and non-ASCII
//! bytes, so a wire value can never escape the storage root. Error messages
//! are bounded static diagnostics, never echoed keys, values, or paths. The
//! host owns installation, digest verification, capability grants, consent,
//! migration, and safe-mode denial; the component stores exactly what it is
//! handed.
//!
//! # Bounds
//!
//! [`MAX_FRAME_BYTES`], [`MAX_SNAPSHOT_BYTES`], [`MAX_ROWS`],
//! [`MAX_BATCH_ROWS`], [`MAX_BATCH_BYTES`], [`MAX_VALUE_BYTES`],
//! [`MAX_READ_ROWS`], [`MAX_READ_BYTES`], and [`MAX_NAMESPACES`] are enforced
//! on both encode and decode. Reads are paged so a 1 MiB snapshot never needs
//! a frame larger than 256 KiB.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Read, Write};

use crate::component::descriptor::COMPONENT_NAME;

/// Wire protocol version implemented by this crate.
pub const PROTOCOL_VERSION: u16 = 1;

/// Size of the big-endian `u32` length prefix in front of every payload.
pub const FRAME_HEADER_BYTES: usize = 4;

/// Maximum payload length of one frame (256 KiB, matching the other
/// component codecs).
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

/// Maximum namespaces one component process holds open (and locks).
pub const MAX_NAMESPACES: usize = 64;

/// Maximum namespace-name bytes (`[a-z0-9][a-z0-9._-]{0,63}`).
pub const MAX_NAMESPACE_NAME_BYTES: usize = 64;

/// Maximum key bytes (`[a-z0-9][a-z0-9._-]{0,127}`).
pub const MAX_KEY_BYTES: usize = 128;

/// Maximum bytes of one row value (one frame chunk, not a whole snapshot).
pub const MAX_VALUE_BYTES: usize = 128 * 1024;

/// Maximum rows in one namespace snapshot.
pub const MAX_ROWS: usize = 4096;

/// Maximum serialized snapshot bytes (matches Core's session-file ceiling).
pub const MAX_SNAPSHOT_BYTES: usize = 1_048_576;

/// Maximum upserts or deletes in one `CommitBatch`.
pub const MAX_BATCH_ROWS: usize = 128;

/// Maximum encoded row/delete payload bytes in one `CommitBatch`.
pub const MAX_BATCH_BYTES: usize = 240 * 1024;

/// Maximum rows one `SnapshotChunk` carries.
pub const MAX_READ_ROWS: usize = 128;

/// Maximum row bytes one `SnapshotChunk` carries.
pub const MAX_READ_BYTES: usize = 240 * 1024;

/// Maximum component name bytes (`[a-z][a-z0-9-]{0,31}`).
pub const MAX_COMPONENT_NAME_BYTES: usize = 32;

/// Maximum version string bytes in `Hello` / `HelloAck`.
pub const MAX_VERSION_BYTES: usize = 64;

/// Maximum `Error.message` bytes.
pub const MAX_ERROR_MESSAGE_BYTES: usize = 256;

// ── tags ────────────────────────────────────────────────────────────────────

/// `Hello` tag.
pub const TAG_HELLO: u8 = 0x01;
/// `HelloAck` tag.
pub const TAG_HELLO_ACK: u8 = 0x02;
/// `OpenNamespace` tag.
pub const TAG_OPEN_NAMESPACE: u8 = 0x10;
/// `ReadSnapshot` tag.
pub const TAG_READ_SNAPSHOT: u8 = 0x11;
/// `CommitBatch` tag.
pub const TAG_COMMIT_BATCH: u8 = 0x12;
/// `Rollback` tag.
pub const TAG_ROLLBACK: u8 = 0x13;
/// `Shutdown` tag.
pub const TAG_SHUTDOWN: u8 = 0x3F;
/// `NamespaceOpened` tag.
pub const TAG_NAMESPACE_OPENED: u8 = 0x20;
/// `SnapshotChunk` tag.
pub const TAG_SNAPSHOT_CHUNK: u8 = 0x21;
/// `Committed` tag.
pub const TAG_COMMITTED: u8 = 0x22;
/// `RolledBack` tag.
pub const TAG_ROLLED_BACK: u8 = 0x23;
/// `Error` tag.
pub const TAG_ERROR: u8 = 0x2F;
/// `ShutdownAck` tag.
pub const TAG_SHUTDOWN_ACK: u8 = 0x3E;

/// Connection-level `Error` frame request id.
pub const CONNECTION_ID: u64 = 0;

// ── values ──────────────────────────────────────────────────────────────────

/// One namespace row: an identifier plus opaque bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Row key (`[a-z0-9][a-z0-9._-]{0,127}`).
    pub key: String,
    /// Opaque value bytes (at most [`MAX_VALUE_BYTES`]).
    pub value: Vec<u8>,
}

/// Typed error category carried by `Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The peer violated the protocol (code 1).
    Protocol,
    /// A request was malformed or violated a bound (code 2).
    InvalidRequest,
    /// A capacity or byte budget is exhausted (code 3).
    Budget,
    /// The operation is not supported on this component/platform (code 4).
    Unsupported,
    /// The namespace was never opened on this connection (code 5).
    UnknownNamespace,
    /// `expected_revision` does not match the current revision (code 6).
    StaleRevision,
    /// Another process holds the namespace lock (code 7).
    Locked,
    /// A snapshot or journal is structurally invalid (code 8).
    CorruptState,
    /// A filesystem operation failed (code 9). A commit or rollback `io` is a
    /// pre-rename failure, so retrying the same revision is safe; an
    /// open/read `io` is an ordinary I/O failure.
    Io,
    /// A commit may have completed but its durable outcome could not be
    /// confirmed, or the namespace path stopped naming the opened directory;
    /// the host must reopen and reread before retrying (code 11).
    Uncertain,
    /// Internal component failure (code 10).
    Internal,
}

// Stable wire codes are 1 protocol, 2 invalid_request, 3 budget, 4
// unsupported, 5 unknown_namespace, 6 stale_revision, 7 locked, 8
// corrupt_state, 9 io, 10 internal, and 11 uncertain.
//
// The table is additive within protocol v1: existing codes never move, so a
// v1 host that predates `uncertain` still decodes every code it knows. Such a
// host receives 11 as an unknown kind and must fail closed (treat it as
// non-retryable) rather than retrying from a cached revision; a host that
// knows `uncertain` reopens the namespace and rereads its revision first.
// `internal` stays at 10 so this addition cannot silently renumber it.

impl ErrorKind {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Protocol => 1,
            Self::InvalidRequest => 2,
            Self::Budget => 3,
            Self::Unsupported => 4,
            Self::UnknownNamespace => 5,
            Self::StaleRevision => 6,
            Self::Locked => 7,
            Self::CorruptState => 8,
            Self::Io => 9,
            Self::Internal => 10,
            Self::Uncertain => 11,
        }
    }

    /// Kind for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Protocol),
            2 => Some(Self::InvalidRequest),
            3 => Some(Self::Budget),
            4 => Some(Self::Unsupported),
            5 => Some(Self::UnknownNamespace),
            6 => Some(Self::StaleRevision),
            7 => Some(Self::Locked),
            8 => Some(Self::CorruptState),
            9 => Some(Self::Io),
            10 => Some(Self::Internal),
            11 => Some(Self::Uncertain),
            _ => None,
        }
    }

    /// Stable snake_case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::InvalidRequest => "invalid_request",
            Self::Budget => "budget",
            Self::Unsupported => "unsupported",
            Self::UnknownNamespace => "unknown_namespace",
            Self::StaleRevision => "stale_revision",
            Self::Locked => "locked",
            Self::CorruptState => "corrupt_state",
            Self::Io => "io",
            Self::Uncertain => "uncertain",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── messages ────────────────────────────────────────────────────────────────

/// One protocol v1 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Handshake offer; must be the first frame (host -> component).
    Hello {
        /// Lowest protocol version the host supports.
        min: u16,
        /// Highest protocol version the host supports.
        max: u16,
        /// Component name the host expects.
        component: String,
        /// Host version string.
        version: String,
    },
    /// Handshake answer (component -> host).
    HelloAck {
        /// Negotiated protocol version.
        protocol: u16,
        /// Component name.
        component: String,
        /// Component version.
        version: String,
    },
    /// Open (create when absent) and lock one namespace (host -> component).
    OpenNamespace {
        /// Non-zero request id for this exchange.
        request: u64,
        /// Namespace name.
        namespace: String,
    },
    /// Read one page of the current committed snapshot (host -> component).
    ReadSnapshot {
        /// Non-zero request id for this exchange.
        request: u64,
        /// Open namespace name.
        namespace: String,
        /// Zero-based first row index in key order.
        start_row: u32,
        /// Maximum rows to return; `0` means [`MAX_READ_ROWS`].
        max_rows: u32,
        /// Maximum row-value bytes to return; `0` means [`MAX_READ_BYTES`].
        max_bytes: u32,
    },
    /// Atomically apply one batch to a namespace (host -> component).
    CommitBatch {
        /// Non-zero request id for this exchange.
        request: u64,
        /// Open namespace name.
        namespace: String,
        /// Revision the host read before building the batch; `0` for a
        /// namespace that has never been committed.
        expected_revision: u64,
        /// Rows to insert or replace.
        upserts: Vec<Row>,
        /// Keys to remove.
        deletes: Vec<String>,
    },
    /// Restore the previous revision as a new revision (host -> component).
    Rollback {
        /// Non-zero request id for this exchange.
        request: u64,
        /// Open namespace name.
        namespace: String,
        /// Current revision the host observed.
        expected_revision: u64,
    },
    /// Flush, release namespace locks, and exit (host -> component).
    Shutdown,
    /// Namespace opened or already open (component -> host).
    NamespaceOpened {
        /// Request id from `OpenNamespace`.
        request: u64,
        /// Namespace name.
        namespace: String,
        /// Current committed revision (`0` when empty).
        revision: u64,
        /// Current row count.
        rows: u32,
        /// Current row-value bytes.
        bytes: u64,
    },
    /// One page of a committed snapshot (component -> host).
    SnapshotChunk {
        /// Request id from `ReadSnapshot`.
        request: u64,
        /// Namespace name.
        namespace: String,
        /// Revision the rows belong to.
        revision: u64,
        /// Zero-based row index of the first returned row.
        start_row: u32,
        /// Rows in key order.
        rows: Vec<Row>,
        /// Rows in the whole snapshot.
        total_rows: u32,
        /// Row-value bytes in the whole snapshot.
        total_bytes: u64,
        /// Whether this page reaches the end of the snapshot.
        done: bool,
    },
    /// Batch committed atomically (component -> host).
    Committed {
        /// Request id from `CommitBatch`.
        request: u64,
        /// Namespace name.
        namespace: String,
        /// New committed revision.
        revision: u64,
        /// Upserts applied.
        rows_written: u32,
        /// Deletes applied.
        rows_removed: u32,
        /// Row-value bytes written by the batch.
        bytes_written: u64,
        /// Row count after the commit.
        total_rows: u32,
        /// Row-value bytes after the commit.
        total_bytes: u64,
    },
    /// Previous revision restored as a new revision (component -> host).
    RolledBack {
        /// Request id from `Rollback`.
        request: u64,
        /// Namespace name.
        namespace: String,
        /// New committed revision.
        revision: u64,
        /// Revision whose contents were restored.
        restored_revision: u64,
        /// Row count after the rollback.
        total_rows: u32,
        /// Row-value bytes after the rollback.
        total_bytes: u64,
    },
    /// Typed error (component -> host).
    Error {
        /// Request id, or [`CONNECTION_ID`] for a connection-level failure.
        request: u64,
        /// Error category.
        kind: ErrorKind,
        /// Bounded static diagnostic; never echoed keys, values, or paths.
        message: String,
    },
    /// Namespaces released; the component exits after this frame
    /// (component -> host).
    ShutdownAck,
}

impl Message {
    /// Wire tag of this message.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Hello { .. } => TAG_HELLO,
            Self::HelloAck { .. } => TAG_HELLO_ACK,
            Self::OpenNamespace { .. } => TAG_OPEN_NAMESPACE,
            Self::ReadSnapshot { .. } => TAG_READ_SNAPSHOT,
            Self::CommitBatch { .. } => TAG_COMMIT_BATCH,
            Self::Rollback { .. } => TAG_ROLLBACK,
            Self::Shutdown => TAG_SHUTDOWN,
            Self::NamespaceOpened { .. } => TAG_NAMESPACE_OPENED,
            Self::SnapshotChunk { .. } => TAG_SNAPSHOT_CHUNK,
            Self::Committed { .. } => TAG_COMMITTED,
            Self::RolledBack { .. } => TAG_ROLLED_BACK,
            Self::Error { .. } => TAG_ERROR,
            Self::ShutdownAck => TAG_SHUTDOWN_ACK,
        }
    }
}

// ── grammar ─────────────────────────────────────────────────────────────────

/// Whether `name` matches `[a-z0-9][a-z0-9._-]{0,63}` with no dot segment.
#[must_use]
pub fn valid_namespace_name(name: &str) -> bool {
    valid_name(name, MAX_NAMESPACE_NAME_BYTES)
}

/// Whether `key` matches `[a-z0-9][a-z0-9._-]{0,127}` with no dot segment.
#[must_use]
pub fn valid_key(key: &str) -> bool {
    valid_name(key, MAX_KEY_BYTES)
}

fn valid_name(value: &str, max: usize) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > max {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        return false;
    }
    // Reject empty dot segments (`..`) so a name can never read as a path
    // traversal even before it is joined to the storage root.
    !value.contains("..")
}

// ── errors ──────────────────────────────────────────────────────────────────

/// Wire codec failure (owned; no `io::Error` escapes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The underlying stream failed.
    Io(io::ErrorKind),
    /// A frame exceeds [`MAX_FRAME_BYTES`] (or an encoder field exceeds its
    /// bound).
    TooLarge {
        /// Observed length.
        len: usize,
    },
    /// A zero-length frame.
    EmptyFrame,
    /// A frame ended before a field was complete.
    Truncated,
    /// A frame carried bytes after the last field.
    TrailingBytes,
    /// The tag is not assigned in protocol v1.
    UnknownTag(u8),
    /// A string field is not UTF-8.
    InvalidUtf8,
    /// A field violates its grammar or bound.
    InvalidField(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(f, "stream i/o error: {kind}"),
            Self::TooLarge { len } => {
                write!(f, "frame is {len} bytes (limit {MAX_FRAME_BYTES})")
            }
            Self::EmptyFrame => f.write_str("empty frame"),
            Self::Truncated => f.write_str("truncated frame"),
            Self::TrailingBytes => f.write_str("trailing bytes after the last field"),
            Self::UnknownTag(tag) => write!(f, "unknown tag 0x{tag:02x}"),
            Self::InvalidUtf8 => f.write_str("string field is not UTF-8"),
            Self::InvalidField(reason) => write!(f, "invalid field: {reason}"),
        }
    }
}

impl std::error::Error for WireError {}

// ── framing ─────────────────────────────────────────────────────────────────

/// Reads length-prefixed frames from a stream.
pub struct FrameReader<R> {
    reader: R,
}

impl<R: Read> FrameReader<R> {
    /// Wraps `reader`.
    pub const fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Reads one frame payload, or `None` at a clean EOF between frames.
    ///
    /// The four-byte header is rejected before any payload allocation or
    /// read when the declared length is zero or over [`MAX_FRAME_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] for I/O failures, a partial header, an empty or
    /// oversize frame, or a truncated payload.
    pub fn read_frame(&mut self) -> Result<Option<Vec<u8>>, WireError> {
        let mut header = [0u8; FRAME_HEADER_BYTES];
        let mut filled = 0;
        while filled < header.len() {
            match self.reader.read(&mut header[filled..]) {
                Ok(0) if filled == 0 => return Ok(None),
                Ok(0) => return Err(WireError::Truncated),
                Ok(n) => filled += n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(WireError::Io(error.kind())),
            }
        }
        let len = u32::from_be_bytes(header) as usize;
        if len == 0 {
            return Err(WireError::EmptyFrame);
        }
        if len > MAX_FRAME_BYTES {
            return Err(WireError::TooLarge { len });
        }
        let mut payload = vec![0u8; len];
        self.reader
            .read_exact(&mut payload)
            .map_err(|error| match error.kind() {
                io::ErrorKind::UnexpectedEof => WireError::Truncated,
                kind => WireError::Io(kind),
            })?;
        Ok(Some(payload))
    }

    /// Reads and decodes one message, or `None` at a clean EOF.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] for framing failures (see
    /// [`FrameReader::read_frame`]) and decode failures.
    pub fn read_message(&mut self) -> Result<Option<Message>, WireError> {
        self.read_frame()?
            .map(|payload| decode_message(&payload))
            .transpose()
    }
}

/// Encodes one complete frame (length prefix included).
///
/// # Errors
///
/// Returns [`WireError`] when a field violates its bound or the payload
/// exceeds [`MAX_FRAME_BYTES`].
pub fn encode_frame(message: &Message) -> Result<Vec<u8>, WireError> {
    let payload = encode_message(message)?;
    let len =
        u32::try_from(payload.len()).map_err(|_| WireError::TooLarge { len: payload.len() })?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Writes one complete frame in a single `write_all`.
///
/// # Errors
///
/// Returns [`WireError`] for encode or I/O failures.
pub fn write_frame<W: Write>(writer: &mut W, message: &Message) -> Result<(), WireError> {
    let frame = encode_frame(message)?;
    writer
        .write_all(&frame)
        .map_err(|error| WireError::Io(error.kind()))
}

/// Encodes one message payload (tag included, no length prefix).
///
/// # Errors
///
/// Returns [`WireError`] when a field violates its bound or the payload
/// exceeds [`MAX_FRAME_BYTES`].
pub fn encode_message(message: &Message) -> Result<Vec<u8>, WireError> {
    let mut encoder = Encoder::default();
    match message {
        Message::Hello {
            min,
            max,
            component,
            version,
        } => {
            encoder.u8(TAG_HELLO);
            encoder.u16(*min);
            encoder.u16(*max);
            encoder.component_name(component)?;
            encoder.version(version)?;
        }
        Message::HelloAck {
            protocol,
            component,
            version,
        } => {
            encoder.u8(TAG_HELLO_ACK);
            encoder.u16(*protocol);
            encoder.component_name(component)?;
            encoder.version(version)?;
        }
        Message::OpenNamespace { request, namespace } => {
            encoder.u8(TAG_OPEN_NAMESPACE);
            encoder.request(*request)?;
            encoder.namespace(namespace)?;
        }
        Message::ReadSnapshot {
            request,
            namespace,
            start_row,
            max_rows,
            max_bytes,
        } => {
            if *max_rows as usize > MAX_READ_ROWS {
                return Err(WireError::InvalidField("max_rows"));
            }
            if *max_bytes as usize > MAX_READ_BYTES {
                return Err(WireError::InvalidField("max_bytes"));
            }
            encoder.u8(TAG_READ_SNAPSHOT);
            encoder.request(*request)?;
            encoder.namespace(namespace)?;
            encoder.u32(*start_row);
            encoder.u32(*max_rows);
            encoder.u32(*max_bytes);
        }
        Message::CommitBatch {
            request,
            namespace,
            expected_revision,
            upserts,
            deletes,
        } => {
            encoder.u8(TAG_COMMIT_BATCH);
            encoder.request(*request)?;
            encoder.namespace(namespace)?;
            encoder.u64(*expected_revision);
            encoder.rows(upserts)?;
            encoder.delete_keys(deletes)?;
        }
        Message::Rollback {
            request,
            namespace,
            expected_revision,
        } => {
            encoder.u8(TAG_ROLLBACK);
            encoder.request(*request)?;
            encoder.namespace(namespace)?;
            encoder.u64(*expected_revision);
        }
        Message::Shutdown => encoder.u8(TAG_SHUTDOWN),
        Message::NamespaceOpened {
            request,
            namespace,
            revision,
            rows,
            bytes,
        } => {
            if *rows as usize > MAX_ROWS {
                return Err(WireError::InvalidField("rows"));
            }
            if *bytes > MAX_SNAPSHOT_BYTES as u64 {
                return Err(WireError::InvalidField("bytes"));
            }
            encoder.u8(TAG_NAMESPACE_OPENED);
            encoder.request(*request)?;
            encoder.namespace(namespace)?;
            encoder.u64(*revision);
            encoder.u32(*rows);
            encoder.u64(*bytes);
        }
        Message::SnapshotChunk {
            request,
            namespace,
            revision,
            start_row,
            rows,
            total_rows,
            total_bytes,
            done,
        } => {
            if *total_rows as usize > MAX_ROWS {
                return Err(WireError::InvalidField("total_rows"));
            }
            if *total_bytes > MAX_SNAPSHOT_BYTES as u64 {
                return Err(WireError::InvalidField("total_bytes"));
            }
            encoder.u8(TAG_SNAPSHOT_CHUNK);
            encoder.request(*request)?;
            encoder.namespace(namespace)?;
            encoder.u64(*revision);
            encoder.u32(*start_row);
            encoder.response_rows(rows)?;
            encoder.u32(*total_rows);
            encoder.u64(*total_bytes);
            encoder.u8(u8::from(*done));
        }
        Message::Committed {
            request,
            namespace,
            revision,
            rows_written,
            rows_removed,
            bytes_written,
            total_rows,
            total_bytes,
        } => {
            if *total_rows as usize > MAX_ROWS {
                return Err(WireError::InvalidField("total_rows"));
            }
            if *rows_written as usize > MAX_BATCH_ROWS || *rows_removed as usize > MAX_BATCH_ROWS {
                return Err(WireError::InvalidField("batch rows"));
            }
            if *bytes_written > MAX_BATCH_BYTES as u64 {
                return Err(WireError::InvalidField("bytes_written"));
            }
            if *total_bytes > MAX_SNAPSHOT_BYTES as u64 {
                return Err(WireError::InvalidField("total_bytes"));
            }
            encoder.u8(TAG_COMMITTED);
            encoder.request(*request)?;
            encoder.namespace(namespace)?;
            encoder.u64(*revision);
            encoder.u32(*rows_written);
            encoder.u32(*rows_removed);
            encoder.u64(*bytes_written);
            encoder.u32(*total_rows);
            encoder.u64(*total_bytes);
        }
        Message::RolledBack {
            request,
            namespace,
            revision,
            restored_revision,
            total_rows,
            total_bytes,
        } => {
            if *total_rows as usize > MAX_ROWS {
                return Err(WireError::InvalidField("total_rows"));
            }
            if *total_bytes > MAX_SNAPSHOT_BYTES as u64 {
                return Err(WireError::InvalidField("total_bytes"));
            }
            encoder.u8(TAG_ROLLED_BACK);
            encoder.request(*request)?;
            encoder.namespace(namespace)?;
            encoder.u64(*revision);
            encoder.u64(*restored_revision);
            encoder.u32(*total_rows);
            encoder.u64(*total_bytes);
        }
        Message::Error {
            request,
            kind,
            message,
        } => {
            encoder.u8(TAG_ERROR);
            encoder.u64(*request);
            encoder.u8(kind.code());
            encoder.diagnostic(message)?;
        }
        Message::ShutdownAck => encoder.u8(TAG_SHUTDOWN_ACK),
    }
    let payload = encoder.finish();
    if payload.len() > MAX_FRAME_BYTES {
        return Err(WireError::TooLarge { len: payload.len() });
    }
    Ok(payload)
}

/// Decodes one message payload (tag included, no length prefix).
///
/// # Errors
///
/// Returns [`WireError`] for an unknown tag, truncation, trailing bytes,
/// invalid UTF-8, unknown enum codes, zero request ids, invalid namespace or
/// key grammar, or any bound violation.
pub fn decode_message(payload: &[u8]) -> Result<Message, WireError> {
    let mut decoder = Decoder::new(payload);
    let tag = decoder.u8()?;
    let message = match tag {
        TAG_HELLO => Message::Hello {
            min: decoder.u16()?,
            max: decoder.u16()?,
            component: decoder.component_name()?,
            version: decoder.version()?,
        },
        TAG_HELLO_ACK => Message::HelloAck {
            protocol: decoder.u16()?,
            component: decoder.component_name()?,
            version: decoder.version()?,
        },
        TAG_OPEN_NAMESPACE => Message::OpenNamespace {
            request: decoder.request()?,
            namespace: decoder.namespace()?,
        },
        TAG_READ_SNAPSHOT => {
            let request = decoder.request()?;
            let namespace = decoder.namespace()?;
            let start_row = decoder.u32()?;
            let max_rows = decoder.u32()?;
            let max_bytes = decoder.u32()?;
            if max_rows as usize > MAX_READ_ROWS {
                return Err(WireError::InvalidField("max_rows"));
            }
            if max_bytes as usize > MAX_READ_BYTES {
                return Err(WireError::InvalidField("max_bytes"));
            }
            Message::ReadSnapshot {
                request,
                namespace,
                start_row,
                max_rows,
                max_bytes,
            }
        }
        TAG_COMMIT_BATCH => {
            let request = decoder.request()?;
            let namespace = decoder.namespace()?;
            let expected_revision = decoder.u64()?;
            let upserts = decoder.rows()?;
            let deletes = decoder.delete_keys()?;
            Message::CommitBatch {
                request,
                namespace,
                expected_revision,
                upserts,
                deletes,
            }
        }
        TAG_ROLLBACK => Message::Rollback {
            request: decoder.request()?,
            namespace: decoder.namespace()?,
            expected_revision: decoder.u64()?,
        },
        TAG_SHUTDOWN => Message::Shutdown,
        TAG_NAMESPACE_OPENED => {
            let request = decoder.request()?;
            let namespace = decoder.namespace()?;
            let revision = decoder.u64()?;
            let rows = decoder.u32()?;
            let bytes = decoder.u64()?;
            if rows as usize > MAX_ROWS {
                return Err(WireError::InvalidField("rows"));
            }
            if bytes > MAX_SNAPSHOT_BYTES as u64 {
                return Err(WireError::InvalidField("bytes"));
            }
            Message::NamespaceOpened {
                request,
                namespace,
                revision,
                rows,
                bytes,
            }
        }
        TAG_SNAPSHOT_CHUNK => {
            let request = decoder.request()?;
            let namespace = decoder.namespace()?;
            let revision = decoder.u64()?;
            let start_row = decoder.u32()?;
            let rows = decoder.response_rows()?;
            let total_rows = decoder.u32()?;
            let total_bytes = decoder.u64()?;
            let done = decoder.bool()?;
            if total_rows as usize > MAX_ROWS {
                return Err(WireError::InvalidField("total_rows"));
            }
            if total_bytes > MAX_SNAPSHOT_BYTES as u64 {
                return Err(WireError::InvalidField("total_bytes"));
            }
            Message::SnapshotChunk {
                request,
                namespace,
                revision,
                start_row,
                rows,
                total_rows,
                total_bytes,
                done,
            }
        }
        TAG_COMMITTED => {
            let request = decoder.request()?;
            let namespace = decoder.namespace()?;
            let revision = decoder.u64()?;
            let rows_written = decoder.u32()?;
            let rows_removed = decoder.u32()?;
            let bytes_written = decoder.u64()?;
            let total_rows = decoder.u32()?;
            let total_bytes = decoder.u64()?;
            if total_rows as usize > MAX_ROWS {
                return Err(WireError::InvalidField("total_rows"));
            }
            if rows_written as usize > MAX_BATCH_ROWS || rows_removed as usize > MAX_BATCH_ROWS {
                return Err(WireError::InvalidField("batch rows"));
            }
            if bytes_written > MAX_BATCH_BYTES as u64 {
                return Err(WireError::InvalidField("bytes_written"));
            }
            if total_bytes > MAX_SNAPSHOT_BYTES as u64 {
                return Err(WireError::InvalidField("total_bytes"));
            }
            Message::Committed {
                request,
                namespace,
                revision,
                rows_written,
                rows_removed,
                bytes_written,
                total_rows,
                total_bytes,
            }
        }
        TAG_ROLLED_BACK => {
            let request = decoder.request()?;
            let namespace = decoder.namespace()?;
            let revision = decoder.u64()?;
            let restored_revision = decoder.u64()?;
            let total_rows = decoder.u32()?;
            let total_bytes = decoder.u64()?;
            if total_rows as usize > MAX_ROWS {
                return Err(WireError::InvalidField("total_rows"));
            }
            if total_bytes > MAX_SNAPSHOT_BYTES as u64 {
                return Err(WireError::InvalidField("total_bytes"));
            }
            Message::RolledBack {
                request,
                namespace,
                revision,
                restored_revision,
                total_rows,
                total_bytes,
            }
        }
        TAG_ERROR => {
            let request = decoder.u64()?;
            let kind_code = decoder.u8()?;
            let kind =
                ErrorKind::from_code(kind_code).ok_or(WireError::InvalidField("error kind"))?;
            Message::Error {
                request,
                kind,
                message: decoder.diagnostic()?,
            }
        }
        TAG_SHUTDOWN_ACK => Message::ShutdownAck,
        other => return Err(WireError::UnknownTag(other)),
    };
    if !decoder.is_empty() {
        return Err(WireError::TrailingBytes);
    }
    Ok(message)
}

/// Component name this binary answers to in `Hello`.
#[must_use]
pub fn expected_component_name() -> &'static str {
    COMPONENT_NAME
}

/// Protocol version range this binary supports.
#[must_use]
pub const fn supported_protocol_range() -> (u16, u16) {
    (PROTOCOL_VERSION, PROTOCOL_VERSION)
}

/// Negotiates `[min, max]` against this component's range.
///
/// Returns the highest overlapping version, or `None` when the ranges do
/// not intersect.
#[must_use]
pub fn negotiate(min: u16, max: u16) -> Option<u16> {
    if min > max {
        return None;
    }
    let low = min.max(PROTOCOL_VERSION);
    let high = max.min(PROTOCOL_VERSION);
    (low <= high).then_some(high)
}

// ── encoder / decoder ───────────────────────────────────────────────────────

#[derive(Default)]
struct Encoder {
    buffer: Vec<u8>,
}

impl Encoder {
    fn u8(&mut self, value: u8) {
        self.buffer.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&mut self, data: &[u8]) {
        self.u32(u32::try_from(data.len()).unwrap_or(u32::MAX));
        self.buffer.extend_from_slice(data);
    }

    fn request(&mut self, request: u64) -> Result<(), WireError> {
        if request == 0 {
            return Err(WireError::InvalidField("zero request id"));
        }
        self.u64(request);
        Ok(())
    }

    fn component_name(&mut self, value: &str) -> Result<(), WireError> {
        let bytes = value.as_bytes();
        let valid = !bytes.is_empty()
            && bytes.len() <= MAX_COMPONENT_NAME_BYTES
            && bytes[0].is_ascii_lowercase()
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
        if !valid {
            return Err(WireError::InvalidField("component name"));
        }
        self.bytes(bytes);
        Ok(())
    }

    fn version(&mut self, value: &str) -> Result<(), WireError> {
        let valid = !value.is_empty()
            && value.len() <= MAX_VERSION_BYTES
            && value.bytes().all(|b| b.is_ascii_graphic() || b == b' ');
        if !valid {
            return Err(WireError::InvalidField("version"));
        }
        self.bytes(value.as_bytes());
        Ok(())
    }

    fn namespace(&mut self, value: &str) -> Result<(), WireError> {
        if !valid_namespace_name(value) {
            return Err(WireError::InvalidField("namespace"));
        }
        self.bytes(value.as_bytes());
        Ok(())
    }

    fn rows(&mut self, rows: &[Row]) -> Result<(), WireError> {
        if rows.len() > MAX_BATCH_ROWS {
            return Err(WireError::InvalidField("upserts"));
        }
        self.u32(u32::try_from(rows.len()).unwrap_or(u32::MAX));
        let mut total = 0usize;
        let mut seen = BTreeSet::new();
        for row in rows {
            if !valid_key(&row.key) {
                return Err(WireError::InvalidField("row key"));
            }
            if !seen.insert(row.key.as_str()) {
                return Err(WireError::InvalidField("duplicate row key"));
            }
            if row.value.len() > MAX_VALUE_BYTES {
                return Err(WireError::InvalidField("row value"));
            }
            total = total.saturating_add(row.key.len() + row.value.len() + 8);
            self.bytes(row.key.as_bytes());
            self.bytes(&row.value);
        }
        if total > MAX_BATCH_BYTES {
            return Err(WireError::InvalidField("batch bytes"));
        }
        Ok(())
    }

    fn response_rows(&mut self, rows: &[Row]) -> Result<(), WireError> {
        if rows.len() > MAX_READ_ROWS {
            return Err(WireError::InvalidField("rows"));
        }
        self.u32(u32::try_from(rows.len()).unwrap_or(u32::MAX));
        let mut total = 0usize;
        for row in rows {
            if !valid_key(&row.key) {
                return Err(WireError::InvalidField("row key"));
            }
            if row.value.len() > MAX_VALUE_BYTES {
                return Err(WireError::InvalidField("row value"));
            }
            total = total.saturating_add(row.key.len() + row.value.len());
            self.bytes(row.key.as_bytes());
            self.bytes(&row.value);
        }
        if total > MAX_READ_BYTES {
            return Err(WireError::InvalidField("read bytes"));
        }
        Ok(())
    }

    fn delete_keys(&mut self, keys: &[String]) -> Result<(), WireError> {
        if keys.len() > MAX_BATCH_ROWS {
            return Err(WireError::InvalidField("deletes"));
        }
        self.u32(u32::try_from(keys.len()).unwrap_or(u32::MAX));
        let mut total = 0usize;
        let mut seen = BTreeSet::new();
        for key in keys {
            if !valid_key(key) {
                return Err(WireError::InvalidField("delete key"));
            }
            if !seen.insert(key.as_str()) {
                return Err(WireError::InvalidField("duplicate delete key"));
            }
            total = total.saturating_add(key.len() + 4);
            self.bytes(key.as_bytes());
        }
        if total > MAX_BATCH_BYTES {
            return Err(WireError::InvalidField("batch bytes"));
        }
        Ok(())
    }

    fn diagnostic(&mut self, message: &str) -> Result<(), WireError> {
        let valid = !message.is_empty()
            && message.len() <= MAX_ERROR_MESSAGE_BYTES
            && message.bytes().all(|b| (0x20..=0x7e).contains(&b));
        if !valid {
            return Err(WireError::InvalidField("error message"));
        }
        self.bytes(message.as_bytes());
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.buffer
    }
}

struct Decoder<'a> {
    buffer: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    const fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self.position.checked_add(len).ok_or(WireError::Truncated)?;
        if end > self.buffer.len() {
            return Err(WireError::Truncated);
        }
        let slice = &self.buffer[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    fn bool(&mut self) -> Result<bool, WireError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::InvalidField("bool")),
        }
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn request(&mut self) -> Result<u64, WireError> {
        let request = self.u64()?;
        if request == 0 {
            return Err(WireError::InvalidField("zero request id"));
        }
        Ok(request)
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, WireError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(WireError::InvalidField("byte length"));
        }
        Ok(self.take(len)?.to_vec())
    }

    fn str_bounded(&mut self, max: usize, field: &'static str) -> Result<String, WireError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(WireError::InvalidField(field));
        }
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| WireError::InvalidUtf8)
    }

    fn component_name(&mut self) -> Result<String, WireError> {
        let name = self.str_bounded(MAX_COMPONENT_NAME_BYTES, "component name")?;
        let valid = !name.is_empty()
            && name.as_bytes()[0].is_ascii_lowercase()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !valid {
            return Err(WireError::InvalidField("component name"));
        }
        Ok(name)
    }

    fn version(&mut self) -> Result<String, WireError> {
        let version = self.str_bounded(MAX_VERSION_BYTES, "version")?;
        let valid =
            !version.is_empty() && version.bytes().all(|b| b.is_ascii_graphic() || b == b' ');
        if !valid {
            return Err(WireError::InvalidField("version"));
        }
        Ok(version)
    }

    fn namespace(&mut self) -> Result<String, WireError> {
        let namespace = self.str_bounded(MAX_NAMESPACE_NAME_BYTES, "namespace")?;
        if !valid_namespace_name(&namespace) {
            return Err(WireError::InvalidField("namespace"));
        }
        Ok(namespace)
    }

    fn rows(&mut self) -> Result<Vec<Row>, WireError> {
        let count = self.u32()? as usize;
        if count > MAX_BATCH_ROWS {
            return Err(WireError::InvalidField("upserts"));
        }
        let mut rows = Vec::with_capacity(count);
        let mut total = 0usize;
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let key = self.str_bounded(MAX_KEY_BYTES, "row key")?;
            if !valid_key(&key) {
                return Err(WireError::InvalidField("row key"));
            }
            if !seen.insert(key.clone()) {
                return Err(WireError::InvalidField("duplicate row key"));
            }
            let value = self.bytes(MAX_VALUE_BYTES)?;
            total = total.saturating_add(key.len() + value.len() + 8);
            rows.push(Row { key, value });
        }
        if total > MAX_BATCH_BYTES {
            return Err(WireError::InvalidField("batch bytes"));
        }
        Ok(rows)
    }

    fn response_rows(&mut self) -> Result<Vec<Row>, WireError> {
        let count = self.u32()? as usize;
        if count > MAX_READ_ROWS {
            return Err(WireError::InvalidField("rows"));
        }
        let mut rows = Vec::with_capacity(count);
        let mut total = 0usize;
        for _ in 0..count {
            let key = self.str_bounded(MAX_KEY_BYTES, "row key")?;
            if !valid_key(&key) {
                return Err(WireError::InvalidField("row key"));
            }
            let value = self.bytes(MAX_VALUE_BYTES)?;
            total = total.saturating_add(key.len() + value.len());
            rows.push(Row { key, value });
        }
        if total > MAX_READ_BYTES {
            return Err(WireError::InvalidField("read bytes"));
        }
        Ok(rows)
    }

    fn delete_keys(&mut self) -> Result<Vec<String>, WireError> {
        let count = self.u32()? as usize;
        if count > MAX_BATCH_ROWS {
            return Err(WireError::InvalidField("deletes"));
        }
        let mut keys = Vec::with_capacity(count);
        let mut total = 0usize;
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let key = self.str_bounded(MAX_KEY_BYTES, "delete key")?;
            if !valid_key(&key) {
                return Err(WireError::InvalidField("delete key"));
            }
            if !seen.insert(key.clone()) {
                return Err(WireError::InvalidField("duplicate delete key"));
            }
            total = total.saturating_add(key.len() + 4);
            keys.push(key);
        }
        if total > MAX_BATCH_BYTES {
            return Err(WireError::InvalidField("batch bytes"));
        }
        Ok(keys)
    }

    fn diagnostic(&mut self) -> Result<String, WireError> {
        let message = self.str_bounded(MAX_ERROR_MESSAGE_BYTES, "error message")?;
        let valid = !message.is_empty() && message.bytes().all(|b| (0x20..=0x7e).contains(&b));
        if !valid {
            return Err(WireError::InvalidField("error message"));
        }
        Ok(message)
    }

    fn is_empty(&self) -> bool {
        self.position == self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(message: &Message) -> Vec<u8> {
        encode_frame(message).expect("encodes")
    }

    fn roundtrip(message: Message) {
        let encoded = frame(&message);
        let mut reader = FrameReader::new(encoded.as_slice());
        assert_eq!(reader.read_message().expect("decodes"), Some(message));
        assert_eq!(reader.read_message().expect("clean eof"), None);
    }

    fn hello() -> Message {
        Message::Hello {
            min: 1,
            max: 1,
            component: "storage".to_owned(),
            version: "0.0.1".to_owned(),
        }
    }

    fn rows() -> Vec<Row> {
        vec![
            Row {
                key: "alpha".to_owned(),
                value: b"one".to_vec(),
            },
            Row {
                key: "beta".to_owned(),
                value: Vec::new(),
            },
        ]
    }

    #[test]
    fn every_message_roundtrips() {
        roundtrip(hello());
        roundtrip(Message::HelloAck {
            protocol: 1,
            component: "storage".to_owned(),
            version: "0.0.1".to_owned(),
        });
        roundtrip(Message::OpenNamespace {
            request: 1,
            namespace: "session-1".to_owned(),
        });
        roundtrip(Message::ReadSnapshot {
            request: 2,
            namespace: "session-1".to_owned(),
            start_row: 0,
            max_rows: 32,
            max_bytes: 1024,
        });
        roundtrip(Message::CommitBatch {
            request: 3,
            namespace: "session-1".to_owned(),
            expected_revision: 4,
            upserts: rows(),
            deletes: vec!["gamma".to_owned()],
        });
        roundtrip(Message::Rollback {
            request: 4,
            namespace: "session-1".to_owned(),
            expected_revision: 5,
        });
        roundtrip(Message::Shutdown);
        roundtrip(Message::NamespaceOpened {
            request: 1,
            namespace: "session-1".to_owned(),
            revision: 2,
            rows: 2,
            bytes: 6,
        });
        roundtrip(Message::SnapshotChunk {
            request: 2,
            namespace: "session-1".to_owned(),
            revision: 2,
            start_row: 0,
            rows: rows(),
            total_rows: 2,
            total_bytes: 6,
            done: true,
        });
        roundtrip(Message::Committed {
            request: 3,
            namespace: "session-1".to_owned(),
            revision: 5,
            rows_written: 2,
            rows_removed: 1,
            bytes_written: 6,
            total_rows: 2,
            total_bytes: 6,
        });
        roundtrip(Message::RolledBack {
            request: 4,
            namespace: "session-1".to_owned(),
            revision: 6,
            restored_revision: 4,
            total_rows: 2,
            total_bytes: 6,
        });
        roundtrip(Message::Error {
            request: 3,
            kind: ErrorKind::StaleRevision,
            message: "revision conflict".to_owned(),
        });
        roundtrip(Message::ShutdownAck);
    }

    #[test]
    fn oversized_frame_is_rejected_from_the_header() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_be_bytes());
        let mut reader = FrameReader::new(stream.as_slice());
        assert_eq!(
            reader.read_frame(),
            Err(WireError::TooLarge {
                len: MAX_FRAME_BYTES + 1
            })
        );
    }

    #[test]
    fn zero_length_frame_and_partial_header_are_rejected() {
        let mut reader = FrameReader::new([0u8, 0, 0, 0].as_slice());
        assert_eq!(reader.read_frame(), Err(WireError::EmptyFrame));

        let mut reader = FrameReader::new([0u8, 0].as_slice());
        assert_eq!(reader.read_frame(), Err(WireError::Truncated));
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let encoded = frame(&hello());
        let mut reader = FrameReader::new(&encoded[..encoded.len() - 1]);
        assert_eq!(reader.read_frame(), Err(WireError::Truncated));
    }

    #[test]
    fn unknown_tags_and_trailing_bytes_are_rejected() {
        assert_eq!(decode_message(&[0x7f]), Err(WireError::UnknownTag(0x7f)));
        let mut encoded = encode_message(&Message::Shutdown).unwrap();
        encoded.push(0);
        assert_eq!(decode_message(&encoded), Err(WireError::TrailingBytes));
    }

    #[test]
    fn zero_request_ids_are_rejected() {
        let mut encoded = encode_message(&Message::OpenNamespace {
            request: 1,
            namespace: "session-1".to_owned(),
        })
        .unwrap();
        encoded[1..9].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            decode_message(&encoded),
            Err(WireError::InvalidField("zero request id"))
        );

        let zero = Message::OpenNamespace {
            request: 0,
            namespace: "session-1".to_owned(),
        };
        assert_eq!(
            encode_message(&zero),
            Err(WireError::InvalidField("zero request id"))
        );
    }

    #[test]
    fn namespaces_and_keys_reject_path_shaped_values() {
        for bad in [
            "",
            "Upper",
            "-dash",
            ".dot",
            "has/slash",
            "has\\slash",
            "has space",
            "double..dot",
            "../escape",
            "with:colon",
            "x".repeat(MAX_NAMESPACE_NAME_BYTES + 1).as_str(),
        ] {
            assert!(!valid_namespace_name(bad), "namespace: {bad}");
        }
        for bad in [
            "",
            "Upper",
            "-dash",
            ".dot",
            "has/slash",
            "has\\slash",
            "has space",
            "double..dot",
            "../escape",
            "with:colon",
            "x".repeat(MAX_KEY_BYTES + 1).as_str(),
        ] {
            assert!(!valid_key(bad), "key: {bad}");
        }
        for good in ["a", "0", "session-1", "plugin.store_v2"] {
            assert!(valid_namespace_name(good), "namespace: {good}");
            assert!(valid_key(good), "key: {good}");
        }
        let message = Message::OpenNamespace {
            request: 1,
            namespace: "../escape".to_owned(),
        };
        assert_eq!(
            encode_message(&message),
            Err(WireError::InvalidField("namespace"))
        );
    }

    #[test]
    fn batch_and_value_bounds_are_enforced() {
        let too_many = vec![
            Row {
                key: "k".to_owned(),
                value: Vec::new(),
            };
            MAX_BATCH_ROWS + 1
        ];
        let message = Message::CommitBatch {
            request: 1,
            namespace: "ns".to_owned(),
            expected_revision: 0,
            upserts: too_many,
            deletes: Vec::new(),
        };
        assert_eq!(
            encode_message(&message),
            Err(WireError::InvalidField("upserts"))
        );

        let too_big = Message::CommitBatch {
            request: 1,
            namespace: "ns".to_owned(),
            expected_revision: 0,
            upserts: vec![Row {
                key: "big".to_owned(),
                value: vec![0; MAX_VALUE_BYTES + 1],
            }],
            deletes: Vec::new(),
        };
        assert_eq!(
            encode_message(&too_big),
            Err(WireError::InvalidField("row value"))
        );

        let duplicate = Message::CommitBatch {
            request: 1,
            namespace: "ns".to_owned(),
            expected_revision: 0,
            upserts: vec![
                Row {
                    key: "same".to_owned(),
                    value: Vec::new(),
                },
                Row {
                    key: "same".to_owned(),
                    value: Vec::new(),
                },
            ],
            deletes: Vec::new(),
        };
        assert_eq!(
            encode_message(&duplicate),
            Err(WireError::InvalidField("duplicate row key"))
        );
    }

    #[test]
    fn response_counters_are_bounded() {
        let too_many_rows = Message::Committed {
            request: 1,
            namespace: "ns".to_owned(),
            revision: 2,
            rows_written: u32::try_from(MAX_BATCH_ROWS + 1).unwrap(),
            rows_removed: 0,
            bytes_written: 0,
            total_rows: 1,
            total_bytes: 0,
        };
        assert_eq!(
            encode_message(&too_many_rows),
            Err(WireError::InvalidField("batch rows"))
        );

        let too_many_bytes = Message::SnapshotChunk {
            request: 1,
            namespace: "ns".to_owned(),
            revision: 2,
            start_row: 0,
            rows: Vec::new(),
            total_rows: 0,
            total_bytes: u64::try_from(MAX_SNAPSHOT_BYTES + 1).unwrap(),
            done: true,
        };
        assert_eq!(
            encode_message(&too_many_bytes),
            Err(WireError::InvalidField("total_bytes"))
        );
    }

    #[test]
    fn read_bounds_are_enforced() {
        let too_many_rows = Message::ReadSnapshot {
            request: 1,
            namespace: "ns".to_owned(),
            start_row: 0,
            max_rows: u32::try_from(MAX_READ_ROWS + 1).unwrap(),
            max_bytes: 0,
        };
        assert_eq!(
            encode_message(&too_many_rows),
            Err(WireError::InvalidField("max_rows"))
        );

        let too_many_bytes = Message::ReadSnapshot {
            request: 1,
            namespace: "ns".to_owned(),
            start_row: 0,
            max_rows: 1,
            max_bytes: u32::try_from(MAX_READ_BYTES + 1).unwrap(),
        };
        assert_eq!(
            encode_message(&too_many_bytes),
            Err(WireError::InvalidField("max_bytes"))
        );
    }

    #[test]
    fn error_messages_are_bounded_and_ascii() {
        let bad = Message::Error {
            request: 0,
            kind: ErrorKind::Protocol,
            message: "bad\nframe".to_owned(),
        };
        assert_eq!(
            encode_message(&bad),
            Err(WireError::InvalidField("error message"))
        );
        let too_long = Message::Error {
            request: 0,
            kind: ErrorKind::Protocol,
            message: "x".repeat(MAX_ERROR_MESSAGE_BYTES + 1),
        };
        assert_eq!(
            encode_message(&too_long),
            Err(WireError::InvalidField("error message"))
        );
    }

    #[test]
    fn handshake_negotiation_is_exact() {
        assert_eq!(negotiate(1, 1), Some(1));
        assert_eq!(negotiate(0, 1), Some(1));
        assert_eq!(negotiate(1, 9), Some(1));
        assert_eq!(negotiate(2, 9), None);
        assert_eq!(negotiate(2, 1), None);
    }

    #[test]
    fn error_codes_are_stable() {
        for kind in [
            ErrorKind::Protocol,
            ErrorKind::InvalidRequest,
            ErrorKind::Budget,
            ErrorKind::Unsupported,
            ErrorKind::UnknownNamespace,
            ErrorKind::StaleRevision,
            ErrorKind::Locked,
            ErrorKind::CorruptState,
            ErrorKind::Io,
            ErrorKind::Internal,
            ErrorKind::Uncertain,
        ] {
            assert_eq!(ErrorKind::from_code(kind.code()), Some(kind));
        }
        // v1 codes are additive: the added `uncertain` kind is 11 and the
        // pre-existing `internal` kind stays 10, so a v1 host never has a
        // known code silently change meaning.
        assert_eq!(ErrorKind::Protocol.code(), 1);
        assert_eq!(ErrorKind::InvalidRequest.code(), 2);
        assert_eq!(ErrorKind::Budget.code(), 3);
        assert_eq!(ErrorKind::Unsupported.code(), 4);
        assert_eq!(ErrorKind::UnknownNamespace.code(), 5);
        assert_eq!(ErrorKind::StaleRevision.code(), 6);
        assert_eq!(ErrorKind::Locked.code(), 7);
        assert_eq!(ErrorKind::CorruptState.code(), 8);
        assert_eq!(ErrorKind::Io.code(), 9);
        assert_eq!(ErrorKind::Internal.code(), 10);
        assert_eq!(ErrorKind::Uncertain.code(), 11);
        assert_eq!(ErrorKind::from_code(10), Some(ErrorKind::Internal));
        assert_eq!(ErrorKind::from_code(11), Some(ErrorKind::Uncertain));
        assert_eq!(ErrorKind::Uncertain.as_str(), "uncertain");
        assert_eq!(ErrorKind::from_code(0), None);
        assert_eq!(ErrorKind::from_code(12), None);
    }

    #[test]
    fn uncertain_error_roundtrips_on_the_wire() {
        let message = Message::Error {
            request: 7,
            kind: ErrorKind::Uncertain,
            message: "storage outcome uncertain; reopen namespace".to_owned(),
        };
        let encoded = encode_message(&message).expect("encode");
        assert_eq!(encoded[0], TAG_ERROR);
        assert_eq!(encoded[9], 11, "uncertain wire code must be 11");
        assert_eq!(decode_message(&encoded).expect("decode"), message);
    }
}
