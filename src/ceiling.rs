//! Every bound enforced by this crate, byte-for-byte with Core.
//!
//! The session ceilings mirror `bitty-runtime` session snapshot bounds; the
//! KV ceilings mirror the `bitty.store` filesystem backend. Core owns these
//! numbers as requirements; this crate enforces them fail-closed before any
//! mutation or filesystem commit. No bound here may change without the owning
//! contract task (CTX-0003 scope per the W-146 plan, gap 6).

/// Maximum session file bytes read or written.
pub const MAX_SESSION_FILE_BYTES: usize = 1_048_576;

/// Maximum bytes of any single session-file line.
pub const MAX_SESSION_LINE_BYTES: usize = 4096;

/// Maximum workspaces per session.
pub const MAX_SESSION_WORKSPACES: usize = 16;

/// Maximum panes per workspace.
pub const MAX_SESSION_PANES_PER_WORKSPACE: usize = 32;

/// Maximum panes across all workspaces (bounds decode CPU).
pub const MAX_SESSION_PANES_TOTAL: usize = 128;

/// Maximum scrollback lines persisted and restored per pane (newest kept).
pub const MAX_SESSION_SCROLLBACK_LINES_PER_PANE: usize = 200;

/// Maximum bytes of one persisted scrollback line.
pub const MAX_SESSION_LINE_TEXT_BYTES: usize = 4096;

/// Maximum bytes of a persisted cwd report.
pub const MAX_SESSION_CWD_BYTES: usize = 4096;

/// Maximum workspace-name chars.
pub const MAX_SESSION_NAME_CHARS: usize = 32;

/// Maximum layout S-expression nesting depth (recursion guard).
pub const MAX_SESSION_LAYOUT_DEPTH: usize = 64;

/// Maximum grid dimension accepted on restore (valid range is `1..=1000`).
pub const MAX_SESSION_GRID_DIM: usize = 1000;

/// Minimum grid dimension accepted on restore.
pub const MIN_SESSION_GRID_DIM: usize = 1;

/// Maximum stored KV value bytes per entry.
pub const STORE_MAX_VALUE_BYTES: usize = 8 * 1024;

/// Maximum entries per plugin KV store.
pub const STORE_MAX_ENTRIES: usize = 256;

/// Aggregate KV byte budget per plugin.
pub const STORE_MAX_TOTAL_BYTES: usize = 64 * 1024;

/// Maximum KV key bytes.
pub const STORE_MAX_KEY_BYTES: usize = 128;

/// Maximum KV store file bytes accepted on load (derived, not tuned).
pub const STORE_FILE_MAX_BYTES: usize =
    STORE_MAX_TOTAL_BYTES + STORE_MAX_ENTRIES * STORE_MAX_KEY_BYTES + 4096;

/// Maximum JSON recursion depth accepted by the KV parser and validator.
pub const JSON_MAX_DEPTH: usize = 16;

/// Current session file format version written by the encoder.
pub const SESSION_FORMAT_VERSION: u32 = 2;

/// Earliest session format version the decoder still migrates.
pub const SESSION_MIN_DECODE_VERSION: u32 = 1;

/// Directory name under the XDG state root.
pub const SESSION_APP_DIR_NAME: &str = "bitty";

/// Sessions subdirectory name.
pub const SESSIONS_DIR_NAME: &str = "sessions";

/// Session file name (version lives inside the file).
pub const SESSION_FILE_NAME: &str = "session";

/// Maximum sealed transcript segment bytes (seal bound).
pub const TRANSCRIPT_SEGMENT_MAX_BYTES: usize = 64 * 1024;

/// Maximum segments retained per panel transcript.
pub const TRANSCRIPT_MAX_SEGMENTS_PER_PANEL: usize = 64;

/// Maximum command-history records retained per panel.
pub const HISTORY_MAX_RECORDS_PER_PANEL: usize = 1000;

/// Maximum command-text bytes per history record.
pub const HISTORY_MAX_COMMAND_BYTES: usize = 4096;
