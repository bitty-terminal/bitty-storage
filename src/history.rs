//! Command-history record types (types only, no persistence).
//!
//! Command history is the small, structured, indexable object derived from
//! the Core event stream behind opt-in capture. Like the transcript, it is
//! greenfield: this module fixes the record shape and bounds so later
//! contract work (`W-139` surface, `W-146` integration) has a stable
//! vocabulary. No history emission, index, or persistence lives here.

use crate::ceiling::HISTORY_MAX_COMMAND_BYTES;

/// Which actor produced a command record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryActor {
    /// Interactive user input.
    User,
    /// Plugin-driven execution.
    Plugin,
    /// Agent-driven execution (read-only default elsewhere).
    Agent,
}

/// One structured command record: command text plus Core-observed facts.
///
/// `OSC 133` markers are advisory only; a record is asserted from
/// Core-observed facts plus declared shell-integration evidence. The
/// optional external reference is opaque: a dangling reference after
/// provider removal surfaces as typed unavailability, never a silent gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRecord {
    /// Panel identity the command ran in.
    pub panel: u64,
    /// Workspace identity the command ran in.
    pub workspace: u64,
    /// Command text (bounded bytes).
    pub command: String,
    /// Working directory at execution, if observed.
    pub cwd: Option<String>,
    /// Start time as Unix seconds.
    pub started_at_secs: u64,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Exit code, if the command completed.
    pub exit_code: Option<i32>,
    /// Which actor ran the command.
    pub actor: HistoryActor,
    /// Opaque reference to an external history system, if any.
    pub external_ref: Option<String>,
}

/// Validates record bounds (command bytes; cwd reuse the session bound).
#[must_use]
pub fn validate_record(record: &CommandRecord) -> bool {
    if record.command.len() > HISTORY_MAX_COMMAND_BYTES {
        return false;
    }
    if record
        .cwd
        .as_ref()
        .is_some_and(|cwd| cwd.len() > crate::ceiling::MAX_SESSION_CWD_BYTES)
    {
        return false;
    }
    true
}
