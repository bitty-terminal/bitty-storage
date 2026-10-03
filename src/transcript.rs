//! Segmented transcript descriptors (types only, no persistence).
//!
//! The segmented transcript is greenfield work behind an explicit opt-in:
//! Core has no transcript emission points, so there is nothing to extract.
//! This module fixes the segment descriptor shape, the seal-bound
//! constants, and the retention-selection rule that a later implementation
//! must execute. Capture, sealing, compression, and the rebuildable index
//! are out of scope until the owning contract authorizes them.

use crate::ceiling::{TRANSCRIPT_MAX_SEGMENTS_PER_PANEL, TRANSCRIPT_SEGMENT_MAX_BYTES};

/// One sealed (or active) transcript segment descriptor.
///
/// Descriptors are metadata only: they name bytes a later implementation
/// owns, never the bytes themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentDescriptor {
    /// Monotonic segment identity within one panel transcript.
    pub id: u64,
    /// Panel identity the segment was captured from.
    pub panel: u64,
    /// Sealed byte size (at most [`TRANSCRIPT_SEGMENT_MAX_BYTES`]).
    pub bytes: usize,
    /// Capture time as Unix seconds (retention age input).
    pub sealed_at_secs: u64,
    /// Whether the segment is sealed (only sealed segments are
    /// retention-eligible; the active segment is never selected).
    pub sealed: bool,
}

/// Retention policy inputs: age and size caps in user-facing terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Maximum retained segment age in seconds.
    pub max_age_secs: u64,
    /// Maximum retained bytes across sealed segments.
    pub max_bytes: usize,
    /// Maximum retained sealed segments.
    pub max_segments: usize,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_age_secs: 30 * 24 * 3600,
            max_bytes: TRANSCRIPT_SEGMENT_MAX_BYTES * TRANSCRIPT_MAX_SEGMENTS_PER_PANEL,
            max_segments: TRANSCRIPT_MAX_SEGMENTS_PER_PANEL,
        }
    }
}

/// Selects sealed segments for deletion under `policy` at `now_secs`.
///
/// Pure policy evaluation (oldest-first): over-age segments first, then
/// oldest sealed segments until the count and byte caps hold. The active
/// (unsealed) segment is never selected. Returns `(panel, id)` pairs in
/// deletion order: segment ids are scoped per panel, so identical ids in
/// different panels stay distinct and each pair identifies the exact
/// bytes to delete.
#[must_use]
pub fn select_for_deletion(
    segments: &[SegmentDescriptor],
    policy: &RetentionPolicy,
    now_secs: u64,
) -> Vec<(u64, u64)> {
    let mut sealed: Vec<&SegmentDescriptor> = segments.iter().filter(|s| s.sealed).collect();
    sealed.sort_by_key(|s| (s.sealed_at_secs, s.panel, s.id));

    let mut selected = Vec::new();
    // Over-age segments are always eligible.
    for segment in &sealed {
        let age = now_secs.saturating_sub(segment.sealed_at_secs);
        if age > policy.max_age_secs {
            selected.push((segment.panel, segment.id));
        }
    }
    // Then enforce count and byte caps oldest-first.
    let remaining: Vec<&SegmentDescriptor> = sealed
        .iter()
        .filter(|s| !selected.contains(&(s.panel, s.id)))
        .copied()
        .collect();
    let mut kept = remaining.len();
    let mut kept_bytes: usize = remaining.iter().map(|s| s.bytes).sum();
    for segment in remaining {
        if kept <= policy.max_segments && kept_bytes <= policy.max_bytes {
            break;
        }
        selected.push((segment.panel, segment.id));
        kept -= 1;
        kept_bytes = kept_bytes.saturating_sub(segment.bytes);
    }
    selected
}

/// Evidence that a retention/purge pass removed bytes (never a filtered
/// view described as a purge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptDeletionEvidence {
    /// `(panel, id)` pairs whose bytes were removed, in deletion order.
    pub removed: Vec<(u64, u64)>,
    /// Bytes removed.
    pub bytes_removed: usize,
    /// Whether the derived index entries were dropped with the bytes (a
    /// rebuildable index must never resurrect deleted content).
    pub index_dropped: bool,
}
