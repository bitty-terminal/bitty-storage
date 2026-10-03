//! Retention selection, deletion evidence, history record bounds, and
//! the Core-owned backend seam.

use bitty_storage::ceiling::*;
use bitty_storage::history::*;
use bitty_storage::transcript::*;
use bitty_storage::{FileBackend, StorageBackend};

fn segment(id: u64, bytes: usize, sealed_at_secs: u64, sealed: bool) -> SegmentDescriptor {
    SegmentDescriptor {
        id,
        panel: 3,
        bytes,
        sealed_at_secs,
        sealed,
    }
}

fn segment_in(
    panel: u64,
    id: u64,
    bytes: usize,
    sealed_at_secs: u64,
    sealed: bool,
) -> SegmentDescriptor {
    SegmentDescriptor {
        id,
        panel,
        bytes,
        sealed_at_secs,
        sealed,
    }
}

#[test]
fn over_age_segments_selected_oldest_first() {
    let policy = RetentionPolicy {
        max_age_secs: 100,
        max_bytes: usize::MAX,
        max_segments: usize::MAX,
    };
    let segments = vec![
        segment(1, 10, 0, true),
        segment(2, 10, 50, true),
        segment(3, 10, 950, true),
        segment(4, 10, 999, false),
    ];
    // now = 1000: ids 1 (age 1000) and 2 (age 950) are over-age; the
    // unsealed segment 4 is never selected.
    assert_eq!(
        select_for_deletion(&segments, &policy, 1000),
        vec![(3, 1), (3, 2)]
    );
}

#[test]
fn count_and_byte_caps_enforced_oldest_first() {
    let policy = RetentionPolicy {
        max_age_secs: u64::MAX,
        max_bytes: 25,
        max_segments: 2,
    };
    let segments = vec![
        segment(1, 10, 10, true),
        segment(2, 10, 20, true),
        segment(3, 10, 30, true),
    ];
    // 3 segments / 30 bytes over caps of 2 / 25: oldest (id 1) goes.
    assert_eq!(select_for_deletion(&segments, &policy, 1000), vec![(3, 1)]);
}

#[test]
fn active_segment_never_selected_and_empty_is_stable() {
    let policy = RetentionPolicy::default();
    assert_eq!(
        select_for_deletion(&[], &policy, 0),
        Vec::<(u64, u64)>::new()
    );
    let segments = vec![segment(7, 10, 0, false)];
    assert_eq!(
        select_for_deletion(&segments, &policy, u64::MAX),
        Vec::<(u64, u64)>::new()
    );
}

#[test]
fn default_policy_matches_seal_bounds() {
    let policy = RetentionPolicy::default();
    assert_eq!(policy.max_segments, TRANSCRIPT_MAX_SEGMENTS_PER_PANEL);
    assert_eq!(
        policy.max_bytes,
        TRANSCRIPT_SEGMENT_MAX_BYTES * TRANSCRIPT_MAX_SEGMENTS_PER_PANEL
    );
}

#[test]
fn shared_segment_ids_stay_panel_scoped() {
    let policy = RetentionPolicy {
        max_age_secs: 100,
        max_bytes: usize::MAX,
        max_segments: usize::MAX,
    };
    // Two panels share segment id 1; only panel 1's copy is over-age.
    // A bare-id selection would exclude panel 2's live copy from the
    // kept set as a side effect; scoped pairs leave it unaffected.
    let segments = vec![
        segment_in(1, 1, 10, 0, true),
        segment_in(2, 1, 10, 950, true),
    ];
    assert_eq!(select_for_deletion(&segments, &policy, 1000), vec![(1, 1)]);
}

#[test]
fn byte_caps_count_each_panels_copy() {
    let policy = RetentionPolicy {
        max_age_secs: u64::MAX,
        max_bytes: 15,
        max_segments: usize::MAX,
    };
    // Same id in two panels plus a third segment: 30 kept bytes over a
    // 15-byte cap. Bare-id accounting would drop both id-1 copies from
    // the kept set after selecting the first, see only 10 kept bytes,
    // and stop early while bytes remain over cap.
    let segments = vec![
        segment_in(1, 1, 10, 10, true),
        segment_in(2, 1, 10, 20, true),
        segment_in(2, 2, 10, 30, true),
    ];
    assert_eq!(
        select_for_deletion(&segments, &policy, 1000),
        vec![(1, 1), (2, 1)]
    );
}

#[test]
fn deletion_evidence_shape() {
    let evidence = TranscriptDeletionEvidence {
        removed: vec![(3, 1), (3, 2)],
        bytes_removed: 120,
        index_dropped: true,
    };
    assert_eq!(evidence.removed.len(), 2);
    assert!(evidence.index_dropped);
}

#[test]
fn history_record_bounds() {
    let good = CommandRecord {
        panel: 1,
        workspace: 0,
        command: "ls -la".to_string(),
        cwd: Some("/tmp".to_string()),
        started_at_secs: 1_700_000_000,
        duration_ms: 12,
        exit_code: Some(0),
        actor: HistoryActor::User,
        external_ref: None,
    };
    assert!(validate_record(&good));
    let mut bad = good.clone();
    bad.command = "x".repeat(HISTORY_MAX_COMMAND_BYTES + 1);
    assert!(!validate_record(&bad));
    let mut bad_cwd = good.clone();
    bad_cwd.cwd = Some("y".repeat(MAX_SESSION_CWD_BYTES + 1));
    assert!(!validate_record(&bad_cwd));
}

#[test]
fn file_backend_seam_commit_load_delete() {
    let dir = std::env::temp_dir().join(format!(
        "bitty-seam-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("object.bin");
    let mut backend = FileBackend::new(path.clone(), 1024);
    assert_eq!(backend.path(), path.as_path());
    // Missing file is a quiet clean start.
    assert_eq!(backend.load().unwrap(), None);
    backend.commit(b"state-v1").unwrap();
    assert_eq!(backend.load().unwrap(), Some(b"state-v1".to_vec()));
    // Over-cap commits are denied with the previous state intact.
    assert!(backend.commit(&vec![0u8; 2048]).is_err());
    assert_eq!(backend.load().unwrap(), Some(b"state-v1".to_vec()));
    // Authoritative delete with evidence; post-delete load is clean.
    let evidence = backend.delete().unwrap();
    assert!(evidence.file_removed);
    assert_eq!(backend.load().unwrap(), None);
    // Deleting an absent file reports no removal.
    let evidence = backend.delete().unwrap();
    assert!(!evidence.file_removed);
    let _ = std::fs::remove_dir_all(&dir);
}
