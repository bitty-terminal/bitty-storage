//! Atomic durable commit, stale-temp hygiene, capped load, and
//! partial-write recovery to a clean start.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use bitty_storage::atomic_io::*;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bitty-storage-{}-{}-{}",
        name,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Backdates a temp file's mtime past the sweep age so it reads as crash
/// litter (live-writer temps are always fresh).
fn backdate_as_litter(path: &std::path::Path) {
    use std::fs::FileTimes;
    let old =
        std::time::SystemTime::now() - std::time::Duration::from_secs(STALE_TEMP_AGE_SECS + 60);
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(FileTimes::new().set_modified(old))
        .unwrap();
}

#[test]
fn save_and_load_round_trip() {
    let dir = scratch_dir("roundtrip");
    let path = dir.join("session");
    save_session_bytes(&path, b"bitty-session v2\n").unwrap();
    assert_eq!(load_session_bytes(&path).unwrap(), b"bitty-session v2\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn over_cap_save_rejected_before_any_write() {
    let dir = scratch_dir("overcap");
    let path = dir.join("session");
    let big = vec![b'x'; bitty_storage::ceiling::MAX_SESSION_FILE_BYTES + 1];
    assert!(save_session_bytes(&path, &big).is_err());
    assert!(!path.exists(), "rejected payload must not touch the fs");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stale_temp_siblings_are_swept_before_writing() {
    let dir = scratch_dir("stale");
    let path = dir.join("session");
    let litter_1 = dir.join("session.tmp.111");
    let litter_2 = dir.join("session.tmp-222-0");
    std::fs::write(&litter_1, b"litter-1").unwrap();
    std::fs::write(&litter_2, b"litter-2").unwrap();
    backdate_as_litter(&litter_1);
    backdate_as_litter(&litter_2);
    std::fs::write(dir.join("unrelated.tmp.333"), b"keep").unwrap();
    save_session_bytes(&path, b"fresh").unwrap();
    assert!(!litter_1.exists());
    assert!(!litter_2.exists());
    assert!(dir.join("unrelated.tmp.333").exists());
    assert_eq!(load_session_bytes(&path).unwrap(), b"fresh");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sweep_never_deletes_live_temps() {
    let dir = scratch_dir("live");
    let path = dir.join("session");
    // A fresh temp (a concurrent saver's in-flight write) survives the
    // pre-write sweep; only aged litter is reclaimed.
    let live = dir.join("session.tmp-4242-0");
    std::fs::write(&live, b"in-flight").unwrap();
    save_session_bytes(&path, b"fresh").unwrap();
    assert!(live.exists(), "live temp must survive the sweep");
    assert_eq!(load_session_bytes(&path).unwrap(), b"fresh");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_saves_to_same_path_all_succeed() {
    use std::sync::{Arc, Barrier};
    let dir = scratch_dir("concurrent");
    let path = dir.join("session");
    save_session_bytes(&path, b"seed").unwrap();
    let threads = 8usize;
    let iters = 25usize;
    let barrier = Arc::new(Barrier::new(threads));
    let mut handles = Vec::new();
    for t in 0..threads {
        let barrier = barrier.clone();
        let path = path.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            for i in 0..iters {
                let payload = format!("t{t}-i{i}");
                save_session_bytes(&path, payload.as_bytes()).unwrap();
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    // Every save committed: the final file is one complete payload, never
    // a torn mix, and no temp sibling is left behind.
    let content = String::from_utf8(load_session_bytes(&path).unwrap()).unwrap();
    let (thread, iter) = content
        .strip_prefix('t')
        .and_then(|rest| rest.split_once("-i"))
        .expect("final content must be one complete payload");
    assert!(thread.parse::<usize>().is_ok_and(|t| t < threads));
    assert!(iter.parse::<usize>().is_ok_and(|i| i < iters));
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("session.tmp"))
        .collect();
    assert!(leftovers.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn no_temp_sibling_remains_after_commit() {
    let dir = scratch_dir("notemp");
    let path = dir.join("session");
    save_session_bytes(&path, b"data").unwrap();
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("session.tmp"))
        .collect();
    assert!(leftovers.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn capped_load_rejects_oversize_file() {
    let dir = scratch_dir("capped");
    let path = dir.join("session");
    std::fs::write(
        &path,
        vec![b'y'; bitty_storage::ceiling::MAX_SESSION_FILE_BYTES + 16],
    )
    .unwrap();
    match load_session_bytes(&path) {
        Err(LoadError::TooLarge { actual, limit }) => {
            assert_eq!(limit, bitty_storage::ceiling::MAX_SESSION_FILE_BYTES);
            assert_eq!(
                actual,
                bitty_storage::ceiling::MAX_SESSION_FILE_BYTES.saturating_add(1),
                "over-cap actual saturates at cap+1",
            );
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oversize_sparse_file_fails_fast_without_draining() {
    // A sparse multi-GB file proves bounded I/O: the old drain-the-tail
    // loop would read gigabytes here, while the saturated report stops
    // after cap+1 bytes. `set_len` keeps the test instant (no bytes
    // written) on filesystems with sparse support.
    let dir = scratch_dir("sparse");
    let path = dir.join("sparse");
    let cap = 1024usize;
    let sparse_len: u64 = 2 * 1024 * 1024 * 1024;
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(sparse_len).unwrap();
    drop(file);
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        sparse_len,
        "sparse fixture must report the full logical size",
    );
    let start = std::time::Instant::now();
    let result = load_bytes_capped(&path, cap);
    let elapsed = start.elapsed();
    match result {
        Err(LoadError::TooLarge { actual, limit }) => {
            assert_eq!(limit, cap);
            assert_eq!(actual, cap.saturating_add(1));
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
    assert!(
        elapsed.as_secs() < 10,
        "capped load must return promptly without draining {sparse_len} bytes, took {elapsed:?}",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn within_cap_load_returns_exact_bytes() {
    let dir = scratch_dir("exact");
    let path = dir.join("exact");
    let content = b"exact-bytes-123";
    std::fs::write(&path, content).unwrap();
    // Cap exactly at length succeeds with byte-identical content.
    assert_eq!(load_bytes_capped(&path, content.len()).unwrap(), content,);
    // One byte over trips the saturated over-cap report.
    match load_bytes_capped(&path, content.len() - 1) {
        Err(LoadError::TooLarge { actual, limit }) => {
            assert_eq!(limit, content.len() - 1);
            assert_eq!(actual, content.len());
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_file_is_a_quiet_clean_start() {
    let dir = scratch_dir("missing");
    assert!(matches!(
        load_session_bytes(&dir.join("does-not-exist")),
        Err(LoadError::NotFound)
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn crashed_save_litter_never_reads_and_next_save_recovers() {
    use bitty_storage::session_codec::{decode_session, encode_session};
    let dir = scratch_dir("crash");
    let path = dir.join("session");
    // Last good commit.
    let snap = bitty_storage::session_codec::SessionSnapshot {
        version: bitty_storage::ceiling::SESSION_FORMAT_VERSION,
        workspaces: vec![bitty_storage::session_codec::WorkspaceSnapshot {
            seq: 1,
            name: "good".to_string(),
            layout: bitty_storage::session_codec::LayoutNode::Leaf {
                id: 1,
                cols: 80,
                rows: 24,
            },
            focus: Some(1),
            panes: vec![bitty_storage::session_codec::PaneSnapshot {
                view: 1,
                cwd: None,
                scrollback: vec!["kept".to_string()],
                attach: Some(bitty_storage::session_codec::PaneAttachment::Primary),
                route: bitty_storage::session_codec::PaneRoute::Terminal,
                mode: bitty_storage::session_codec::PresentationMode::Tiled,
            }],
        }],
        active: 0,
        mru: vec![0],
    };
    let good = encode_session(&snap).unwrap();
    save_session_bytes(&path, &good).unwrap();
    // Simulate a crashed save: temp litter plus a torn destination write
    // is NOT simulated (rename is atomic); litter must simply be ignored.
    let litter = dir.join("session.tmp.99999");
    std::fs::write(&litter, b"torn-bytes").unwrap();
    backdate_as_litter(&litter);
    let loaded = load_session_bytes(&path).unwrap();
    assert_eq!(decode_session(&loaded).unwrap(), snap);
    // Next save sweeps the litter and commits cleanly.
    save_session_bytes(&path, &good).unwrap();
    assert!(!dir.join("session.tmp.99999").exists());
    assert_eq!(load_session_bytes(&path).unwrap(), good);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn corrupt_file_fails_closed_so_caller_starts_clean() {
    use bitty_storage::session_codec::decode_session;
    let dir = scratch_dir("corrupt");
    let path = dir.join("session");
    save_session_bytes(&path, b"bitty-session v2\ntruncated-garbage").unwrap();
    let loaded = load_session_bytes(&path).unwrap();
    assert!(decode_session(&loaded).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn committed_file_is_user_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = scratch_dir("mode");
    let path = dir.join("session");
    save_session_bytes(&path, b"secret-capable").unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unique_temp_names_do_not_collide() {
    let dir = scratch_dir("unique");
    let path = dir.join("store.json");
    let a = unique_temp_sibling_for(&path);
    let b = unique_temp_sibling_for(&path);
    assert_ne!(a, b);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// CTX-0006 (storage#13): identical-behavior evidence for the published
// commit surface. Each test pins one clause of the shared contract with
// Core's install-path copy (write temp, fsync temp, rename onto the
// destination, remove the temp on any failure, never touch the destination
// on failure). Core proves the same clauses through its injected
// filesystem; here the same clauses are proved through observable
// real-filesystem behavior.
// ---------------------------------------------------------------------------

#[test]
fn low_level_commit_replaces_atomically_and_leaves_no_temp() {
    let dir = scratch_dir("lowlevel-order");
    let path = dir.join("session");
    std::fs::write(&path, b"previous").unwrap();
    let temp = dir.join("session.tmp.order");
    write_atomic_durably(&path, b"next", &temp).unwrap();
    // Final-state outcome: the destination holds exactly the new bytes,
    // and the explicit temp is gone.
    assert_eq!(std::fs::read(&path).unwrap(), b"next");
    assert!(!temp.exists(), "explicit temp must be gone after commit");
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("session.tmp"))
        .collect();
    assert!(leftovers.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn low_level_commit_cleans_temp_and_preserves_destination_on_rename_failure() {
    let dir = scratch_dir("lowlevel-rename-fail");
    // A directory as the destination forces the rename step to fail after
    // a successful temp write and sync, mirroring an injected rename
    // failure on the Core side.
    let destination = dir.join("destdir");
    std::fs::create_dir(&destination).unwrap();
    let temp = dir.join("session.tmp.rename-fail");
    let result = write_atomic_durably(&destination, b"next", &temp);
    assert!(result.is_err(), "rename onto a directory must fail");
    assert!(!temp.exists(), "temp must be removed after rename failure");
    assert!(
        destination.is_dir(),
        "destination directory must be preserved, never deleted"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn low_level_commit_preserves_destination_on_write_failure() {
    let dir = scratch_dir("lowlevel-write-fail");
    let path = dir.join("session");
    std::fs::write(&path, b"previous").unwrap();
    // A regular file as the temp parent forces the temp open to fail with
    // ENOTDIR before any byte is written, mirroring an injected write
    // failure on the Core side.
    let parent_file = dir.join("parentfile");
    std::fs::write(&parent_file, b"parent").unwrap();
    let temp = parent_file.join("session.tmp.write-fail");
    let result = write_atomic_durably(&path, b"next", &temp);
    assert!(result.is_err(), "temp open under a file must fail");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"previous",
        "failed commit must leave the previous destination intact"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn save_preserves_existing_file_on_cap_rejection() {
    let dir = scratch_dir("save-cap-preserve");
    let path = dir.join("session");
    save_session_bytes(&path, b"previous").unwrap();
    let big = vec![b'x'; bitty_storage::ceiling::MAX_SESSION_FILE_BYTES + 1];
    assert!(save_session_bytes(&path, &big).is_err());
    assert_eq!(
        load_session_bytes(&path).unwrap(),
        b"previous",
        "cap rejection must happen before any filesystem mutation"
    );
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("session.tmp"))
        .collect();
    assert!(leftovers.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn save_failure_leaves_no_file_and_no_temp() {
    let dir = scratch_dir("save-enotdir");
    // A regular file as the destination parent forces directory creation to
    // fail before any temp exists, so neither a destination nor temp litter
    // may appear.
    let parent_file = dir.join("parentfile");
    std::fs::write(&parent_file, b"parent").unwrap();
    let path = parent_file.join("session");
    assert!(save_session_bytes(&path, b"data").is_err());
    assert!(!path.exists(), "failed save must not create a destination");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn low_level_commit_does_not_sweep_while_save_sweeps() {
    // Layering evidence for the F5 parity gap: the low-level commit helper
    // on either side performs no stale-temp sweep; only the high-level save
    // sweeps before writing. Core has no sweep layer for its index path.
    let dir = scratch_dir("sweep-layer");
    let path = dir.join("session");
    let litter = dir.join("session.tmp.777");
    std::fs::write(&litter, b"litter").unwrap();
    backdate_as_litter(&litter);
    let temp = dir.join("session.tmp.explicit");
    write_atomic_durably(&path, b"direct", &temp).unwrap();
    assert!(
        litter.exists(),
        "low-level commit must not sweep crash litter"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"direct");
    save_session_bytes(&path, b"via-save").unwrap();
    assert!(
        !litter.exists(),
        "high-level save must sweep aged litter before writing"
    );
    assert_eq!(load_session_bytes(&path).unwrap(), b"via-save");
    let _ = std::fs::remove_dir_all(&dir);
}
