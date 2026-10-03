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
