//! Independent privacy and security verification for CTX-0004.
//!
//! Written fresh from the accepted contracts, not from the CTX-0003 test
//! suite: W-131 (bitty-docs `storage-and-history-boundary.md`), W-137
//! (bitty-plugins-docs `history-and-storage-policy.md`), and the W-146
//! decisions DEC-W146-1..4. Each test names the contract rule it proves.
//!
//! Contract rules under test:
//! - W-131 verification 1: purge removes bytes; post-purge export/query
//!   returns nothing; no derived index can resurrect deleted content.
//! - W-131 verification 2: sensitive output is not persisted by default;
//!   only the accepted bounded session snapshot on explicit exit-save is
//!   written, never ambiently; safe/headless runs write nothing (the crate
//!   has no ambient write path at all: every write takes an explicit call).
//! - W-131 verification 3: scope escape is denied; a plugin cannot read
//!   another plugin's KV; upward traversal and absolute paths are denied
//!   fail-closed.
//! - W-131 verification 5: budgets and denials are atomic; over-budget or
//!   over-depth values are denied with the previous state intact.
//! - W-131 verification 6: recovery is deterministic; an interrupted commit
//!   never corrupts the store; concurrent commits stay whole.
//! - W-131 "what Core retains": files carry user-only permissions.
//! - W-137: per-plugin KV grants no filesystem authority; keys are data,
//!   never path segments; terminal-derived content has no KV shim.
//! - DEC-W146-3: exit-write default unchanged (this crate performs no
//!   exit write on its own; persistence requires an explicit commit call).
//! - DEC-W146-4: no database engine anywhere (text codec only; enforced
//!   structurally by the absence of any DB dependency in Cargo.toml/lock).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bitty_storage::atomic_io::{LoadError, load_bytes_capped, save_bytes_atomic};
use bitty_storage::ceiling::{
    MAX_SESSION_FILE_BYTES, STORE_FILE_MAX_BYTES, STORE_MAX_KEY_BYTES, STORE_MAX_VALUE_BYTES,
};
use bitty_storage::history::{HistoryActor, validate_record};
use bitty_storage::kv::{JsonValue, KvStore, StoreErrorCode};
use bitty_storage::session_codec::{
    SessionError, decode_session, encode_session, session_file_for,
};
use bitty_storage::transcript::{RetentionPolicy, SegmentDescriptor, select_for_deletion};
use bitty_storage::{CommandRecord, FileBackend, StorageBackend};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bitty-ctx0004-privacy-{name}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn dir_entries(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        out.push(entry.unwrap().path());
    }
    out.sort();
    out
}

fn valid_key(i: usize) -> String {
    format!("k{i:03}")
}

// ---------------------------------------------------------------------------
// W-131 verification 2: nothing is persisted without an explicit call.
// ---------------------------------------------------------------------------

#[test]
fn construction_and_load_miss_create_no_files() {
    // W-131: sensitive terminal-derived content is not written by default.
    // The crate must persist NOTHING unless explicitly asked: building
    // stores, resolving paths, running retention selection, validating
    // records, and missing-file loads are all side-effect free.
    let dir = scratch_dir("no-ambient-writes");
    let before = dir_entries(&dir);

    // Path resolution is pure.
    let session_path =
        session_file_for(Some(dir.to_string_lossy().as_ref()), None).expect("path resolves");
    assert!(!session_path.exists());

    // In-memory KV work touches nothing.
    let mut mem = KvStore::in_memory();
    mem.set("note", JsonValue::String("seed-secret-marker".into()))
        .unwrap();
    assert_eq!(dir_entries(&dir), before);

    // Load-miss on every backend is a quiet clean start, creating nothing.
    let missing_kv = dir.join("absent-store.json");
    let loaded = KvStore::load(missing_kv.clone()).expect("load-miss starts clean");
    assert!(loaded.is_empty());
    assert!(!missing_kv.exists());

    let missing_session = dir.join("absent-session");
    let backend = FileBackend::new(missing_session.clone(), MAX_SESSION_FILE_BYTES);
    assert_eq!(backend.load().unwrap(), None);
    assert!(!missing_session.exists());
    assert!(load_bytes_capped(&missing_session, MAX_SESSION_FILE_BYTES).is_err());

    // Retention selection and record validation are pure policy evaluation.
    let segments = vec![SegmentDescriptor {
        id: 1,
        panel: 1,
        bytes: 10,
        sealed_at_secs: 0,
        sealed: true,
    }];
    let _ = select_for_deletion(&segments, &RetentionPolicy::default(), 0);
    assert!(validate_record(&CommandRecord {
        panel: 1,
        workspace: 0,
        command: "ls".into(),
        cwd: None,
        started_at_secs: 0,
        duration_ms: 1,
        exit_code: Some(0),
        actor: HistoryActor::User,
        external_ref: None,
    }));

    assert_eq!(
        dir_entries(&dir),
        before,
        "no construction/load-miss/validation path may create files"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn session_snapshot_requires_an_explicit_commit_call() {
    // DEC-W146-3 + W-131: the only accepted default write is Core's
    // exit-save; this crate performs no write on its own. Encoding,
    // decoding, and path lookup never touch the filesystem; only
    // `commit`/`save_bytes_atomic` writes.
    let dir = scratch_dir("explicit-commit");
    let path = dir.join("sessions").join("session");

    let snap = empty_snapshot();
    let bytes = encode_session(&snap).unwrap();
    assert!(!path.exists(), "encode must not write");
    assert!(decode_session(&bytes).is_ok());
    assert!(!path.exists(), "decode must not write");

    let mut backend = FileBackend::new(path.clone(), MAX_SESSION_FILE_BYTES);
    backend.commit(&bytes).expect("explicit commit writes");
    assert!(path.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

fn empty_snapshot() -> bitty_storage::SessionSnapshot {
    use bitty_storage::session_codec::{
        LayoutNode, PaneAttachment, PaneRoute, PaneSnapshot, PresentationMode, SessionSnapshot,
        WorkspaceSnapshot,
    };
    SessionSnapshot {
        version: bitty_storage::ceiling::SESSION_FORMAT_VERSION,
        workspaces: vec![WorkspaceSnapshot {
            seq: 1,
            name: "ws".into(),
            layout: LayoutNode::Leaf {
                id: 1,
                cols: 80,
                rows: 24,
            },
            focus: Some(1),
            panes: vec![PaneSnapshot {
                view: 1,
                cwd: None,
                scrollback: Vec::new(),
                attach: Some(PaneAttachment::Session),
                route: PaneRoute::Terminal,
                mode: PresentationMode::Tiled,
            }],
        }],
        active: 0,
        mru: vec![0],
    }
}

// ---------------------------------------------------------------------------
// W-131 verification 1: purge effectiveness.
// ---------------------------------------------------------------------------

#[test]
fn kv_purge_removes_bytes_and_post_purge_query_returns_nothing() {
    // W-131 verification 1: purge removes the original bytes; a post-purge
    // export/query returns nothing; raw bytes are unrecoverable from disk.
    let dir = scratch_dir("purge");
    let path = dir.join("plugin.json");
    let mut store = KvStore::with_path(Some(path.clone()));
    store
        .set(
            "secret",
            JsonValue::String("seed-secret-purge-marker".into()),
        )
        .unwrap();
    store.set("count", JsonValue::Integer(42)).unwrap();
    assert!(path.exists());

    let evidence = store.purge().expect("purge succeeds");
    assert!(evidence.keys_removed >= 2);
    assert!(evidence.bytes_removed > 0);
    assert!(evidence.file_removed);

    // Query surface is empty.
    assert_eq!(store.export_json(), "{}");
    assert_eq!(store.get("secret"), None);
    assert_eq!(store.get("count"), None);
    assert!(store.is_empty());

    // Raw bytes are gone from the filesystem.
    assert!(!path.exists());
    let read = std::fs::read(&path).unwrap_err();
    assert_eq!(read.kind(), std::io::ErrorKind::NotFound);
    let leftovers: Vec<_> = dir_entries(&dir)
        .into_iter()
        .filter(|p| p != &dir)
        .collect();
    assert!(
        leftovers.is_empty(),
        "purge must leave no store bytes behind: {leftovers:?}"
    );

    // Reloading the purged path starts clean (no resurrection).
    let reloaded = KvStore::load(path).expect("purged path loads clean");
    assert!(reloaded.is_empty());
    assert_eq!(reloaded.export_json(), "{}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn session_delete_removes_the_file_and_load_misses_after() {
    // The session object honors the same deletion discipline: delete the
    // file, then load-miss is a clean start.
    let dir = scratch_dir("session-delete");
    let path = dir.join("session");
    let bytes = encode_session(&empty_snapshot()).unwrap();
    let mut backend = FileBackend::new(path.clone(), MAX_SESSION_FILE_BYTES);
    backend.commit(&bytes).unwrap();
    assert!(path.exists());

    let evidence = backend.delete().expect("delete succeeds");
    assert!(evidence.file_removed);
    assert!(!path.exists());
    assert_eq!(backend.load().unwrap(), None);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// W-131 verification 3 + W-137: per-plugin KV isolation, no traversal.
// ---------------------------------------------------------------------------

#[test]
fn two_plugin_dirs_cannot_read_each_other() {
    // W-131 verification 3 / W-137: plugin KV is scoped by plugin
    // identity; no cross-plugin read. Two sibling store directories stay
    // fully isolated across set/get/export/file-load.
    let dir = scratch_dir("isolation");
    let path_a = dir.join("plugin-a").join("store.json");
    let path_b = dir.join("plugin-b").join("store.json");

    let mut store_a = KvStore::with_path(Some(path_a.clone()));
    store_a
        .set("secret", JsonValue::String("plugin-a-seed-secret".into()))
        .unwrap();
    let mut store_b = KvStore::with_path(Some(path_b.clone()));
    store_b.set("other", JsonValue::Integer(1)).unwrap();

    assert_eq!(store_b.get("secret"), None);
    assert!(!store_b.export_json().contains("plugin-a-seed-secret"));

    // Loading B's committed file yields only B's keys.
    let reloaded_b = KvStore::load(path_b).expect("b loads");
    assert_eq!(reloaded_b.get("secret"), None);
    assert_eq!(reloaded_b.get("other"), Some(JsonValue::Integer(1)));

    // A's committed bytes contain nothing of B and vice versa.
    let raw_a = std::fs::read(&path_a).unwrap();
    assert!(!raw_a.windows(5).any(|w| w == b"other"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn traversal_shaped_keys_are_rejected_and_keys_never_become_paths() {
    // W-131 verification 3: upward traversal and absolute paths are denied
    // fail-closed. Key grammar rejects every path-shaped input, and valid
    // dotted keys are data: they never create filesystem structure.
    let dir = scratch_dir("traversal");
    let path = dir.join("store.json");
    let mut store = KvStore::with_path(Some(path.clone()));
    store.set("keep", JsonValue::Integer(7)).unwrap();
    let committed_before = std::fs::read(&path).unwrap();

    for hostile in [
        "../evil",
        "..",
        ".",
        "/etc/passwd",
        "/absolute",
        "a/b",
        "a\\b",
        "has space",
        "Upper",
        "a\0b",
        "",
        "double..dot",
        "-leading-dash",
        ".leading-dot",
    ] {
        let err = store.set(hostile, JsonValue::Integer(0)).unwrap_err();
        assert_eq!(
            err.code(),
            StoreErrorCode::KeyInvalid,
            "key {hostile:?} must be KeyInvalid"
        );
        assert_eq!(err.wire_code(), "E_STORE_KEY_INVALID");
        assert!(store.get(hostile).is_none());
    }
    // Over-long keys are denied too.
    let long = "k".repeat(STORE_MAX_KEY_BYTES + 1);
    assert_eq!(
        store.set(&long, JsonValue::Integer(0)).unwrap_err().code(),
        StoreErrorCode::KeyInvalid
    );

    // Denials leave the previous state (memory and file) intact.
    assert_eq!(store.get("keep"), Some(JsonValue::Integer(7)));
    assert_eq!(std::fs::read(&path).unwrap(), committed_before);

    // Valid dotted keys stay data: no subdirectories or extra files appear.
    store.set("sub.dir", JsonValue::Integer(1)).unwrap();
    store.set("a.b.c", JsonValue::Integer(2)).unwrap();
    assert_eq!(
        dir_entries(&dir),
        vec![path.clone()],
        "keys must never become filesystem entries"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// User-only file permissions (W-131 "what Core retains").
// ---------------------------------------------------------------------------

#[test]
#[cfg(unix)]
fn committed_files_are_user_only() {
    // W-131: session/KV files carry user-only permissions. The atomic
    // commit path creates files mode 0600 and re-asserts 0600 before the
    // first byte, so even a pre-existing wider file is narrowed.
    use std::os::unix::fs::PermissionsExt as _;

    let dir = scratch_dir("perms");
    let session_path = dir.join("deep").join("session");
    save_bytes_atomic(&session_path, b"payload", MAX_SESSION_FILE_BYTES).unwrap();
    let mode = std::fs::metadata(&session_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "session commit must be user-only");

    // A pre-existing group-readable file is narrowed back to 0600.
    std::fs::set_permissions(&session_path, std::fs::Permissions::from_mode(0o640)).unwrap();
    save_bytes_atomic(&session_path, b"payload-2", MAX_SESSION_FILE_BYTES).unwrap();
    let mode = std::fs::metadata(&session_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "re-commit must narrow pre-existing modes");

    // KV commits share the same atomic path: committed store files are 0600.
    let kv_path = dir.join("plugin").join("store.json");
    let mut kv = KvStore::with_path(Some(kv_path.clone()));
    kv.set("k", JsonValue::String("v".into())).unwrap();
    let mode = std::fs::metadata(&kv_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "KV commit must be user-only");

    // Verifier note (no overclaim): parent directories are created with the
    // process umask (0755 under the standard 022 umask observed here), not
    // forced 0700 — the user-only guarantee in the contracts covers files.
    let dir_mode = std::fs::metadata(dir.join("deep"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    // Directory mode is umask-derived and not part of the contract; record only.
    let _ = dir_mode;
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Adversarial inputs: oversize, hostile bytes, hostile JSON.
// ---------------------------------------------------------------------------

#[test]
fn oversize_and_hostile_session_inputs_fail_closed_fast() {
    // W-131 verification 5/6: hostile files are rejected by kind without
    // unbounded I/O or allocation. Each case must complete (no hang/OOM).
    let dir = scratch_dir("hostile-session");

    // Multi-MB garbage is rejected as TooLarge after the first excess byte.
    let big_path = dir.join("big");
    std::fs::write(&big_path, vec![0u8; 4 * 1024 * 1024]).unwrap();
    let started = std::time::Instant::now();
    assert!(
        matches!(
            load_bytes_capped(&big_path, MAX_SESSION_FILE_BYTES),
            Err(LoadError::TooLarge { .. })
        ),
        "capped load must reject an oversize file as TooLarge"
    );
    let err = decode_session(&std::fs::read(&big_path).unwrap()).unwrap_err();
    assert!(
        matches!(err, SessionError::TooLarge { .. }),
        "multi-MB input must be TooLarge, got {err}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "capped load must stay fast"
    );

    // NUL bytes and invalid UTF-8 are Corrupt, never echoed.
    for (name, bytes) in [
        ("nul", b"bitty-session v2\n\x00binary".to_vec()),
        ("invalid-utf8", b"bitty-session v2\n\xff\xfe\n".to_vec()),
        (
            "garbage",
            b"definitely not a session file, seed-secret-x1\n".to_vec(),
        ),
    ] {
        let err = decode_session(&bytes).unwrap_err();
        assert!(
            matches!(err, SessionError::Corrupt(_)),
            "{name} must be Corrupt, got {err}"
        );
        assert!(
            !format!("{err}").contains("seed-secret-x1"),
            "error display must never echo file contents"
        );
    }

    // A hostile over-long single line trips the line cap as TooLarge.
    let mut lined = b"bitty-session v2\nworkspaces 1 active 0 mru 0\n".to_vec();
    lined.extend(vec![b'y'; 9000]);
    lined.push(b'\n');
    assert!(matches!(
        decode_session(&lined).unwrap_err(),
        SessionError::TooLarge { .. }
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oversize_and_hostile_kv_inputs_fail_closed() {
    // W-131 verification 5: over-budget or over-depth values are denied
    // with the previous state intact; hostile store images fail by kind.
    let dir = scratch_dir("hostile-kv");
    let path = dir.join("store.json");
    let mut store = KvStore::with_path(Some(path.clone()));
    store.set("keep", JsonValue::Integer(7)).unwrap();
    let committed_before = std::fs::read(&path).unwrap();

    // Oversize single value denied; in-memory and file state intact. This
    // check runs while the committed file is still pristine, so the
    // byte comparison proves the denial wrote nothing.
    let big = JsonValue::String("v".repeat(STORE_MAX_VALUE_BYTES + 1));
    assert_eq!(
        store.set("big", big).unwrap_err().code(),
        StoreErrorCode::ValueInvalid
    );
    assert_eq!(store.get("keep"), Some(JsonValue::Integer(7)));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        committed_before,
        "denied write must leave the committed file byte-identical"
    );

    // Multi-MB garbage image: quota denial, previous state intact.
    // (The hostile bytes are seeded straight into the file to exercise the
    // load path; the denial under test is the load rejection by kind.)
    std::fs::write(&path, vec![b'z'; STORE_FILE_MAX_BYTES + 1024]).unwrap();
    let err = KvStore::load(path.clone()).unwrap_err();
    assert_eq!(
        err.code(),
        StoreErrorCode::Quota,
        "oversize image must be Quota"
    );
    assert_eq!(
        store.get("keep"),
        Some(JsonValue::Integer(7)),
        "in-memory state survives a failed load of the file"
    );

    // NUL bytes / invalid UTF-8 / non-object roots / deep nesting.
    for (name, bytes) in [
        ("nul", b"{\"\x00\":1}".to_vec()),
        ("invalid-utf8", b"{\"a\":\xff}".to_vec()),
        ("array-root", b"[1,2,3]".to_vec()),
        ("scalar-root", b"42".to_vec()),
        ("trailing", b"{}trailing".to_vec()),
        ("deep", nested_json(24).into_bytes()),
    ] {
        let err = KvStore::load_bytes(None, &bytes).unwrap_err();
        assert_eq!(
            err.code(),
            StoreErrorCode::ValueInvalid,
            "{name} image must be ValueInvalid"
        );
    }

    // Non-finite numbers (1e999 parses to inf) are denied, not persisted.
    let err = KvStore::load_bytes(None, b"{\"inf\":1e999}").unwrap_err();
    assert_eq!(err.code(), StoreErrorCode::ValueInvalid);

    // Quota exhaustion via many small entries: denied, nothing persisted.
    let mut bulk = KvStore::in_memory();
    for i in 0..300usize {
        let _ = bulk.set(&valid_key(i), JsonValue::Integer(i as i64));
    }
    assert!(bulk.len() <= 256, "entry-count ceiling must hold");
    let _ = std::fs::remove_dir_all(&dir);
}

fn nested_json(depth: usize) -> String {
    let mut out = String::from("{\"a\":");
    for _ in 1..depth {
        out.push_str("{\"a\":");
    }
    out.push('1');
    for _ in 1..depth {
        out.push('}');
    }
    out.push('}');
    out
}

// ---------------------------------------------------------------------------
// Atomicity under adversarial interleavings: symlink swap, concurrency.
// ---------------------------------------------------------------------------

#[test]
#[cfg(unix)]
fn symlink_swap_never_observes_a_partial_commit() {
    // W-131 verification 6: rename commits are atomic. Swapping a symlink
    // between write and load (or saving through a symlink) always yields
    // one whole generation, never a mixture.
    let dir = scratch_dir("symlink");
    let target_a = dir.join("a.session");
    let target_b = dir.join("b.session");
    let link = dir.join("live.session");

    let gen_a = encode_session(&empty_snapshot()).unwrap();
    let mut snap_b = empty_snapshot();
    snap_b.workspaces[0].name = "other".into();
    let gen_b = encode_session(&snap_b).unwrap();
    assert_ne!(gen_a, gen_b);
    save_bytes_atomic(&target_a, &gen_a, MAX_SESSION_FILE_BYTES).unwrap();
    save_bytes_atomic(&target_b, &gen_b, MAX_SESSION_FILE_BYTES).unwrap();

    // Saving via a symlink path never follows the link: rename(2) swaps the
    // directory entry atomically, so the link itself becomes a regular file
    // holding exactly the new generation while the old target is untouched.
    // (A following-write would be a symlink-redirection hazard; the commit
    // path is immune to it by construction.)
    std::os::unix::fs::symlink(&target_a, &link).unwrap();
    save_bytes_atomic(&link, &gen_b, MAX_SESSION_FILE_BYTES).unwrap();
    assert_eq!(
        std::fs::read(&target_a).unwrap(),
        gen_a,
        "old target must be untouched: no symlink-following write"
    );
    assert_eq!(std::fs::read(&link).unwrap(), gen_b);
    assert!(
        std::fs::symlink_metadata(&link).unwrap().is_file(),
        "rename replaces the link itself"
    );
    assert!(decode_session(&std::fs::read(&link).unwrap()).is_ok());

    // Repoint the symlink between generations: every load is whole.
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&target_a, &link).unwrap();
    save_bytes_atomic(&target_a, &gen_a, MAX_SESSION_FILE_BYTES).unwrap();
    for _ in 0..20 {
        let seen = std::fs::read(&link).unwrap();
        assert!(
            seen == gen_a || seen == gen_b,
            "load must be one whole generation"
        );
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&target_b, &link).unwrap();
        let seen = std::fs::read(&link).unwrap();
        assert!(
            seen == gen_a || seen == gen_b,
            "load must be one whole generation"
        );
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&target_a, &link).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_thread_savers_keep_every_load_whole() {
    // W-131 verification 6 (intra-process direction): N savers hammering
    // one path via per-writer unique temp siblings never collide; every
    // concurrent load observes one whole payload.
    use std::sync::{Arc, Barrier};

    let dir = scratch_dir("hammer");
    let path = Arc::new(dir.join("session"));
    let payloads: Arc<Vec<Vec<u8>>> = Arc::new(vec![encode_session(&empty_snapshot()).unwrap(), {
        let mut snap = empty_snapshot();
        snap.workspaces[0].name = "hammer-b".into();
        encode_session(&snap).unwrap()
    }]);

    let barrier = Arc::new(Barrier::new(9));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let (path, payloads, barrier) = (
            Arc::clone(&path),
            Arc::clone(&payloads),
            Arc::clone(&barrier),
        );
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            for i in 0..25 {
                let payload = &payloads[i % payloads.len()];
                save_bytes_atomic(&path, payload, MAX_SESSION_FILE_BYTES).expect("saver succeeds");
            }
        }));
    }
    let (rpath, rpayloads, rbarrier) = (
        Arc::clone(&path),
        Arc::clone(&payloads),
        Arc::clone(&barrier),
    );
    handles.push(std::thread::spawn(move || {
        rbarrier.wait();
        for _ in 0..200 {
            if let Ok(bytes) = std::fs::read(rpath.as_path()) {
                assert!(
                    rpayloads.iter().any(|p| p == &bytes),
                    "concurrent load must be one whole payload, got {} bytes",
                    bytes.len()
                );
            }
        }
    }));
    for handle in handles {
        handle.join().expect("thread succeeds");
    }

    // Final state decodes.
    let final_bytes = std::fs::read(path.as_path()).unwrap();
    assert!(payloads.iter().any(|p| p == &final_bytes));
    assert!(decode_session(&final_bytes).is_ok());

    // No temp litter survives the storm.
    let litter: Vec<_> = dir_entries(&dir)
        .into_iter()
        .filter(|p| p.file_name().unwrap().to_string_lossy().contains(".tmp"))
        .collect();
    assert!(litter.is_empty(), "no temp litter may survive: {litter:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn two_processes_saving_one_path_both_succeed_and_final_decodes() {
    // W-131 verification 6 (cross-process direction): two OS processes
    // saving the same path concurrently both succeed (unique temp names
    // carry the pid), and the final file is one whole generation that
    // decodes. The saver logic lives in src/bin/save_worker.rs; this test
    // only orchestrates and asserts.
    let worker = env!("CARGO_BIN_EXE_save_worker");
    let dir = scratch_dir("two-proc");

    let payload_a = encode_session(&empty_snapshot()).unwrap();
    let mut snap_b = empty_snapshot();
    snap_b.workspaces[0].name = "proc-b".into();
    let payload_b = encode_session(&snap_b).unwrap();
    let file_a = dir.join("a.payload");
    let file_b = dir.join("b.payload");
    std::fs::write(&file_a, &payload_a).unwrap();
    std::fs::write(&file_b, &payload_b).unwrap();
    let target = dir.join("session");

    // Simultaneous spawn: both processes race on the same path.
    let first = std::process::Command::new(worker)
        .arg(&target)
        .arg(&file_a)
        .spawn()
        .expect("spawn saver A");
    let second = std::process::Command::new(worker)
        .arg(&target)
        .arg(&file_b)
        .spawn()
        .expect("spawn saver B");
    let out_a = first.wait_with_output().expect("wait A");
    let out_b = second.wait_with_output().expect("wait B");
    assert!(out_a.status.success(), "saver A must succeed");
    assert!(out_b.status.success(), "saver B must succeed");

    let final_bytes = std::fs::read(&target).unwrap();
    assert!(
        final_bytes == payload_a || final_bytes == payload_b,
        "final file must be one whole generation"
    );
    assert!(
        decode_session(&final_bytes).is_ok(),
        "final file must decode"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
