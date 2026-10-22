//! Store-level durability, journal recovery, containment, and bound tests.
//!
//! These tests deliberately construct the on-disk snapshot and journal bytes
//! themselves (rather than calling private encoders) so the format is proven
//! from an independent implementation, including a crash between journal
//! publication and snapshot replacement.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bitty_storage::component::protocol::{MAX_ROWS, Row};
use bitty_storage::component::store::{NamespaceName, StorageRoot, StoreErrorKind};

const SNAPSHOT_MAGIC: &[u8] = b"bitty-storage-snapshot\n";
const JOURNAL_MAGIC: &[u8] = b"bitty-storage-journal\n";
const FORMAT_VERSION: u32 = 1;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn scratch_root(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bitty-storage-store-{}-{}-{}",
        name,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch root");
    dir
}

fn checksum(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn snapshot_bytes(revision: u64, rows: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SNAPSHOT_MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&revision.to_be_bytes());
    out.extend_from_slice(&(rows.len() as u32).to_be_bytes());
    let mut sorted = rows.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(right.0));
    for (key, value) in sorted {
        out.extend_from_slice(&(key.len() as u32).to_be_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    let checksum = checksum(&out);
    out.extend_from_slice(&checksum.to_be_bytes());
    out
}

fn journal_bytes(revision: u64, rows: &[(&str, &[u8])]) -> Vec<u8> {
    let payload = snapshot_bytes(revision, rows);
    let mut out = Vec::new();
    out.extend_from_slice(JOURNAL_MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&revision.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    let checksum = checksum(&out);
    out.extend_from_slice(&checksum.to_be_bytes());
    out
}

fn name(value: &str) -> NamespaceName {
    NamespaceName::parse(value).expect("valid namespace")
}

fn row(key: &str, value: &[u8]) -> Row {
    Row {
        key: key.to_owned(),
        value: value.to_vec(),
    }
}

#[test]
fn commit_persists_and_rollback_toggles() {
    let root = scratch_root("commit");
    let storage = StorageRoot::new(&root).expect("root");
    let mut namespace = storage.open_namespace(&name("session")).expect("open");
    assert_eq!(namespace.revision(), 0);
    let outcome = namespace
        .commit(0, vec![row("a", b"1"), row("b", b"2")], Vec::new())
        .expect("commit");
    assert_eq!(outcome.revision, 1);
    assert_eq!(outcome.total_rows, 2);
    drop(namespace);

    let mut reopened = storage.open_namespace(&name("session")).expect("reopen");
    assert_eq!(reopened.revision(), 1);
    let page = reopened.read_page(0, 0, 0).expect("read");
    assert_eq!(page.total_rows, 2);
    assert_eq!(page.rows, vec![row("a", b"1"), row("b", b"2")]);

    let outcome = reopened
        .commit(
            1,
            vec![row("a", b"changed"), row("c", b"3")],
            vec!["b".to_owned()],
        )
        .expect("second commit");
    assert_eq!(outcome.revision, 2);
    let rolled = reopened.rollback(2).expect("rollback");
    assert_eq!(rolled.revision, 3);
    assert_eq!(rolled.restored_revision, 1);
    let page = reopened.read_page(0, 0, 0).expect("read");
    assert_eq!(page.rows, vec![row("a", b"1"), row("b", b"2")]);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn published_journal_is_replayed_after_a_crash() {
    let root = scratch_root("journal");
    let storage = StorageRoot::new(&root).expect("root");
    let mut namespace = storage.open_namespace(&name("session")).expect("open");
    namespace
        .commit(0, vec![row("a", b"1")], Vec::new())
        .expect("commit");
    drop(namespace);

    // Simulate a crash after the journal rename but before the snapshot
    // rename: the next open must complete the published target.
    std::fs::write(
        root.join("session").join("journal"),
        journal_bytes(2, &[("a", b"1"), ("b", b"2")]),
    )
    .expect("write journal");

    let reopened = storage.open_namespace(&name("session")).expect("recover");
    assert_eq!(reopened.revision(), 2);
    let page = reopened.read_page(0, 0, 0).expect("read");
    assert_eq!(page.rows, vec![row("a", b"1"), row("b", b"2")]);
    assert!(
        !root.join("session").join("journal").exists(),
        "replayed journal must be removed"
    );

    // Recovery must also complete step 2 (`previous` = revision 1) before
    // publishing the journal target, or this rollback would skip a revision.
    let mut reopened = reopened;
    let rolled = reopened.rollback(2).expect("rollback after replay");
    assert_eq!(rolled.restored_revision, 1);
    let page = reopened.read_page(0, 0, 0).expect("read");
    assert_eq!(page.rows, vec![row("a", b"1")]);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn first_commit_recovery_removes_stale_previous() {
    let root = scratch_root("stale-previous");
    let storage = StorageRoot::new(&root).expect("root");
    let namespace = storage.open_namespace(&name("fresh")).expect("open");
    drop(namespace);

    // A previous image from an earlier namespace lifetime plus a journal for
    // the first commit: recovery must remove the stale image, not make
    // revision 1 rollback-able to unrelated state.
    std::fs::write(
        root.join("fresh").join("previous"),
        snapshot_bytes(7, &[("old", b"stale")]),
    )
    .expect("write previous");
    std::fs::write(
        root.join("fresh").join("journal"),
        journal_bytes(1, &[("a", b"1")]),
    )
    .expect("write journal");

    let mut reopened = storage.open_namespace(&name("fresh")).expect("recover");
    assert_eq!(reopened.revision(), 1);
    assert!(!root.join("fresh").join("previous").exists());
    assert_eq!(
        reopened.rollback(1).expect_err("no previous").kind(),
        StoreErrorKind::NoPrevious
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn corrupt_journal_and_snapshot_fail_closed() {
    let root = scratch_root("corrupt");
    let storage = StorageRoot::new(&root).expect("root");
    let namespace = storage.open_namespace(&name("bad-journal")).expect("open");
    drop(namespace);
    std::fs::write(root.join("bad-journal").join("journal"), b"garbage").expect("write");
    let error = storage
        .open_namespace(&name("bad-journal"))
        .expect_err("corrupt journal");
    assert_eq!(error.kind(), StoreErrorKind::Corrupt);

    let namespace = storage.open_namespace(&name("bad-snapshot")).expect("open");
    drop(namespace);
    std::fs::write(root.join("bad-snapshot").join("snapshot"), b"garbage").expect("write");
    let error = storage
        .open_namespace(&name("bad-snapshot"))
        .expect_err("corrupt snapshot");
    assert_eq!(error.kind(), StoreErrorKind::Corrupt);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn path_shaped_names_and_symlinked_directories_are_refused() {
    for bad in ["../escape", "/absolute", "a/b", "..", ".hidden", "Upper"] {
        assert_eq!(
            NamespaceName::parse(bad).expect_err("invalid").kind(),
            StoreErrorKind::InvalidName,
            "name: {bad}"
        );
    }

    let root = scratch_root("symlink");
    let outside = scratch_root("outside");
    let storage = StorageRoot::new(&root).expect("root");
    std::os::unix::fs::symlink(&outside, root.join("evil")).expect("symlink");
    let error = storage
        .open_namespace(&name("evil"))
        .expect_err("symlink must be refused");
    assert_eq!(error.kind(), StoreErrorKind::InvalidName);
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn a_second_open_is_locked_while_the_first_lives() {
    let root = scratch_root("lock");
    let first_root = StorageRoot::new(&root).expect("root");
    let second_root = StorageRoot::new(&root).expect("root");
    let first = first_root.open_namespace(&name("shared")).expect("first");
    let error = second_root
        .open_namespace(&name("shared"))
        .expect_err("lock contention");
    assert_eq!(error.kind(), StoreErrorKind::Locked);
    drop(first);
    second_root
        .open_namespace(&name("shared"))
        .expect("lock released");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rollback_without_previous_and_stale_revision_are_typed() {
    let root = scratch_root("typed");
    let storage = StorageRoot::new(&root).expect("root");
    let mut namespace = storage.open_namespace(&name("ns")).expect("open");
    assert_eq!(
        namespace.rollback(0).expect_err("no previous").kind(),
        StoreErrorKind::NoPrevious
    );
    namespace
        .commit(0, vec![row("a", b"1")], Vec::new())
        .expect("commit");
    assert_eq!(
        namespace
            .commit(0, vec![row("b", b"2")], Vec::new())
            .expect_err("stale")
            .kind(),
        StoreErrorKind::StaleRevision
    );
    let page = namespace.read_page(0, 0, 0).expect("read");
    assert_eq!(page.rows, vec![row("a", b"1")]);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn snapshot_and_row_bounds_reject_without_mutation() {
    let root = scratch_root("bounds");
    let storage = StorageRoot::new(&root).expect("root");
    let mut namespace = storage.open_namespace(&name("bytes")).expect("open");

    let chunk = vec![b'x'; 128 * 1024];
    let mut revision = 0;
    let mut committed = 0;
    for index in 0..10 {
        match namespace.commit(
            revision,
            vec![row(&format!("k{index:02}"), &chunk)],
            Vec::new(),
        ) {
            Ok(outcome) => {
                revision = outcome.revision;
                committed += 1;
            }
            Err(error) => {
                assert_eq!(error.kind(), StoreErrorKind::Bound);
                break;
            }
        }
    }
    assert!((7..10).contains(&committed), "committed {committed}");
    assert_eq!(namespace.revision(), revision);
    assert_eq!(namespace.row_count(), committed);

    let mut rows = storage.open_namespace(&name("rows")).expect("open");
    let mut revision = 0;
    for batch in 0..32 {
        let upserts: Vec<Row> = (0..128)
            .map(|offset| row(&format!("k{:05}", batch * 128 + offset), b"x"))
            .collect();
        revision = rows
            .commit(revision, upserts, Vec::new())
            .expect("batch")
            .revision;
    }
    assert_eq!(rows.row_count(), MAX_ROWS);
    let error = rows
        .commit(revision, vec![row("overflow", b"x")], Vec::new())
        .expect_err("row bound");
    assert_eq!(error.kind(), StoreErrorKind::Bound);
    assert_eq!(rows.row_count(), MAX_ROWS);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn journal_target_equal_to_the_snapshot_is_discarded() {
    let root = scratch_root("stale-journal");
    let storage = StorageRoot::new(&root).expect("root");
    let mut namespace = storage.open_namespace(&name("ns")).expect("open");
    namespace
        .commit(0, vec![row("a", b"1")], Vec::new())
        .expect("commit");
    drop(namespace);

    // A crash after the snapshot rename leaves a journal at the same
    // revision; recovery must remove it without rewriting state.
    std::fs::write(
        root.join("ns").join("journal"),
        journal_bytes(1, &[("a", b"1")]),
    )
    .expect("write journal");
    let reopened = storage.open_namespace(&name("ns")).expect("open");
    assert_eq!(reopened.revision(), 1);
    assert!(!root.join("ns").join("journal").exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn root_containment_keeps_every_member_inside() {
    let root = scratch_root("containment");
    let storage = StorageRoot::new(&root).expect("root");
    let namespace = storage.open_namespace(&name("session-1")).expect("open");
    drop(namespace);
    let dir = Path::new(&root).join("session-1");
    for member in ["snapshot", "previous", "journal", "lock"] {
        let path = dir.join(member);
        if path.exists() {
            assert!(path.starts_with(&root), "member escaped: {path:?}");
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}
