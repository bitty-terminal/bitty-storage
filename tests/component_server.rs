//! Live component-server integration tests.
//!
//! The real `bitty-storage` binary is spawned as a stdio coprocess and driven
//! with the public protocol codec. Every test uses a fresh temporary storage
//! root, so no host state is read or written.
//!
//! Covered acceptance paths: handshake, commit durability across a clean
//! restart and a SIGKILL, rollback, bounded paging, stale revisions,
//! namespace limits, oversize frames, malformed frames, path-shaped wire
//! names, and cross-process lock contention.

#![cfg(unix)]

use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use bitty_storage::component::protocol::{
    ErrorKind, FrameReader, MAX_FRAME_BYTES, MAX_NAMESPACES, MAX_READ_ROWS, Message,
    PROTOCOL_VERSION, Row, write_frame,
};
use bitty_storage::component::server::{COMPONENT_VERSION, SERVER_EXIT_OK, SERVER_EXIT_PROTOCOL};

/// Upper bound for one protocol message.
const WAIT: Duration = Duration::from_secs(20);

static SEQ: AtomicU64 = AtomicU64::new(0);

fn scratch_root(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bitty-storage-component-{}-{}-{}",
        name,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch root");
    dir
}

fn row(key: &str, value: &[u8]) -> Row {
    Row {
        key: key.to_owned(),
        value: value.to_vec(),
    }
}

/// One spawned component process plus its decoded message stream.
struct Component {
    child: Child,
    stdin: std::process::ChildStdin,
    messages: Receiver<Result<Message, String>>,
    exited: bool,
}

impl Component {
    fn start(root: &Path) -> Self {
        let binary: PathBuf = std::env::var_os("BITTY_STORAGE_COMPONENT_BIN")
            .map_or_else(|| env!("CARGO_BIN_EXE_bitty-storage").into(), Into::into);
        let mut child = Command::new(binary)
            .arg("--root")
            .arg(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bitty-storage");
        let stdin = child.stdin.take().expect("component stdin");
        let stdout = child.stdout.take().expect("component stdout");
        let (sender, messages) = mpsc::channel();
        std::thread::Builder::new()
            .name("component-reader".to_owned())
            .spawn(move || {
                let mut reader = FrameReader::new(BufReader::new(stdout));
                loop {
                    match reader.read_message() {
                        Ok(Some(message)) => {
                            if sender.send(Ok(message)).is_err() {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            let _ = sender.send(Err(error.to_string()));
                            break;
                        }
                    }
                }
            })
            .expect("reader thread");
        let mut component = Self {
            child,
            stdin,
            messages,
            exited: false,
        };
        component.handshake();
        component
    }

    fn handshake(&mut self) {
        self.send(&Message::Hello {
            min: PROTOCOL_VERSION,
            max: PROTOCOL_VERSION,
            component: "storage".to_owned(),
            version: "test".to_owned(),
        });
        match self.recv() {
            Message::HelloAck {
                protocol,
                component,
                version,
            } => {
                assert_eq!(protocol, PROTOCOL_VERSION);
                assert_eq!(component, "storage");
                assert_eq!(version, COMPONENT_VERSION);
            }
            other => panic!("expected HelloAck, got {other:?}"),
        }
    }

    fn send(&mut self, message: &Message) {
        write_frame(&mut self.stdin, message).expect("write frame");
        self.stdin.flush().expect("flush frame");
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        self.stdin.write_all(bytes).expect("write raw");
        self.stdin.flush().expect("flush raw");
    }

    fn recv(&self) -> Message {
        match self.messages.recv_timeout(WAIT) {
            Ok(Ok(message)) => message,
            Ok(Err(error)) => panic!("component protocol error: {error}"),
            Err(RecvTimeoutError::Timeout) => panic!("timed out waiting for a component frame"),
            Err(RecvTimeoutError::Disconnected) => panic!("component closed its stdout"),
        }
    }

    fn open(&mut self, request: u64, namespace: &str) -> Message {
        self.send(&Message::OpenNamespace {
            request,
            namespace: namespace.to_owned(),
        });
        self.recv()
    }

    fn commit(
        &mut self,
        request: u64,
        namespace: &str,
        expected_revision: u64,
        upserts: Vec<Row>,
        deletes: Vec<String>,
    ) -> Message {
        self.send(&Message::CommitBatch {
            request,
            namespace: namespace.to_owned(),
            expected_revision,
            upserts,
            deletes,
        });
        self.recv()
    }

    fn read_page(
        &mut self,
        request: u64,
        namespace: &str,
        start_row: u32,
        max_rows: u32,
        max_bytes: u32,
    ) -> Message {
        self.send(&Message::ReadSnapshot {
            request,
            namespace: namespace.to_owned(),
            start_row,
            max_rows,
            max_bytes,
        });
        self.recv()
    }

    fn read_all(&mut self, namespace: &str) -> (u64, Vec<Row>) {
        let mut rows = Vec::new();
        let mut start = 0u32;
        let mut revision: u64;
        let mut request = 1000u64;
        loop {
            let page = self.read_page(request, namespace, start, MAX_READ_ROWS as u32, 0);
            request += 1;
            match page {
                Message::SnapshotChunk {
                    revision: seen,
                    rows: page_rows,
                    total_rows,
                    done,
                    ..
                } => {
                    revision = seen;
                    assert!(
                        !page_rows.is_empty() || done,
                        "empty page before the snapshot end"
                    );
                    start += u32::try_from(page_rows.len()).expect("page length");
                    rows.extend(page_rows);
                    if done {
                        assert_eq!(rows.len(), total_rows as usize);
                        break;
                    }
                }
                other => panic!("expected SnapshotChunk, got {other:?}"),
            }
        }
        (revision, rows)
    }

    fn shutdown(mut self) {
        self.send(&Message::Shutdown);
        match self.recv() {
            Message::ShutdownAck => {}
            other => panic!("expected ShutdownAck, got {other:?}"),
        }
        let status = self.child.wait().expect("wait for component");
        self.exited = true;
        assert_eq!(status.code(), Some(i32::from(SERVER_EXIT_OK)));
    }

    fn kill_and_wait(&mut self) -> std::process::ExitStatus {
        self.child.kill().expect("kill component");
        let status = self.child.wait().expect("wait for killed component");
        self.exited = true;
        status
    }
}

impl Drop for Component {
    fn drop(&mut self) {
        if self.exited {
            return;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn expect_opened(message: Message, namespace: &str) -> (u64, u32, u64) {
    match message {
        Message::NamespaceOpened {
            namespace: seen,
            revision,
            rows,
            bytes,
            ..
        } => {
            assert_eq!(seen, namespace);
            (revision, rows, bytes)
        }
        other => panic!("expected NamespaceOpened, got {other:?}"),
    }
}

fn expect_error(message: Message, kind: ErrorKind) -> String {
    match message {
        Message::Error {
            kind: seen,
            message,
            ..
        } => {
            assert_eq!(seen, kind);
            message
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

fn expect_committed(message: Message) -> u64 {
    match message {
        Message::Committed { revision, .. } => revision,
        other => panic!("expected Committed, got {other:?}"),
    }
}

#[test]
fn handshake_then_shutdown_is_clean() {
    let root = scratch_root("handshake");
    let component = Component::start(&root);
    component.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn commit_survives_a_clean_restart() {
    let root = scratch_root("restart");
    let mut first = Component::start(&root);
    let (revision, rows, bytes) = expect_opened(first.open(1, "session-1"), "session-1");
    assert_eq!((revision, rows, bytes), (0, 0, 0));

    let revision = expect_committed(first.commit(
        2,
        "session-1",
        0,
        vec![row("alpha", b"one"), row("beta", b"two")],
        Vec::new(),
    ));
    assert_eq!(revision, 1);
    let (revision, rows) = first.read_all("session-1");
    assert_eq!(revision, 1);
    assert_eq!(rows, vec![row("alpha", b"one"), row("beta", b"two")]);
    first.shutdown();

    let mut second = Component::start(&root);
    let (revision, count, _) = expect_opened(second.open(1, "session-1"), "session-1");
    assert_eq!((revision, count), (1, 2));
    let (revision, rows) = second.read_all("session-1");
    assert_eq!(revision, 1);
    assert_eq!(rows, vec![row("alpha", b"one"), row("beta", b"two")]);
    second.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn commit_is_atomic_and_rejects_a_stale_revision() {
    let root = scratch_root("stale");
    let mut component = Component::start(&root);
    assert_eq!(expect_opened(component.open(1, "ns"), "ns").0, 0);
    assert_eq!(
        expect_committed(component.commit(2, "ns", 0, vec![row("a", b"1")], Vec::new())),
        1
    );
    let text = expect_error(
        component.commit(3, "ns", 0, vec![row("a", b"2"), row("b", b"3")], Vec::new()),
        ErrorKind::StaleRevision,
    );
    assert_eq!(text, "revision conflict");
    let (revision, rows) = component.read_all("ns");
    assert_eq!(revision, 1);
    assert_eq!(rows, vec![row("a", b"1")]);
    component.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rollback_restores_the_previous_revision_as_a_new_revision() {
    let root = scratch_root("rollback");
    let mut component = Component::start(&root);
    assert_eq!(expect_opened(component.open(1, "history"), "history").0, 0);
    assert_eq!(
        expect_committed(component.commit(
            2,
            "history",
            0,
            vec![row("a", b"1"), row("b", b"2")],
            Vec::new(),
        )),
        1
    );
    assert_eq!(
        expect_committed(component.commit(
            3,
            "history",
            1,
            vec![row("a", b"changed"), row("c", b"3")],
            vec!["b".to_owned()],
        )),
        2
    );

    component.send(&Message::Rollback {
        request: 4,
        namespace: "history".to_owned(),
        expected_revision: 2,
    });
    match component.recv() {
        Message::RolledBack {
            revision,
            restored_revision,
            total_rows,
            ..
        } => {
            assert_eq!(revision, 3);
            assert_eq!(restored_revision, 1);
            assert_eq!(total_rows, 2);
        }
        other => panic!("expected RolledBack, got {other:?}"),
    }
    let (revision, rows) = component.read_all("history");
    assert_eq!(revision, 3);
    assert_eq!(rows, vec![row("a", b"1"), row("b", b"2")]);

    // A second rollback toggles back to the state before the first one.
    component.send(&Message::Rollback {
        request: 5,
        namespace: "history".to_owned(),
        expected_revision: 3,
    });
    match component.recv() {
        Message::RolledBack {
            revision,
            restored_revision,
            ..
        } => {
            assert_eq!(revision, 4);
            assert_eq!(restored_revision, 2);
        }
        other => panic!("expected RolledBack, got {other:?}"),
    }
    let (_, rows) = component.read_all("history");
    assert_eq!(rows, vec![row("a", b"changed"), row("c", b"3")]);
    component.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rollback_without_a_previous_revision_is_typed() {
    let root = scratch_root("no-previous");
    let mut component = Component::start(&root);
    assert_eq!(expect_opened(component.open(1, "fresh"), "fresh").0, 0);
    component.send(&Message::Rollback {
        request: 2,
        namespace: "fresh".to_owned(),
        expected_revision: 0,
    });
    let text = expect_error(component.recv(), ErrorKind::InvalidRequest);
    assert_eq!(text, "no previous revision");
    component.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn crash_after_commit_preserves_acknowledged_state() {
    let root = scratch_root("crash");
    let mut component = Component::start(&root);
    assert_eq!(expect_opened(component.open(1, "session"), "session").0, 0);
    assert_eq!(
        expect_committed(component.commit(
            2,
            "session",
            0,
            vec![row("alpha", b"durable"), row("beta", b"also")],
            Vec::new(),
        )),
        1
    );
    let status = component.kill_and_wait();
    assert!(!status.success(), "SIGKILL must not report success");

    let mut restarted = Component::start(&root);
    let (revision, rows, _) = expect_opened(restarted.open(1, "session"), "session");
    assert_eq!((revision, rows), (1, 2));
    let (revision, rows) = restarted.read_all("session");
    assert_eq!(revision, 1);
    assert_eq!(rows, vec![row("alpha", b"durable"), row("beta", b"also")]);
    restarted.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn reads_are_paged_and_ordered() {
    let root = scratch_root("paging");
    let mut component = Component::start(&root);
    expect_opened(component.open(1, "rows"), "rows");
    let first: Vec<Row> = (0..100)
        .map(|index| row(&format!("k{index:04}"), format!("v{index}").as_bytes()))
        .collect();
    let second: Vec<Row> = (100..200)
        .map(|index| row(&format!("k{index:04}"), format!("v{index}").as_bytes()))
        .collect();
    assert_eq!(
        expect_committed(component.commit(2, "rows", 0, first.clone(), Vec::new())),
        1
    );
    assert_eq!(
        expect_committed(component.commit(3, "rows", 1, second.clone(), Vec::new())),
        2
    );

    let mut seen = Vec::new();
    let mut start = 0u32;
    let mut pages = 0;
    loop {
        match component.read_page(10 + pages, "rows", start, 32, 0) {
            Message::SnapshotChunk {
                rows: page,
                total_rows,
                done,
                ..
            } => {
                assert_eq!(total_rows, 200);
                assert!(page.len() <= 32);
                pages += 1;
                start += u32::try_from(page.len()).expect("page length");
                seen.extend(page);
                if done {
                    break;
                }
            }
            other => panic!("expected SnapshotChunk, got {other:?}"),
        }
    }
    assert_eq!(pages, 7);
    assert_eq!(seen.len(), 200);
    let mut expected = first;
    expected.extend(second);
    expected.sort_by(|left, right| left.key.cmp(&right.key));
    assert_eq!(seen, expected);
    component.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn namespace_row_and_byte_bounds_fail_closed() {
    let root = scratch_root("bounds");
    let mut component = Component::start(&root);
    expect_opened(component.open(1, "bounded"), "bounded");

    // 32 full batches fill MAX_ROWS (4096); the next row is rejected and the
    // committed revision does not advance.
    let mut revision = 0;
    for batch in 0..32 {
        let rows: Vec<Row> = (0..128)
            .map(|offset| row(&format!("k{:05}", batch * 128 + offset), b"x"))
            .collect();
        revision =
            expect_committed(component.commit(100 + batch, "bounded", revision, rows, Vec::new()));
    }
    assert_eq!(revision, 32);
    let text = expect_error(
        component.commit(
            200,
            "bounded",
            revision,
            vec![row("overflow", b"x")],
            Vec::new(),
        ),
        ErrorKind::Budget,
    );
    assert_eq!(text, "storage bound exceeded");
    let (seen, rows) = component.read_all("bounded");
    assert_eq!(seen, 32);
    assert_eq!(rows.len(), 4096);

    // Namespace capacity is bounded independently.
    for index in 0..MAX_NAMESPACES - 1 {
        let name = format!("ns-{index:02}");
        expect_opened(component.open(1000 + index as u64, &name), &name);
    }
    let text = expect_error(component.open(2000, "one-too-many"), ErrorKind::Budget);
    assert_eq!(text, "namespace limit reached");
    component.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn lock_contention_between_components_is_typed_and_recovers() {
    let root = scratch_root("lock");
    let mut first = Component::start(&root);
    expect_opened(first.open(1, "shared"), "shared");

    let mut second = Component::start(&root);
    let text = expect_error(second.open(1, "shared"), ErrorKind::Locked);
    assert_eq!(text, "namespace is locked");
    second.shutdown();

    // The kernel releases the lock when the first component goes away.
    first.shutdown();
    let mut third = Component::start(&root);
    expect_opened(third.open(1, "shared"), "shared");
    third.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unknown_namespace_is_typed() {
    let root = scratch_root("unknown");
    let mut component = Component::start(&root);
    let text = expect_error(
        component.read_page(1, "never-opened", 0, 0, 0),
        ErrorKind::UnknownNamespace,
    );
    assert_eq!(text, "unknown namespace");
    component.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn oversized_frame_is_rejected_and_the_component_exits_protocol() {
    let root = scratch_root("oversize-frame");
    let mut component = Component::start(&root);
    let oversized = u32::try_from(MAX_FRAME_BYTES + 1).expect("fits u32");
    component.send_raw(&oversized.to_be_bytes());
    let text = expect_error(component.recv(), ErrorKind::Protocol);
    assert_eq!(text, "frame too large");
    let status = component.child.wait().expect("wait for component");
    assert_eq!(status.code(), Some(i32::from(SERVER_EXIT_PROTOCOL)));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn malformed_frames_exit_protocol_without_panicking() {
    let root = scratch_root("malformed");
    let mut component = Component::start(&root);
    component.send_raw(&[0u8, 0, 0, 0]);
    let text = expect_error(component.recv(), ErrorKind::Protocol);
    assert_eq!(text, "invalid protocol frame");
    let status = component.child.wait().expect("wait for component");
    assert_eq!(status.code(), Some(i32::from(SERVER_EXIT_PROTOCOL)));
    let _ = std::fs::remove_dir_all(&root);

    let root = scratch_root("unknown-tag");
    let mut component = Component::start(&root);
    let mut frame = Vec::new();
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.push(0x7f);
    component.send_raw(&frame);
    let text = expect_error(component.recv(), ErrorKind::Protocol);
    assert_eq!(text, "invalid protocol frame");
    let status = component.child.wait().expect("wait for component");
    assert_eq!(status.code(), Some(i32::from(SERVER_EXIT_PROTOCOL)));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn path_shaped_namespace_on_the_wire_is_rejected() {
    let root = scratch_root("wire-path");
    let mut component = Component::start(&root);
    // `../escape` cannot be encoded through the typed codec, so build the
    // exact wire bytes an untrusted peer could send.
    let namespace = b"../escape";
    let mut payload = Vec::new();
    payload.push(0x10u8);
    payload.extend_from_slice(&7u64.to_be_bytes());
    payload.extend_from_slice(&(namespace.len() as u32).to_be_bytes());
    payload.extend_from_slice(namespace);
    let mut frame = Vec::new();
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    component.send_raw(&frame);
    let text = expect_error(component.recv(), ErrorKind::Protocol);
    assert_eq!(text, "invalid protocol frame");
    let status = component.child.wait().expect("wait for component");
    assert_eq!(status.code(), Some(i32::from(SERVER_EXIT_PROTOCOL)));
    assert!(!root.join("..").join("escape").exists());
    let _ = std::fs::remove_dir_all(&root);
}
