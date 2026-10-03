//! Core W-146 parity for CTX-0004 (Issue #1).
//!
//! Provenance: every file under `tests/fixtures/core-parity/` is a
//! byte-for-byte copy of the golden fixtures committed to Core at
//! `bitty@3df633c6` (merged PR #1646, W-146 Core side) under
//! `crates/bitty-terminal/tests/fixtures/session-parity/` and
//! `store-parity/`. Core's own tree documents them as "the pre-rewire Core
//! codec outputs for exactly these inputs", and Core's tests at that
//! revision assert Core-written bytes equal these fixtures
//! (`kv_commit_produces_golden_bytes`; session golden round-trips).
//! Expected semantics below are transcribed from Core's golden inputs at
//! that revision (`storage_backends.rs` golden snapshots), not from the
//! CTX-0003 implementation.
//!
//! Precise parity statement (no overclaim):
//! - PROVEN with real Core artifacts: the storage crate decodes all six
//!   Core session fixtures and the Core KV fixture; decode-then-encode is
//!   byte-identical to the fixture for every file; storage-constructed
//!   snapshots/KV built from Core's documented golden inputs encode to
//!   byte-identical images. Because Core's own tests prove Core-written ==
//!   fixture, transitively storage-written == Core-written for the covered
//!   shapes (single/multi workspace, splits, stacks, detached panes,
//!   escapes, full scrollback, nested KV, arrays, non-ASCII, big floats).
//! - PROVEN by constant: every ceiling enforced here equals Core's value at
//!   3df633c6 (cited per constant).
//! - PROVEN by kind: corrupt/oversize/version-skew inputs fail with the same
//!   error KIND taxonomy Core uses (TooLarge vs Corrupt vs
//!   UnsupportedVersion; Quota vs ValueInvalid on the KV side).
//! - NOT proven: no Core code runs in this repository (by design —
//!   DEC-W146-2 forbids the reverse dependency, so the oracle for Core's
//!   bytes is the vendored fixtures plus Core's documented assertions).
//!   Core-owned runtime behavior (capture, restore re-derivation,
//!   generation fencing, safe/headless gating, validation-before-mutation)
//!   is out of scope. Transcript/history have no Core counterpart
//!   (greenfield behind opt-in) so no parity is asserted for them.

use std::path::PathBuf;

use bitty_storage::ceiling::*;
use bitty_storage::kv::{JsonValue, KvStore, StoreErrorCode};
use bitty_storage::session_codec::{
    LayoutNode, PaneAttachment, PaneRoute, PaneSnapshot, PresentationMode, SessionError,
    SessionSnapshot, WorkspaceSnapshot, decode_session, encode_session,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("core-parity")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|_| panic!("vendored Core fixture missing: {name}"))
}

fn leaf(id: u64) -> LayoutNode {
    LayoutNode::Leaf {
        id,
        cols: 80,
        rows: 24,
    }
}

fn pane(
    view: u64,
    cwd: Option<&str>,
    scrollback: &[&str],
    attach: PaneAttachment,
    mode: PresentationMode,
) -> PaneSnapshot {
    PaneSnapshot {
        view,
        cwd: cwd.map(str::to_owned),
        scrollback: scrollback.iter().map(|s| (*s).to_owned()).collect(),
        attach: Some(attach),
        route: PaneRoute::Terminal,
        mode,
    }
}

// ---------------------------------------------------------------------------
// Direction 1: every Core fixture decodes to the semantics Core wrote.
// ---------------------------------------------------------------------------

#[test]
fn core_basic_fixture_decodes_to_core_golden_semantics() {
    let snap = decode_session(&fixture("basic.session")).expect("Core basic fixture decodes");
    assert_eq!(snap.version, 2);
    assert_eq!(snap.active, 0);
    assert_eq!(snap.mru, vec![0]);
    assert_eq!(snap.workspaces.len(), 1);
    let ws = &snap.workspaces[0];
    assert_eq!(ws.seq, 7);
    assert_eq!(ws.name, "ws7");
    assert_eq!(ws.layout, leaf(7));
    assert_eq!(ws.focus, Some(7));
    // Core's golden input left attach unspecified (None) and recorded the
    // cwd verbatim as the file:// URL string; the file carries the resolved
    // `primary` token and the verbatim cwd.
    assert_eq!(
        ws.panes,
        vec![pane(
            7,
            Some("file:///tmp"),
            &["hello world"],
            PaneAttachment::Primary,
            PresentationMode::Tiled
        )]
    );
}

#[test]
fn core_empty_fixture_decodes_to_core_golden_semantics() {
    let snap = decode_session(&fixture("empty.session")).expect("Core empty fixture decodes");
    assert_eq!(snap.version, 2);
    assert_eq!((snap.active, snap.mru.as_slice()), (0, [0].as_slice()));
    let ws = &snap.workspaces[0];
    assert_eq!((ws.seq, ws.name.as_str()), (5, "empty"));
    assert_eq!(ws.layout, leaf(5));
    assert_eq!(ws.focus, Some(5));
    assert_eq!(
        ws.panes,
        vec![pane(
            5,
            None,
            &[],
            PaneAttachment::Session,
            PresentationMode::Tiled
        )]
    );
}

#[test]
fn core_detached_fixture_decodes_to_core_golden_semantics() {
    let snap = decode_session(&fixture("detached.session")).expect("Core detached fixture decodes");
    let ws = &snap.workspaces[0];
    assert_eq!((ws.seq, ws.name.as_str()), (3, "ws3"));
    assert_eq!(ws.focus, Some(11));
    match &ws.layout {
        LayoutNode::Split {
            horizontal,
            ratio,
            first,
            second,
        } => {
            assert!(!horizontal, "Core golden split is vertical");
            assert_eq!(
                *ratio, 0.25,
                "Core golden ratio decodes from bits 1048576000"
            );
            assert_eq!(first.as_ref(), &leaf(11));
            assert_eq!(second.as_ref(), &leaf(12));
        }
        other => panic!("expected Core vertical split, got {other:?}"),
    }
    assert_eq!(
        ws.panes,
        vec![
            pane(
                11,
                Some("file:///tmp"),
                &["live"],
                PaneAttachment::Session,
                PresentationMode::Tiled
            ),
            pane(
                12,
                None,
                &[],
                PaneAttachment::Detached,
                PresentationMode::Scratchpad
            ),
        ]
    );
}

#[test]
fn core_escapes_fixture_decodes_to_core_golden_semantics() {
    let snap = decode_session(&fixture("escapes.session")).expect("Core escapes fixture decodes");
    let ws = &snap.workspaces[0];
    assert_eq!(ws.name, "work zone é中");
    assert_eq!(ws.focus, Some(2));
    match &ws.layout {
        LayoutNode::Split {
            horizontal,
            ratio,
            first,
            second,
        } => {
            assert!(horizontal, "Core golden split is horizontal");
            assert_eq!(
                *ratio, 0.5,
                "Core golden ratio decodes from bits 1056964608"
            );
            assert_eq!(first.as_ref(), &leaf(1));
            assert_eq!(second.as_ref(), &leaf(2));
        }
        other => panic!("expected Core horizontal split, got {other:?}"),
    }
    assert_eq!(
        ws.panes,
        vec![
            pane(
                1,
                Some("file:///tmp/dir with spaces"),
                &["back\\slash", "line\nbreak", "cr\rhere", "  padded  ", ""],
                PaneAttachment::Primary,
                PresentationMode::Floating
            ),
            pane(
                2,
                None,
                &["plain"],
                PaneAttachment::Session,
                PresentationMode::Tiled
            ),
        ]
    );
}

#[test]
fn core_multi_fixture_decodes_to_core_golden_semantics() {
    let snap = decode_session(&fixture("multi.session")).expect("Core multi fixture decodes");
    assert_eq!(snap.active, 1);
    assert_eq!(snap.mru, vec![1, 0]);
    assert_eq!(snap.workspaces.len(), 2);
    let (first, second) = (&snap.workspaces[0], &snap.workspaces[1]);
    assert_eq!((first.seq, first.name.as_str()), (1, "first"));
    assert_eq!(first.layout, leaf(1));
    assert_eq!(
        first.panes,
        vec![pane(
            1,
            None,
            &[],
            PaneAttachment::Session,
            PresentationMode::Tiled
        )]
    );
    assert_eq!((second.seq, second.name.as_str()), (2, "second"));
    assert_eq!(second.focus, Some(3));
    match &second.layout {
        LayoutNode::Stack(children) => {
            assert_eq!(children.as_slice(), &[leaf(2), leaf(3)]);
        }
        other => panic!("expected Core stack layout, got {other:?}"),
    }
    assert_eq!(
        second.panes,
        vec![
            pane(
                2,
                Some("file:///var/tmp"),
                &["a", "b"],
                PaneAttachment::Session,
                PresentationMode::Tiled
            ),
            pane(
                3,
                None,
                &["c"],
                PaneAttachment::Primary,
                PresentationMode::Fullscreen
            ),
        ]
    );
}

#[test]
fn core_fullpane_fixture_decodes_to_core_golden_semantics() {
    let snap = decode_session(&fixture("fullpane.session")).expect("Core fullpane fixture decodes");
    let ws = &snap.workspaces[0];
    assert_eq!((ws.seq, ws.name.as_str()), (9, "full"));
    assert_eq!(ws.panes.len(), 1);
    let saved = &ws.panes[0];
    assert_eq!(saved.cwd.as_deref(), Some("file:///tmp"));
    assert_eq!(saved.scrollback.len(), 200, "Core golden keeps 200 lines");
    for (i, line) in saved.scrollback.iter().enumerate() {
        assert_eq!(line, &format!("scrollback line {i:03} with tail"));
    }
    assert_eq!(saved.attach, Some(PaneAttachment::Primary));
}

// ---------------------------------------------------------------------------
// Direction 2: byte-shape compatibility (decode -> encode is the identity).
// ---------------------------------------------------------------------------

#[test]
fn every_core_session_fixture_reencodes_byte_identical() {
    // Byte-shape compatibility: the storage encoder maps each decoded Core
    // fixture back to the exact bytes Core wrote. Combined with Core's own
    // assertions that Core-written == fixture, storage-written ==
    // Core-written for these shapes.
    for name in [
        "basic.session",
        "detached.session",
        "empty.session",
        "escapes.session",
        "fullpane.session",
        "multi.session",
    ] {
        let raw = fixture(name);
        let snap = decode_session(&raw).expect("Core fixture decodes");
        let reencoded = encode_session(&snap).expect("decoded Core fixture re-encodes");
        assert_eq!(
            reencoded, raw,
            "re-encode of Core fixture {name} must be byte-identical"
        );
        // And the re-encoded bytes decode to the same snapshot (fixpoint).
        assert_eq!(decode_session(&reencoded).expect("fixpoint decodes"), snap);
    }
}

#[test]
fn storage_constructed_snapshot_encodes_to_core_basic_bytes() {
    // Encoder direction from Core's documented golden inputs: Core's
    // golden_snapshot("basic") uses attach None with cwd "file:///tmp";
    // the storage encoder must produce the exact Core fixture bytes.
    let snap = SessionSnapshot {
        version: SESSION_FORMAT_VERSION,
        workspaces: vec![WorkspaceSnapshot {
            seq: 7,
            name: "ws7".into(),
            layout: leaf(7),
            focus: Some(7),
            panes: vec![PaneSnapshot {
                view: 7,
                cwd: Some("file:///tmp".into()),
                scrollback: vec!["hello world".into()],
                attach: None,
                route: PaneRoute::Terminal,
                mode: PresentationMode::Tiled,
            }],
        }],
        active: 0,
        mru: vec![0],
    };
    assert_eq!(
        encode_session(&snap).expect("encodes"),
        fixture("basic.session")
    );
}

#[test]
fn storage_constructed_kv_encodes_to_core_golden_bytes() {
    // Encoder direction from Core's kv_commit_produces_golden_bytes inputs:
    // the same seven sets through this crate must commit the exact bytes
    // Core committed (key order, float rendering, escaping all covered).
    let mut store = KvStore::in_memory();
    store
        .set("app.theme", JsonValue::String("dark\\mode\n".into()))
        .unwrap();
    store.set("app.retries", JsonValue::Integer(3)).unwrap();
    store.set("app.ratio", JsonValue::Number(0.5)).unwrap();
    store.set("app.big", JsonValue::Number(1e20)).unwrap();
    store.set("app.enabled", JsonValue::Bool(true)).unwrap();
    store
        .set(
            "app.nested",
            JsonValue::Table(vec![
                (JsonValue::String("a".into()), JsonValue::Integer(1)),
                (
                    JsonValue::String("b".into()),
                    JsonValue::Table(vec![(
                        JsonValue::String("c".into()),
                        JsonValue::String("deep é".into()),
                    )]),
                ),
            ]),
        )
        .unwrap();
    store
        .set(
            "app.list",
            JsonValue::array(vec![JsonValue::Integer(1), JsonValue::Integer(2)]),
        )
        .unwrap();
    assert_eq!(
        store.export_json().as_bytes(),
        fixture("store.json").as_slice()
    );
}

#[test]
fn core_kv_fixture_decodes_to_core_golden_values() {
    let raw = fixture("store.json");
    let store = KvStore::load_bytes(None, &raw).expect("Core store fixture decodes");
    assert_eq!(store.len(), 7);
    assert_eq!(
        store.get("app.theme"),
        Some(JsonValue::String("dark\\mode\n".into()))
    );
    assert_eq!(store.get("app.retries"), Some(JsonValue::Integer(3)));
    assert_eq!(store.get("app.ratio"), Some(JsonValue::Number(0.5)));
    // Core committed Lua 1e20; it renders integer-like and parses back as
    // a float (above i64 range). No precision is lost: 1e20 is exact.
    assert_eq!(store.get("app.big"), Some(JsonValue::Number(1e20)));
    assert_eq!(store.get("app.enabled"), Some(JsonValue::Bool(true)));
    assert_eq!(
        store.get("app.list"),
        Some(JsonValue::array(vec![
            JsonValue::Integer(1),
            JsonValue::Integer(2)
        ]))
    );
    assert_eq!(
        store.get("app.nested"),
        Some(JsonValue::Table(vec![
            (JsonValue::String("a".into()), JsonValue::Integer(1)),
            (
                JsonValue::String("b".into()),
                JsonValue::Table(vec![(
                    JsonValue::String("c".into()),
                    JsonValue::String("deep é".into()),
                )]),
            ),
        ]))
    );
    // Decode-then-encode is byte-identical: the committed image survives a
    // load/commit cycle unchanged through this crate.
    assert_eq!(store.export_json().as_bytes(), raw.as_slice());
}

// ---------------------------------------------------------------------------
// Ceiling parity: every bound equals Core@3df633c6 (cited per constant).
// ---------------------------------------------------------------------------

#[test]
fn ceilings_match_core_byte_for_byte() {
    // Session ceilings mirror bitty-runtime session bounds at 3df633c6
    // (crates/bitty-runtime/src/runtime/session.rs).
    assert_eq!(MAX_SESSION_FILE_BYTES, 1_048_576);
    assert_eq!(MAX_SESSION_LINE_BYTES, 4096);
    assert_eq!(MAX_SESSION_WORKSPACES, 16);
    assert_eq!(MAX_SESSION_PANES_PER_WORKSPACE, 32);
    assert_eq!(MAX_SESSION_PANES_TOTAL, 128);
    assert_eq!(MAX_SESSION_SCROLLBACK_LINES_PER_PANE, 200);
    assert_eq!(MAX_SESSION_LINE_TEXT_BYTES, 4096);
    // Core derives this from bitty_rich SHELL_CWD_MAX_BYTES, itself
    // BoundedString::MAX_LEN = 4096 (crates/bitty-vt/src/bounded.rs).
    assert_eq!(MAX_SESSION_CWD_BYTES, 4096);
    assert_eq!(MAX_SESSION_NAME_CHARS, 32);
    assert_eq!(MAX_SESSION_LAYOUT_DEPTH, 64);
    // Core accepts `1..=1000` per axis (session.rs docs "View dims").
    assert_eq!(MAX_SESSION_GRID_DIM, 1000);
    assert_eq!(MIN_SESSION_GRID_DIM, 1);
    assert_eq!(SESSION_FORMAT_VERSION, 2);
    assert_eq!(SESSION_MIN_DECODE_VERSION, 1);
    assert_eq!(SESSION_APP_DIR_NAME, "bitty");
    assert_eq!(SESSIONS_DIR_NAME, "sessions");
    assert_eq!(SESSION_FILE_NAME, "session");
    // KV ceilings mirror bitty-runtime plugin store bounds at 3df633c6
    // (crates/bitty-runtime/src/plugin_runtime/store.rs).
    assert_eq!(STORE_MAX_VALUE_BYTES, 8 * 1024);
    assert_eq!(STORE_MAX_ENTRIES, 256);
    assert_eq!(STORE_MAX_TOTAL_BYTES, 64 * 1024);
    assert_eq!(STORE_MAX_KEY_BYTES, 128);
    assert_eq!(
        STORE_FILE_MAX_BYTES,
        64 * 1024 + 256 * 128 + 4096,
        "store file ceiling is the derived Core formula"
    );
    assert_eq!(JSON_MAX_DEPTH, 16);
}

// ---------------------------------------------------------------------------
// Negative parity: corrupt/oversize inputs fail with the same error KIND.
// ---------------------------------------------------------------------------

#[test]
fn negative_parity_session_kinds_match_core() {
    // Core session_storage_tests at 3df633c6: corrupt files fail (runtime
    // falls back to a clean start, errors content-free); oversize files
    // fail as TooLarge; v3 is UnsupportedVersion(3).
    let garbage = b"definitely not a session file, seed-secret-x2\xff\xfe\n".to_vec();
    let err = decode_session(&garbage).unwrap_err();
    assert!(
        matches!(err, SessionError::Corrupt(_)),
        "Core-corrupt shape must be Corrupt, got {err}"
    );
    assert!(
        !format!("{err}").contains("seed-secret-x2"),
        "denial must stay content-free like Core's"
    );

    let big = vec![b'x'; MAX_SESSION_FILE_BYTES + 1];
    assert!(
        matches!(
            decode_session(&big).unwrap_err(),
            SessionError::TooLarge { .. }
        ),
        "Core-oversize shape must be TooLarge"
    );

    let v3 = b"bitty-session v3\nworkspaces 1 active 0 mru 0\n";
    assert_eq!(
        decode_session(v3).unwrap_err(),
        SessionError::UnsupportedVersion(3),
        "Core v3 rejection must be UnsupportedVersion(3)"
    );

    // Core's over-cap scrollback header is rejected without echoing lines.
    let mut raw = format!(
        "bitty-session v1\nworkspaces 1 active 0 mru 0\nworkspace 1 none\nname ws1\nlayout (leaf 1 80 24)\npane 1 80 24 {} 0\n",
        MAX_SESSION_SCROLLBACK_LINES_PER_PANE + 1
    );
    for i in 0..MAX_SESSION_SCROLLBACK_LINES_PER_PANE + 1 {
        raw.push_str(&format!("overflow line {i}\n"));
    }
    raw.push_str("end-pane\nend-workspace\nend-session\n");
    let err = decode_session(raw.as_bytes()).unwrap_err();
    assert!(
        matches!(err, SessionError::Corrupt(_)),
        "over-cap scrollback must be Corrupt, got {err}"
    );
    assert!(!format!("{err}").contains("overflow"));

    // Core's hostile-cwd case: an escaped field that would exceed the line
    // cap fails closed before any I/O as TooLarge.
    let mut snap = SessionSnapshot {
        version: SESSION_FORMAT_VERSION,
        workspaces: vec![WorkspaceSnapshot {
            seq: 1,
            name: "ws".into(),
            layout: leaf(1),
            focus: Some(1),
            panes: vec![PaneSnapshot {
                view: 1,
                cwd: Some("\\".repeat(3000)),
                scrollback: Vec::new(),
                attach: Some(PaneAttachment::Session),
                route: PaneRoute::Terminal,
                mode: PresentationMode::Tiled,
            }],
        }],
        active: 0,
        mru: vec![0],
    };
    assert!(
        matches!(
            encode_session(&snap).unwrap_err(),
            SessionError::TooLarge { .. }
        ),
        "escape-amplified cwd must be TooLarge pre-I/O"
    );
    snap.workspaces[0].panes[0].cwd = Some("file:///tmp".into());
    assert!(encode_session(&snap).is_ok());
}

#[test]
fn negative_parity_kv_kinds_match_core() {
    // Core kv_missing_load_starts_clean_and_ceiling_holds at 3df633c6:
    // missing loads clean, over-ceiling images fail, corrupt images fail
    // with content-free errors. Kind correspondence: over-ceiling -> Quota,
    // corrupt -> ValueInvalid.
    let over = vec![b'x'; STORE_FILE_MAX_BYTES + 1];
    assert_eq!(
        KvStore::load_bytes(None, &over).unwrap_err().code(),
        StoreErrorCode::Quota
    );
    let err = KvStore::load_bytes(None, b"{not json, seed-secret-x3").unwrap_err();
    assert_eq!(err.code(), StoreErrorCode::ValueInvalid);
    assert!(!format!("{err}").contains("seed-secret-x3"));
}
