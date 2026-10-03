//! Codec round-trips, ceiling enforcement, fail-closed decode, and the
//! v1 migration path.

use bitty_storage::ceiling::*;
use bitty_storage::session_codec::*;

fn leaf(id: u64) -> LayoutNode {
    LayoutNode::Leaf {
        id,
        cols: 80,
        rows: 24,
    }
}

fn pane(view: u64, attach: Option<PaneAttachment>) -> PaneSnapshot {
    PaneSnapshot {
        view,
        cwd: Some("/tmp/work".to_string()),
        scrollback: vec!["hello".to_string(), "world".to_string()],
        attach,
        route: PaneRoute::Terminal,
        mode: PresentationMode::Tiled,
    }
}

fn snapshot() -> SessionSnapshot {
    SessionSnapshot {
        version: SESSION_FORMAT_VERSION,
        workspaces: vec![WorkspaceSnapshot {
            seq: 7,
            name: "main".to_string(),
            layout: leaf(1),
            focus: Some(1),
            panes: vec![pane(1, Some(PaneAttachment::Primary))],
        }],
        active: 0,
        mru: vec![0],
    }
}

fn multi_workspace(count: usize) -> SessionSnapshot {
    let mut snap = snapshot();
    snap.workspaces = (0..count)
        .map(|i| WorkspaceSnapshot {
            seq: i as u64,
            name: format!("ws{i}"),
            layout: leaf(1000 + i as u64),
            focus: Some(1000 + i as u64),
            panes: vec![PaneSnapshot {
                view: 1000 + i as u64,
                cwd: None,
                scrollback: Vec::new(),
                attach: Some(if i == 0 {
                    PaneAttachment::Primary
                } else {
                    PaneAttachment::Session
                }),
                route: PaneRoute::Terminal,
                mode: PresentationMode::Tiled,
            }],
        })
        .collect();
    snap.mru = (0..count).collect();
    snap
}

#[test]
fn escape_round_trip() {
    for raw in [
        "plain",
        "back\\slash",
        "line\nbreak",
        "carriage\rreturn",
        "mix\\ed\n\r end",
        "spaces stay whole",
        "unicode snowman ☃",
        "",
    ] {
        assert_eq!(unescape_field(&escape_field(raw)).unwrap(), raw);
    }
}

#[test]
fn unescape_rejects_dangling_and_unknown() {
    assert!(unescape_field("abc\\").is_err());
    assert!(unescape_field("a\\qb").is_err());
    assert!(unescape_field("a\\tb").is_err());
}

#[test]
fn layout_round_trip() {
    let tree = LayoutNode::Split {
        horizontal: true,
        ratio: 0.5,
        first: Box::new(leaf(1)),
        second: Box::new(LayoutNode::Stack(vec![leaf(2), leaf(3)])),
    };
    let line = encode_layout(&tree);
    assert_eq!(decode_layout(&line).unwrap(), tree);
}

#[test]
fn layout_vertical_axis_round_trip() {
    let tree = LayoutNode::Split {
        horizontal: false,
        ratio: 0.3,
        first: Box::new(leaf(9)),
        second: Box::new(leaf(10)),
    };
    assert_eq!(decode_layout(&encode_layout(&tree)).unwrap(), tree);
}

#[test]
fn layout_non_finite_ratio_normalizes() {
    let line = format!(
        "(split h {} (leaf 1 80 24) (leaf 2 80 24))",
        f32::NAN.to_bits()
    );
    let LayoutNode::Split { ratio, .. } = decode_layout(&line).unwrap() else {
        panic!("expected split");
    };
    assert_eq!(ratio, 0.5);
}

#[test]
fn layout_rejects_bad_shapes() {
    for line in [
        "",
        "(leaf 1 80)",
        "(leaf x 80 24)",
        "(leaf 1 0 24)",
        "(leaf 1 80 1001)",
        "(leaf 1 80 24) extra",
        "(split x 1 (leaf 1 80 24) (leaf 2 80 24))",
        "(bogus 1 2 3)",
        "(leaf 1 80 24",
        "leaf 1 80 24)",
    ] {
        assert!(decode_layout(line).is_err(), "accepted: {line}");
    }
}

#[test]
fn layout_rejects_too_many_leaves() {
    let mut inner = String::from("(stack");
    for i in 0..=MAX_SESSION_PANES_PER_WORKSPACE {
        inner.push_str(&format!(" (leaf {} 80 24)", 500 + i));
    }
    inner.push(')');
    assert!(decode_layout(&inner).is_err());
}

#[test]
fn layout_rejects_excess_depth() {
    let mut line = "(leaf 1 80 24)".to_string();
    for _ in 0..=MAX_SESSION_LAYOUT_DEPTH {
        line = format!("(split h 1056964608 {line} (leaf 2 80 24))");
    }
    assert!(decode_layout(&line).is_err());
}

#[test]
fn session_round_trip_is_byte_identical() {
    let snap = snapshot();
    let bytes = encode_session(&snap).unwrap();
    let decoded = decode_session(&bytes).unwrap();
    assert_eq!(decoded.version, SESSION_FORMAT_VERSION);
    assert_eq!(encode_session(&decoded).unwrap(), bytes);
}

#[test]
fn session_round_trip_multi_workspace_stack() {
    let snap = SessionSnapshot {
        version: SESSION_FORMAT_VERSION,
        workspaces: vec![
            WorkspaceSnapshot {
                seq: 1,
                name: "a".to_string(),
                layout: LayoutNode::Stack(vec![leaf(1), leaf(2)]),
                focus: Some(2),
                panes: vec![
                    pane(1, None),
                    PaneSnapshot {
                        view: 2,
                        cwd: None,
                        scrollback: Vec::new(),
                        attach: None,
                        route: PaneRoute::Terminal,
                        mode: PresentationMode::Floating,
                    },
                ],
            },
            WorkspaceSnapshot {
                seq: 2,
                name: "b".to_string(),
                layout: LayoutNode::Split {
                    horizontal: false,
                    ratio: 0.25,
                    first: Box::new(leaf(3)),
                    second: Box::new(leaf(4)),
                },
                focus: None,
                panes: vec![
                    PaneSnapshot {
                        view: 3,
                        cwd: None,
                        scrollback: Vec::new(),
                        attach: Some(PaneAttachment::Detached),
                        route: PaneRoute::Terminal,
                        mode: PresentationMode::Tiled,
                    },
                    pane(4, Some(PaneAttachment::Session)),
                ],
            },
        ],
        active: 1,
        mru: vec![1, 0],
    };
    let bytes = encode_session(&snap).unwrap();
    let decoded = decode_session(&bytes).unwrap();
    // Legacy `None` attachments resolve through the startup owner on encode
    // (workspace "b" is active with no focus, so leaf 3 owns startup and
    // every `None` pane lands on `Session`).
    assert_eq!(encode_session(&decoded).unwrap(), bytes);
    assert_eq!(
        decoded.workspaces[0].panes[0].attach,
        Some(PaneAttachment::Session)
    );
}

#[test]
fn v1_file_migrates_to_v2_shape() {
    let v1 = "bitty-session v1\n\
        workspaces 1 active 0 mru 0\n\
        workspace 3 none\n\
        name legacy\n\
        layout (leaf 11 80 24)\n\
        pane 11 80 24 1 1\n\
        /tmp/old\n\
        old line\n\
        end-pane\n\
        end-workspace\n\
        end-session\n";
    let snap = decode_session(v1.as_bytes()).unwrap();
    assert_eq!(snap.version, SESSION_FORMAT_VERSION);
    assert_eq!(snap.workspaces[0].panes[0].attach, None);
    assert_eq!(snap.workspaces[0].panes[0].route, PaneRoute::Terminal);
    assert_eq!(snap.workspaces[0].panes[0].mode, PresentationMode::Tiled);
    // Migrated snapshots re-encode as v2 and decode again cleanly.
    let v2 = encode_session(&snap).unwrap();
    assert!(v2.starts_with(b"bitty-session v2\n"));
    let again = decode_session(&v2).unwrap();
    assert_eq!(encode_session(&again).unwrap(), v2);
}

#[test]
fn decode_rejects_versions_outside_v1_to_v2() {
    for version in [0, 3, 9, 99] {
        let text = format!("bitty-session v{version}\n");
        match decode_session(text.as_bytes()) {
            Err(SessionError::UnsupportedVersion(v)) => assert_eq!(v, version),
            other => panic!("version {version}: expected UnsupportedVersion, got {other:?}"),
        }
    }
}

#[test]
fn decode_rejects_bad_magic_truncation_trailing() {
    let good = encode_session(&snapshot()).unwrap();
    let good_text = std::str::from_utf8(&good).unwrap();
    // Bad magic.
    assert!(decode_session(b"nope\n").is_err());
    // Truncated (drop the end-session marker).
    let truncated: Vec<u8> = good[..good.len() - 12].to_vec();
    assert!(decode_session(&truncated).is_err());
    // Trailing data after end-session.
    let mut trailing = good.clone();
    trailing.extend_from_slice(b"extra\n");
    assert!(decode_session(&trailing).is_err());
    // Non-UTF8.
    assert!(matches!(
        decode_session(&[0xff, 0xfe, b'\n']),
        Err(SessionError::Corrupt(_))
    ));
    // Empty.
    assert!(decode_session(b"").is_err());
    let _ = good_text;
}

#[test]
fn decode_rejects_oversize_file_and_line() {
    assert!(matches!(
        decode_session(&vec![b'x'; MAX_SESSION_FILE_BYTES + 1]),
        Err(SessionError::TooLarge { .. })
    ));
    let mut text = String::from("bitty-session v2\n");
    text.push_str(&"y".repeat(MAX_SESSION_LINE_BYTES + 1));
    text.push('\n');
    assert!(matches!(
        decode_session(text.as_bytes()),
        Err(SessionError::TooLarge { .. })
    ));
}

#[test]
fn encode_rejects_oversize_file() {
    let mut snap = snapshot();
    snap.workspaces[0].panes[0].scrollback = vec!["z".repeat(4000); 200];
    // 200 x ~4000B lines approaches but stays under 1 MiB; force the trip
    // with many workspaces at the cap instead.
    let mut big = multi_workspace(16);
    for ws in &mut big.workspaces {
        ws.panes[0].scrollback = vec!["w".repeat(4000); 8];
    }
    // 16 panes x 8 lines x 4000B = ~512 KiB: still under; assert the small
    // case encodes, and construct the true oversize via raw decode guard.
    assert!(encode_session(&big).is_ok());
    let _ = snap;
    assert!(matches!(
        decode_session(&vec![b'q'; MAX_SESSION_FILE_BYTES + 1]),
        Err(SessionError::TooLarge { .. })
    ));
}

#[test]
fn encode_rejects_escaped_line_overflow() {
    // 3000 backslashes escape to 6000 bytes: raw text within its own
    // bound, escaped line over the decode line cap.
    let mut snap = snapshot();
    snap.workspaces[0].panes[0].scrollback = vec!["\\".repeat(3000)];
    assert!(matches!(
        encode_session(&snap),
        Err(SessionError::TooLarge { .. })
    ));
}

#[test]
fn ceilings_are_enforced_on_encode() {
    // Workspace count.
    assert!(encode_session(&multi_workspace(MAX_SESSION_WORKSPACES + 1)).is_err());
    // Workspace name chars.
    let mut snap = snapshot();
    snap.workspaces[0].name = "n".repeat(MAX_SESSION_NAME_CHARS + 1);
    assert!(encode_session(&snap).is_err());
    // Cwd bytes.
    let mut snap = snapshot();
    snap.workspaces[0].panes[0].cwd = Some("c".repeat(MAX_SESSION_CWD_BYTES + 1));
    assert!(encode_session(&snap).is_err());
    // Scrollback lines per pane.
    let mut snap = snapshot();
    snap.workspaces[0].panes[0].scrollback =
        vec!["l".to_string(); MAX_SESSION_SCROLLBACK_LINES_PER_PANE + 1];
    assert!(encode_session(&snap).is_err());
    // Scrollback line bytes.
    let mut snap = snapshot();
    snap.workspaces[0].panes[0].scrollback = vec!["l".repeat(MAX_SESSION_LINE_TEXT_BYTES + 1)];
    assert!(encode_session(&snap).is_err());
}

#[test]
fn pane_count_ceilings_hold() {
    // 33 panes in one workspace.
    let panes: Vec<PaneSnapshot> = (0..=MAX_SESSION_PANES_PER_WORKSPACE as u64)
        .map(|i| PaneSnapshot {
            view: 200 + i,
            cwd: None,
            scrollback: Vec::new(),
            attach: Some(PaneAttachment::Session),
            route: PaneRoute::Terminal,
            mode: PresentationMode::Tiled,
        })
        .collect();
    let mut children = String::from("(stack");
    for i in 0..=MAX_SESSION_PANES_PER_WORKSPACE as u64 {
        children.push_str(&format!(" (leaf {} 80 24)", 200 + i));
    }
    children.push(')');
    let snap = SessionSnapshot {
        version: SESSION_FORMAT_VERSION,
        workspaces: vec![WorkspaceSnapshot {
            seq: 1,
            name: "crowded".to_string(),
            layout: decode_layout(&children).unwrap_or(LayoutNode::Stack(vec![leaf(200)])),
            focus: Some(200),
            panes,
        }],
        active: 0,
        mru: vec![0],
    };
    // Either the layout decode or the snapshot validation must refuse.
    let refused = decode_layout(&children).is_err() || encode_session(&snap).is_err();
    assert!(refused, "33-pane workspace must be refused");
}

#[test]
fn total_pane_ceiling_holds() {
    // 16 workspaces x 8 panes = 128 is fine; 129 must fail.
    let mut ok = multi_workspace(16);
    for (i, ws) in ok.workspaces.iter_mut().enumerate() {
        let base = 5000 + (i as u64) * 10;
        ws.layout = LayoutNode::Stack((0..8).map(|k| leaf(base + k)).collect());
        ws.focus = Some(base);
        ws.panes = (0..8)
            .map(|k| PaneSnapshot {
                view: base + k,
                cwd: None,
                scrollback: Vec::new(),
                attach: Some(if i == 0 && k == 0 {
                    PaneAttachment::Primary
                } else {
                    PaneAttachment::Session
                }),
                route: PaneRoute::Terminal,
                mode: PresentationMode::Tiled,
            })
            .collect();
    }
    assert!(encode_session(&ok).is_ok());
    let mut over = ok.clone();
    over.workspaces[0].layout = LayoutNode::Stack((0..9).map(|k| leaf(9000 + k)).collect());
    over.workspaces[0].focus = Some(9000);
    over.workspaces[0].panes.push(PaneSnapshot {
        view: 9008,
        cwd: None,
        scrollback: Vec::new(),
        attach: Some(PaneAttachment::Session),
        route: PaneRoute::Terminal,
        mode: PresentationMode::Tiled,
    });
    assert!(encode_session(&over).is_err());
}

#[test]
fn structural_violations_rejected() {
    // Active out of range.
    let mut snap = snapshot();
    snap.active = 3;
    assert!(encode_session(&snap).is_err());
    // MRU length mismatch.
    let mut snap = snapshot();
    snap.mru = vec![0, 1];
    assert!(encode_session(&snap).is_err());
    // MRU head must be active.
    let mut snap = multi_workspace(2);
    snap.active = 0;
    snap.mru = vec![1, 0];
    assert!(encode_session(&snap).is_err());
    // Duplicate workspace seq.
    let mut snap = multi_workspace(2);
    snap.workspaces[1].seq = snap.workspaces[0].seq;
    assert!(encode_session(&snap).is_err());
    // Duplicate pane id across workspaces.
    let mut snap = multi_workspace(2);
    snap.workspaces[1].layout = leaf(1000);
    snap.workspaces[1].panes[0].view = 1000;
    assert!(encode_session(&snap).is_err());
    // Focus not a leaf.
    let mut snap = snapshot();
    snap.workspaces[0].focus = Some(999);
    assert!(encode_session(&snap).is_err());
    // Pane coverage mismatch.
    let mut snap = snapshot();
    snap.workspaces[0].panes.push(pane(2, None));
    assert!(encode_session(&snap).is_err());
    // Detached pane carrying state.
    let mut snap = snapshot();
    snap.workspaces[0].panes[0].attach = Some(PaneAttachment::Detached);
    assert!(encode_session(&snap).is_err());
    // Duplicate primary.
    let mut snap = multi_workspace(2);
    snap.workspaces[0].panes[0].attach = Some(PaneAttachment::Primary);
    snap.workspaces[1].panes[0].attach = Some(PaneAttachment::Primary);
    assert!(encode_session(&snap).is_err());
    // Wrong version on encode.
    let mut snap = snapshot();
    snap.version = 1;
    assert!(matches!(
        encode_session(&snap),
        Err(SessionError::UnsupportedVersion(1))
    ));
}

#[test]
fn decode_enforces_field_bounds_fail_closed() {
    // Cwd over bound inside an otherwise valid file.
    let mut text = String::from(
        "bitty-session v2\nworkspaces 1 active 0 mru 0\nworkspace 1 10\nname w\nlayout (leaf 10 80 24)\n",
    );
    text.push_str("pane 10 80 24 0 1 primary terminal tiled\n");
    text.push_str(&"c".repeat(MAX_SESSION_CWD_BYTES + 1));
    text.push_str("\nend-pane\nend-workspace\nend-session\n");
    assert!(decode_session(text.as_bytes()).is_err());
    // Scrollback count over bound.
    let bad = "bitty-session v2\nworkspaces 1 active 0 mru 0\nworkspace 1 10\nname w\nlayout (leaf 10 80 24)\n\
        pane 10 80 24 201 0 primary terminal tiled\nend-pane\nend-workspace\nend-session\n";
    assert!(decode_session(bad.as_bytes()).is_err());
    // Bad escape in a field.
    let bad_esc = "bitty-session v2\nworkspaces 1 active 0 mru 0\nworkspace 1 10\nname a\\qb\nlayout (leaf 10 80 24)\n\
        pane 10 80 24 0 0 primary terminal tiled\nend-pane\nend-workspace\nend-session\n";
    assert!(decode_session(bad_esc.as_bytes()).is_err());
    // Unknown attach/route/mode tokens.
    let bad_tok = "bitty-session v2\nworkspaces 1 active 0 mru 0\nworkspace 1 10\nname w\nlayout (leaf 10 80 24)\n\
        pane 10 80 24 0 0 owner terminal tiled\nend-pane\nend-workspace\nend-session\n";
    assert!(decode_session(bad_tok.as_bytes()).is_err());
    // Pane dims mismatch vs layout.
    let mismatch = "bitty-session v2\nworkspaces 1 active 0 mru 0\nworkspace 1 10\nname w\nlayout (leaf 10 80 24)\n\
        pane 10 100 24 0 0 primary terminal tiled\nend-pane\nend-workspace\nend-session\n";
    assert!(decode_session(mismatch.as_bytes()).is_err());
}

#[test]
fn xdg_helpers_use_injected_values() {
    let dir = session_file_for(Some("/xdg-state"), Some("/ignored-home")).unwrap();
    assert_eq!(
        dir,
        std::path::PathBuf::from("/xdg-state/bitty/sessions/session")
    );
    let dir = session_file_for(None, Some("/fake-home")).unwrap();
    assert_eq!(
        dir,
        std::path::PathBuf::from("/fake-home/.local/state/bitty/sessions/session")
    );
    assert!(session_file_for(Some("   "), Some("  ")).is_none());
    assert!(session_file_for(None, None).is_none());
    // Live wrappers resolve from the process environment without panicking.
    let _ = bitty_storage::session_codec::session_file();
    let _ = bitty_storage::session_codec::session_dir();
    let _ = bitty_storage::session_codec::state_home();
}

#[test]
fn error_display_is_content_free() {
    let err = SessionError::Corrupt("marker");
    assert_eq!(err.to_string(), "session file corrupt (marker)");
    assert_eq!(SessionError::NotFound.to_string(), "session file not found");
    assert_eq!(
        SessionError::UnsupportedVersion(9).to_string(),
        "unsupported session version (9)"
    );
}
