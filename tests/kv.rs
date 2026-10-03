//! KV quota typed denials, atomic commits, retention/purge with
//! deletion evidence, and load fail-closed behavior.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use bitty_storage::ceiling::*;
use bitty_storage::kv::*;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bitty-kv-{}-{}-{}",
        name,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn small_value(n: usize) -> JsonValue {
    JsonValue::String("v".repeat(n))
}

#[test]
fn set_get_remove_round_trip() {
    let mut store = KvStore::in_memory();
    assert!(store.is_empty());
    store.set("alpha", JsonValue::Integer(1)).unwrap();
    store
        .set("beta", JsonValue::array(vec![JsonValue::Bool(true)]))
        .unwrap();
    assert_eq!(store.get("alpha"), Some(JsonValue::Integer(1)));
    assert_eq!(store.len(), 2);
    store.remove("alpha").unwrap();
    assert_eq!(store.get("alpha"), None);
    // Absent-key removal is a successful no-op.
    store.remove("missing").unwrap();
    assert_eq!(store.len(), 1);
}

#[test]
fn key_grammar_denials_are_typed() {
    let mut store = KvStore::in_memory();
    for bad in [
        String::new(),
        "Upper".to_string(),
        "-dash-start".to_string(),
        ".dot-start".to_string(),
        "has space".to_string(),
        "has/slash".to_string(),
        "double..dot".to_string(),
        "x".repeat(STORE_MAX_KEY_BYTES + 1),
    ] {
        let err = store.set(&bad, JsonValue::Integer(0)).unwrap_err();
        assert_eq!(err.code(), StoreErrorCode::KeyInvalid, "key: {bad}");
        assert_eq!(err.wire_code(), "E_STORE_KEY_INVALID");
    }
    for good in [
        "a",
        "0",
        "9lives-ok",
        "a-b.c_d",
        "x".repeat(STORE_MAX_KEY_BYTES).as_str(),
    ] {
        store.set(good, JsonValue::Integer(0)).unwrap();
    }
}

#[test]
fn oversize_value_denied_with_previous_intact() {
    let mut store = KvStore::in_memory();
    store.set("keep", JsonValue::Integer(7)).unwrap();
    let err = store
        .set("big", small_value(STORE_MAX_VALUE_BYTES))
        .unwrap_err();
    assert_eq!(err.code(), StoreErrorCode::ValueInvalid);
    assert_eq!(err.wire_code(), "E_STORE_VALUE_INVALID");
    assert_eq!(store.get("keep"), Some(JsonValue::Integer(7)));
    assert_eq!(store.get("big"), None);
}

#[test]
fn entry_count_quota_denied_atomically() {
    let mut store = KvStore::in_memory();
    for i in 0..STORE_MAX_ENTRIES {
        store
            .set(&format!("k{i:04}"), JsonValue::Integer(i as i64))
            .unwrap();
    }
    assert_eq!(store.len(), STORE_MAX_ENTRIES);
    let err = store.set("overflow", JsonValue::Integer(-1)).unwrap_err();
    assert_eq!(err.code(), StoreErrorCode::Quota);
    assert_eq!(err.wire_code(), "E_STORE_QUOTA");
    assert_eq!(store.len(), STORE_MAX_ENTRIES);
    assert_eq!(store.get("overflow"), None);
}

#[test]
fn total_bytes_quota_denied_atomically() {
    let mut store = KvStore::in_memory();
    // Values just under the per-value ceiling; enough of them trips the
    // 64 KiB aggregate budget before the 256-entry cap.
    let chunk = STORE_MAX_VALUE_BYTES - 64;
    let mut i = 0;
    loop {
        let key = format!("bulk{i:04}");
        match store.set(&key, small_value(chunk)) {
            Ok(()) => i += 1,
            Err(err) => {
                assert_eq!(err.code(), StoreErrorCode::Quota);
                break;
            }
        }
        assert!(i < STORE_MAX_ENTRIES, "entry cap hit before byte quota");
    }
    assert!(!store.is_empty());
}

#[test]
fn nesting_depth_enforced() {
    fn nested(depth: usize) -> JsonValue {
        let mut v = JsonValue::Integer(1);
        for _ in 0..depth {
            v = JsonValue::array(vec![v]);
        }
        v
    }
    let mut store = KvStore::in_memory();
    store.set("ok", nested(4)).unwrap();
    let err = store.set("deep", nested(JSON_MAX_DEPTH + 4)).unwrap_err();
    assert_eq!(err.code(), StoreErrorCode::ValueInvalid);
    assert!(store.get("deep").is_none());
    // Parser depth guard trips on hostile input too.
    let mut hostile = String::new();
    for _ in 0..JSON_MAX_DEPTH + 4 {
        hostile.push('[');
    }
    for _ in 0..JSON_MAX_DEPTH + 4 {
        hostile.push(']');
    }
    assert!(parse_json(&hostile).is_err());
}

#[test]
fn non_finite_numbers_rejected() {
    let mut store = KvStore::in_memory();
    for n in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let err = store.set("num", JsonValue::Number(n)).unwrap_err();
        assert_eq!(err.code(), StoreErrorCode::ValueInvalid);
    }
    assert!(store.get("num").is_none());
}

#[test]
fn json_round_trip_all_shapes() {
    let values = vec![
        JsonValue::Nil,
        JsonValue::Bool(true),
        JsonValue::Bool(false),
        JsonValue::Integer(-42),
        JsonValue::Number(2.5),
        JsonValue::String("esc \" \\ \n \r \t \u{1} snowman ☃".to_string()),
        JsonValue::array(vec![JsonValue::Integer(1), JsonValue::Nil]),
        JsonValue::Table(vec![(
            JsonValue::String("k".to_string()),
            JsonValue::Integer(1),
        )]),
    ];
    for v in values {
        assert_eq!(parse_json(&encode_json(&v)).unwrap(), v);
    }
    // Integer table keys normalize to strings on encode (Core parity:
    // the JSON object model has string keys only).
    let int_keyed = JsonValue::Table(vec![(
        JsonValue::Integer(2),
        JsonValue::String("num-key".to_string()),
    )]);
    assert_eq!(
        parse_json(&encode_json(&int_keyed)).unwrap(),
        JsonValue::Table(vec![(
            JsonValue::String("2".to_string()),
            JsonValue::String("num-key".to_string()),
        )])
    );
    // Malformed inputs fail closed.
    for bad in [
        "",
        "{",
        "{\"a\":}",
        "[1,]",
        "{\"a\" 1}",
        "tru",
        "nul",
        "[1 2]",
        "\u{0}",
    ] {
        assert!(parse_json(bad).is_err(), "accepted: {bad:?}");
    }
}

#[test]
fn file_persistence_round_trip() {
    let dir = scratch_dir("persist");
    let path = dir.join("store.json");
    let mut store = KvStore::with_path(Some(path.clone()));
    store
        .set("theme", JsonValue::String("dark".to_string()))
        .unwrap();
    store.set("count", JsonValue::Integer(3)).unwrap();
    assert!(path.exists());
    let reloaded = KvStore::load(path.clone()).unwrap();
    assert_eq!(
        reloaded.get("theme"),
        Some(JsonValue::String("dark".to_string()))
    );
    assert_eq!(reloaded.get("count"), Some(JsonValue::Integer(3)));
    // Denied writes leave the committed file untouched.
    let before = std::fs::read(&path).unwrap();
    let mut writer = KvStore::load(path.clone()).unwrap();
    assert!(
        writer
            .set("big", small_value(STORE_MAX_VALUE_BYTES))
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(KvStore::load(path).unwrap().get("big"), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_store_file_starts_clean() {
    let dir = scratch_dir("absent");
    let store = KvStore::load(dir.join("nope.json")).unwrap();
    assert!(store.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_rejects_bad_images_fail_closed() {
    // Non-object root.
    assert!(KvStore::load_bytes(None, b"[1,2]").is_err());
    // Non-string key.
    assert!(KvStore::load_bytes(None, b"{1:2}").is_err());
    // Unparsable.
    assert!(KvStore::load_bytes(None, b"{oops").is_err());
    // Not UTF-8.
    assert!(KvStore::load_bytes(None, &[0xff, 0xfe]).is_err());
    // Oversize file image.
    assert!(KvStore::load_bytes(None, &vec![b'{'; STORE_FILE_MAX_BYTES + 1]).is_err());
    // Over-quota content.
    let mut big = String::from("{");
    for i in 0..STORE_MAX_ENTRIES + 1 {
        if i > 0 {
            big.push(',');
        }
        big.push_str(&format!("\"k{i:04}\":1"));
    }
    big.push('}');
    assert!(KvStore::load_bytes(None, big.as_bytes()).is_err());
    // Invalid key inside the file.
    assert!(KvStore::load_bytes(None, b"{\"Bad\":1}").is_err());
}

#[test]
fn purge_removes_bytes_and_query_returns_nothing() {
    let dir = scratch_dir("purge");
    let path = dir.join("store.json");
    let mut store = KvStore::with_path(Some(path.clone()));
    store.set("a", JsonValue::Integer(1)).unwrap();
    store
        .set("b", JsonValue::String("two".to_string()))
        .unwrap();
    assert!(path.exists());
    let evidence = store.purge();
    assert_eq!(evidence.keys_removed, 2);
    assert!(evidence.bytes_removed > 0);
    assert!(evidence.file_removed);
    assert!(!path.exists());
    // Post-purge export/query returns nothing.
    assert_eq!(store.export_json(), "{}");
    assert_eq!(store.get("a"), None);
    assert_eq!(store.get("b"), None);
    assert!(store.is_empty());
    // A reload from the removed path starts clean (no resurrection).
    let reloaded = KvStore::load(path).unwrap();
    assert!(reloaded.is_empty());
    assert_eq!(reloaded.export_json(), "{}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn in_memory_purge_needs_no_file() {
    let mut store = KvStore::in_memory();
    store.set("x", JsonValue::Bool(true)).unwrap();
    let evidence = store.purge();
    assert_eq!(evidence.keys_removed, 1);
    assert!(!evidence.file_removed);
    assert_eq!(store.export_json(), "{}");
}
