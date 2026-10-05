//! Per-plugin KV filesystem backend mechanics.
//!
//! Ported from the Core `bitty.store` backend: bounded key grammar,
//! quota validation before any mutation, hand-rolled deterministic JSON,
//! and atomic durable commits that leave the previous state intact on
//! denial. The Lua-side quota bridge and the host-service contract stay
//! with Core/SDK; this module implements the bytes behind the Core-owned
//! gate. No eviction, no partial writes, no cross-plugin reads.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::atomic_io::{LoadError, unique_temp_sibling_for, write_atomic_durably};
use crate::ceiling::{
    JSON_MAX_DEPTH, STORE_FILE_MAX_BYTES, STORE_MAX_ENTRIES, STORE_MAX_KEY_BYTES,
    STORE_MAX_TOTAL_BYTES, STORE_MAX_VALUE_BYTES,
};

/// JSON-compatible plain data (hand-rolled, std-only; no serde).
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    /// JSON `null` (also the deletion marker on the write path).
    Nil,
    /// JSON boolean.
    Bool(bool),
    /// JSON integer.
    Integer(i64),
    /// JSON number (must be finite to persist).
    Number(f64),
    /// JSON string.
    String(String),
    /// JSON object (string keys) or array (1-based integer keys) as
    /// ordered pairs; encoding decides the shape deterministically.
    Table(Vec<(JsonValue, JsonValue)>),
}

impl JsonValue {
    /// Builds an array table from ordered values (1-based integer keys).
    #[must_use]
    pub fn array(values: Vec<JsonValue>) -> Self {
        let pairs = values
            .into_iter()
            .enumerate()
            .map(|(i, v)| (Self::Integer(i as i64 + 1), v))
            .collect();
        Self::Table(pairs)
    }
}

/// Typed denial codes (stable strings; the SDK maps them to Lua errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreErrorCode {
    /// Key grammar violation.
    KeyInvalid,
    /// Value shape violation (size, depth, non-finite, bad key type).
    ValueInvalid,
    /// Entry-count or total-bytes quota exceeded.
    Quota,
    /// Durable commit failed; previous state is intact.
    Io,
}

/// Typed, catchable denial. Messages are bounded and content-free except
/// the offending key on load (keys are plugin-authored identifiers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    code: StoreErrorCode,
    message: String,
}

impl StoreError {
    #[must_use]
    pub fn new(code: StoreErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn code(&self) -> StoreErrorCode {
        self.code
    }

    /// Stable wire code (`E_STORE_*`).
    #[must_use]
    pub fn wire_code(&self) -> &'static str {
        match self.code {
            StoreErrorCode::KeyInvalid => "E_STORE_KEY_INVALID",
            StoreErrorCode::ValueInvalid => "E_STORE_VALUE_INVALID",
            StoreErrorCode::Quota => "E_STORE_QUOTA",
            StoreErrorCode::Io => "E_STORE_IO",
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.wire_code(), self.message)
    }
}

impl std::error::Error for StoreError {}

/// One plugin's bounded key/value store (single-namespace mechanics).
///
/// Validation runs before any mutation; commits are atomic. A denied
/// write leaves both the in-memory state and the previously committed
/// file untouched.
#[derive(Debug)]
pub struct KvStore {
    path: Option<PathBuf>,
    entries: BTreeMap<String, JsonValue>,
}

impl KvStore {
    /// In-memory store with no persistence path.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            entries: BTreeMap::new(),
        }
    }

    /// Empty store that commits to `path` (`None` disables persistence).
    #[must_use]
    pub fn with_path(path: Option<PathBuf>) -> Self {
        Self {
            path,
            entries: BTreeMap::new(),
        }
    }

    /// Load from `path`, or start empty when the file is absent (clean
    /// start). The read streams through a `take(cap + 1)` bound at
    /// [`STORE_FILE_MAX_BYTES`], so at most `cap + 1` bytes are ever
    /// buffered or read and a large or hostile file cannot cause an
    /// unbounded allocation. A metadata size pre-check fails closed
    /// early on already-oversize files; it is an early-out only and the
    /// take-limited streaming read remains the enforcement point, so a
    /// grow-after-stat race cannot bypass the cap. Over-cap,
    /// unparsable, or quota-violating files are rejected with the
    /// previous (empty) state intact. The over-cap report saturates at
    /// `cap + 1` ("over cap"), never the exact file size.
    pub fn load(path: PathBuf) -> Result<Self, StoreError> {
        // Metadata early-out only, never enforcement: stat first and fail
        // closed with a saturated over-cap report when the file is already
        // over the ceiling. A metadata failure falls through to the
        // streaming read below, which stays authoritative, so a
        // grow-after-stat race cannot bypass the cap (fail-closed only
        // toward rejection).
        if let Ok(metadata) = std::fs::metadata(&path) {
            if metadata.len() > STORE_FILE_MAX_BYTES as u64 {
                return Err(map_load_error(&LoadError::TooLarge {
                    actual: STORE_FILE_MAX_BYTES.saturating_add(1),
                    limit: STORE_FILE_MAX_BYTES,
                }));
            }
        }
        let bytes = match crate::atomic_io::load_bytes_capped(&path, STORE_FILE_MAX_BYTES) {
            Ok(bytes) => bytes,
            Err(LoadError::NotFound) => return Ok(Self::with_path(Some(path))),
            Err(err) => return Err(map_load_error(&err)),
        };
        Self::load_bytes(Some(path), &bytes)
    }

    /// Decode `bytes` as a store image (shared by file load and tests).
    pub fn load_bytes(path: Option<PathBuf>, bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() > STORE_FILE_MAX_BYTES {
            return Err(StoreError::new(
                StoreErrorCode::Quota,
                "plugin store exceeds the file ceiling",
            ));
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| StoreError::load("store image is not UTF-8"))?;
        let value = parse_json(text).map_err(StoreError::load)?;
        let JsonValue::Table(pairs) = value else {
            return Err(StoreError::load("store root must be an object"));
        };
        let mut entries = BTreeMap::new();
        for (key, entry) in pairs {
            let JsonValue::String(key) = key else {
                return Err(StoreError::load("store keys must be strings"));
            };
            validate_entry(&key, &entry).map_err(|err| {
                StoreError::load(format!(
                    "store entry violates invariants: {}",
                    err.message()
                ))
            })?;
            entries.insert(key, entry);
        }
        validate_store_quota(&entries)
            .map_err(|err| StoreError::load(format!("store quota violated: {}", err.message())))?;
        Ok(Self { path, entries })
    }

    /// Read a value; `None` when absent.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<JsonValue> {
        self.entries.get(key).cloned()
    }

    /// Atomically set one entry. Fails closed before any mutation on
    /// invalid key, value, or quota.
    pub fn set(&mut self, key: &str, value: JsonValue) -> Result<(), StoreError> {
        validate_key(key)?;
        validate_entry(key, &value)?;
        let mut candidate = self.entries.clone();
        candidate.insert(key.to_string(), value);
        validate_store_quota(&candidate)?;
        self.persist_entries(&candidate)?;
        self.entries = candidate;
        Ok(())
    }

    /// Atomically delete one entry (explicit `nil` write). Absent keys
    /// are a successful no-op that still commits.
    pub fn remove(&mut self, key: &str) -> Result<(), StoreError> {
        validate_key(key)?;
        let mut candidate = self.entries.clone();
        candidate.remove(key);
        self.persist_entries(&candidate)?;
        self.entries = candidate;
        Ok(())
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Persistence path, if any.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Deterministic export of every entry (query surface for evidence:
    /// after a purge this returns the empty object).
    #[must_use]
    pub fn export_json(&self) -> String {
        let mut out = String::from("{");
        for (index, (key, value)) in self.entries.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&encode_json(&JsonValue::String(key.clone())));
            out.push(':');
            out.push_str(&encode_json(value));
        }
        out.push('}');
        out
    }

    /// Authoritative purge: removes the committed bytes (when a path is
    /// configured) and clears every entry, returning deletion evidence.
    /// A post-purge [`export_json`](Self::export_json) returns the empty
    /// object and [`get`](Self::get) returns `None` for every key.
    ///
    /// A missing file is a successful no-op (`file_removed: false`); any
    /// other removal failure is returned so callers can tell when
    /// committed bytes may remain on disk. The file is removed before the
    /// in-memory entries are cleared, so a failed purge leaves both the
    /// committed file and the previous state intact.
    pub fn purge(&mut self) -> Result<DeletionEvidence, StoreError> {
        let keys_removed = self.entries.len();
        let bytes_removed = self.export_json().len();
        let file_removed = match &self.path {
            None => false,
            Some(path) => match std::fs::remove_file(path) {
                Ok(()) => true,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
                Err(err) => {
                    return Err(StoreError::new(
                        StoreErrorCode::Io,
                        format!("purge could not remove the store file: {err}"),
                    ));
                }
            },
        };
        self.entries.clear();
        Ok(DeletionEvidence {
            keys_removed,
            bytes_removed,
            file_removed,
        })
    }

    fn persist_entries(&self, candidate: &BTreeMap<String, JsonValue>) -> Result<(), StoreError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut buffer = String::from("{");
        for (index, (key, value)) in candidate.iter().enumerate() {
            if index > 0 {
                buffer.push(',');
            }
            buffer.push_str(&encode_json(&JsonValue::String(key.clone())));
            buffer.push(':');
            buffer.push_str(&encode_json(value));
        }
        buffer.push('}');
        let temp = unique_temp_sibling_for(path);
        write_atomic_durably(path, buffer.as_bytes(), &temp).map_err(|_| {
            StoreError::new(StoreErrorCode::Io, "could not commit the plugin state file")
        })?;
        Ok(())
    }
}

impl StoreError {
    fn load(message: impl Into<String>) -> Self {
        // Load rejections surface as value-invalid denials with bounded
        // detail; quota violations keep their own code via the caller.
        Self::new(StoreErrorCode::ValueInvalid, message)
    }
}

/// Evidence that a purge removed bytes (never a filtered view described
/// as a purge).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeletionEvidence {
    /// Entries cleared from memory.
    pub keys_removed: usize,
    /// Export bytes accounted before removal.
    pub bytes_removed: usize,
    /// Whether a committed store file was deleted.
    pub file_removed: bool,
}

/// Validate one key/value pair against store invariants.
pub fn validate_entry(key: &str, value: &JsonValue) -> Result<(), StoreError> {
    validate_key(key)?;
    let encoded = encode_json(value);
    if encoded.len() > STORE_MAX_VALUE_BYTES {
        return Err(StoreError::new(
            StoreErrorCode::ValueInvalid,
            "store value exceeds the 8 KiB ceiling",
        ));
    }
    validate_json_value(value, 2)?;
    Ok(())
}

/// Validate the aggregate quota (entry count and total encoded bytes).
pub fn validate_store_quota(entries: &BTreeMap<String, JsonValue>) -> Result<(), StoreError> {
    if entries.len() > STORE_MAX_ENTRIES {
        return Err(StoreError::new(
            StoreErrorCode::Quota,
            "plugin store entry count exceeds limit",
        ));
    }
    let total: usize = entries
        .iter()
        .map(|(k, v)| k.len() + encode_json(v).len())
        .sum();
    if total > STORE_MAX_TOTAL_BYTES {
        return Err(StoreError::new(
            StoreErrorCode::Quota,
            "plugin store quota exceeded",
        ));
    }
    Ok(())
}

/// Key grammar: `1..=128` bytes, starts `[a-z0-9]`, body
/// `[a-z0-9-._]`, no empty dot segments.
pub fn validate_key(key: &str) -> Result<(), StoreError> {
    if key.is_empty() || key.len() > STORE_MAX_KEY_BYTES {
        return Err(StoreError::new(
            StoreErrorCode::KeyInvalid,
            "store key must be 1..128 bytes",
        ));
    }
    let bytes = key.as_bytes();
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(StoreError::new(
            StoreErrorCode::KeyInvalid,
            "store key must start with [a-z0-9]",
        ));
    }
    for byte in bytes {
        let allowed = byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'-' | b'.' | b'_');
        if !allowed {
            return Err(StoreError::new(
                StoreErrorCode::KeyInvalid,
                "store key contains an invalid character",
            ));
        }
    }
    if key.contains("..") {
        return Err(StoreError::new(
            StoreErrorCode::KeyInvalid,
            "store key must not contain empty dot segments",
        ));
    }
    Ok(())
}

fn validate_json_value(value: &JsonValue, depth: usize) -> Result<(), StoreError> {
    if depth > JSON_MAX_DEPTH {
        return Err(StoreError::new(
            StoreErrorCode::ValueInvalid,
            "store value nesting exceeds depth ceiling",
        ));
    }
    match value {
        JsonValue::Nil | JsonValue::Bool(_) | JsonValue::Integer(_) => Ok(()),
        JsonValue::Number(n) if n.is_finite() => Ok(()),
        JsonValue::Number(_) => Err(StoreError::new(
            StoreErrorCode::ValueInvalid,
            "store value must be finite",
        )),
        JsonValue::String(s) if std::str::from_utf8(s.as_bytes()).is_ok() => Ok(()),
        JsonValue::String(_) => Err(StoreError::new(
            StoreErrorCode::ValueInvalid,
            "store value must be valid UTF-8",
        )),
        JsonValue::Table(pairs) => {
            for (key, child) in pairs {
                match key {
                    JsonValue::String(_) | JsonValue::Integer(_) => {}
                    _ => {
                        return Err(StoreError::new(
                            StoreErrorCode::ValueInvalid,
                            "store table keys must be strings or numbers",
                        ));
                    }
                }
                validate_json_value(child, depth + 1)?;
            }
            Ok(())
        }
    }
}

/// Encode a bounded value as deterministic compact JSON.
#[must_use]
pub fn encode_json(value: &JsonValue) -> String {
    match value {
        JsonValue::Nil => "null".to_string(),
        JsonValue::Bool(true) => "true".to_string(),
        JsonValue::Bool(false) => "false".to_string(),
        JsonValue::Integer(i) => i.to_string(),
        JsonValue::Number(n) => {
            if *n == n.trunc() && n.is_finite() && n.abs() < 9.007_199_254_740_992e15 {
                format!("{}", *n as i64)
            } else {
                format!("{n}")
            }
        }
        JsonValue::String(s) => {
            let mut out = String::with_capacity(s.len() + 2);
            out.push('"');
            for ch in s.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }
        JsonValue::Table(pairs) => {
            let only_array = pairs
                .iter()
                .enumerate()
                .all(|(i, (k, _))| matches!(k, JsonValue::Integer(n) if *n == i as i64 + 1));
            if only_array {
                let mut out = String::from("[");
                for (index, (_, child)) in pairs.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&encode_json(child));
                }
                out.push(']');
                return out;
            }
            let mut out = String::from("{");
            for (index, (key, child)) in pairs.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                let key_string = match key {
                    JsonValue::String(s) => s.clone(),
                    JsonValue::Integer(i) => i.to_string(),
                    _ => String::new(),
                };
                out.push_str(&encode_json(&JsonValue::String(key_string)));
                out.push(':');
                out.push_str(&encode_json(child));
            }
            out.push('}');
            out
        }
    }
}

/// Parse the compact JSON subset written by [`encode_json`].
pub fn parse_json(input: &str) -> Result<JsonValue, String> {
    let mut parser = JsonParser {
        bytes: input.as_bytes(),
        pos: 0,
        depth: 0,
    };
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err("trailing data after JSON value".to_string());
    }
    Ok(value)
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl JsonParser<'_> {
    fn parse_value(&mut self) -> Result<JsonValue, String> {
        self.depth += 1;
        if self.depth > JSON_MAX_DEPTH {
            return Err("JSON nesting too deep".to_string());
        }
        self.skip_ws();
        let byte = *self.bytes.get(self.pos).ok_or("unexpected end of JSON")?;
        let value = match byte {
            b'{' => self.parse_object()?,
            b'[' => self.parse_array()?,
            b'"' => JsonValue::String(self.parse_string()?),
            b't' => {
                self.expect_literal("true")?;
                JsonValue::Bool(true)
            }
            b'f' => {
                self.expect_literal("false")?;
                JsonValue::Bool(false)
            }
            b'n' => {
                self.expect_literal("null")?;
                JsonValue::Nil
            }
            _ => self.parse_number()?,
        };
        self.depth -= 1;
        Ok(value)
    }

    fn parse_object(&mut self) -> Result<JsonValue, String> {
        self.pos += 1;
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(JsonValue::Table(pairs));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.bytes.get(self.pos) != Some(&b':') {
                return Err("expected ':' in JSON object".to_string());
            }
            self.pos += 1;
            let value = self.parse_value()?;
            pairs.push((JsonValue::String(key), value));
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err("expected ',' or '}' in JSON object".to_string()),
            }
        }
        Ok(JsonValue::Table(pairs))
    }

    fn parse_array(&mut self) -> Result<JsonValue, String> {
        self.pos += 1;
        let mut values = Vec::new();
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(JsonValue::array(values));
        }
        loop {
            values.push(self.parse_value()?);
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err("expected ',' or ']' in JSON array".to_string()),
            }
        }
        Ok(JsonValue::array(values))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.bytes.get(self.pos) != Some(&b'"') {
            return Err("expected JSON string".to_string());
        }
        self.pos += 1;
        let mut out = String::new();
        loop {
            let byte = *self.bytes.get(self.pos).ok_or("unterminated JSON string")?;
            self.pos += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escape = *self.bytes.get(self.pos).ok_or("unterminated JSON escape")?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'u' => {
                            let hex = self
                                .bytes
                                .get(self.pos..self.pos + 4)
                                .ok_or("bad unicode escape")?;
                            let text =
                                std::str::from_utf8(hex).map_err(|_| "bad unicode escape")?;
                            let code =
                                u32::from_str_radix(text, 16).map_err(|_| "bad unicode escape")?;
                            self.pos += 4;
                            let ch = char::from_u32(code).ok_or("bad unicode scalar")?;
                            out.push(ch);
                        }
                        _ => return Err("unknown JSON escape".to_string()),
                    }
                }
                b if b < 0x20 => return Err("control character in JSON string".to_string()),
                _ => {
                    let start = self.pos - 1;
                    let width = utf8_width(byte);
                    let end = start + width;
                    if end > self.bytes.len() {
                        return Err("truncated UTF-8 in JSON string".to_string());
                    }
                    let text = std::str::from_utf8(&self.bytes[start..end])
                        .map_err(|_| "invalid UTF-8 in JSON string")?;
                    out.push_str(text);
                    self.pos = end;
                }
            }
        }
        Ok(out)
    }

    fn parse_number(&mut self) -> Result<JsonValue, String> {
        let start = self.pos;
        while let Some(byte) = self.bytes.get(self.pos) {
            if byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E') {
                self.pos += 1;
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| "bad number")?;
        if text.is_empty() {
            return Err("expected JSON value".to_string());
        }
        if !text.contains(['.', 'e', 'E']) {
            if let Ok(integer) = text.parse::<i64>() {
                return Ok(JsonValue::Integer(integer));
            }
        }
        let number = text.parse::<f64>().map_err(|_| "bad number")?;
        Ok(JsonValue::Number(number))
    }

    fn expect_literal(&mut self, literal: &str) -> Result<(), String> {
        if self.bytes[self.pos..].starts_with(literal.as_bytes()) {
            self.pos += literal.len();
            Ok(())
        } else {
            Err(format!("expected JSON literal '{literal}'"))
        }
    }

    fn skip_ws(&mut self) {
        while let Some(byte) = self.bytes.get(self.pos) {
            if byte.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }
}

fn utf8_width(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

/// Capped file load shared with the store-file evidence tests.
#[must_use]
pub fn store_file_cap() -> usize {
    STORE_FILE_MAX_BYTES
}

/// Rejects `LoadError` shapes at the store boundary (fail-closed decode).
#[must_use]
pub fn map_load_error(err: &LoadError) -> StoreError {
    match err {
        LoadError::NotFound => StoreError::new(StoreErrorCode::Io, "store file not found"),
        LoadError::TooLarge { actual, limit } => StoreError::new(
            StoreErrorCode::Quota,
            format!("plugin store exceeds the file ceiling ({actual} > {limit})"),
        ),
        LoadError::Io(msg) => {
            StoreError::new(StoreErrorCode::Io, format!("store read failed: {msg}"))
        }
    }
}
