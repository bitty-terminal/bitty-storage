//! Session snapshot file codec mechanics.
//!
//! Ported from the Core session save path: backslash-escaped text codec,
//! layout S-expression tokenizer/parser, versioned encode/decode, and XDG
//! path helpers. Capture, apply, restore re-derivation, whole-snapshot
//! validation-before-mutation, and generation fencing stay in Core; this
//! module implements the byte mechanics behind the Core-owned gate and
//! enforces every ceiling fail-closed on the way through.
//!
//! File shape (v2): a `bitty-session v2` magic line, a
//! `workspaces <n> active <a> mru <…>` header, then one block per
//! workspace (`workspace`, `name`, `layout`, repeated `pane` records with
//! escaped `cwd`/`scrollback` lines, `end-pane`, `end-workspace`) closed
//! by `end-session`. v1 pane records (five fields) migrate in memory to
//! the v2 shape; anything outside v1..=v2 is rejected before parsing.

use std::path::PathBuf;

use crate::ceiling::{
    MAX_SESSION_CWD_BYTES, MAX_SESSION_FILE_BYTES, MAX_SESSION_GRID_DIM, MAX_SESSION_LAYOUT_DEPTH,
    MAX_SESSION_LINE_BYTES, MAX_SESSION_LINE_TEXT_BYTES, MAX_SESSION_NAME_CHARS,
    MAX_SESSION_PANES_PER_WORKSPACE, MAX_SESSION_PANES_TOTAL,
    MAX_SESSION_SCROLLBACK_LINES_PER_PANE, MAX_SESSION_WORKSPACES, MIN_SESSION_GRID_DIM,
    SESSION_APP_DIR_NAME, SESSION_FILE_NAME, SESSION_FORMAT_VERSION, SESSION_MIN_DECODE_VERSION,
    SESSIONS_DIR_NAME,
};

/// Session magic line prefix.
const SESSION_MAGIC: &str = "bitty-session v";

/// Everything that can go wrong across session encode/decode.
///
/// All variants are content-free (kinds and counts only): `Display` output
/// is safe for stderr and must never gain a snapshot/line/cwd payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// No session file exists at the resolved path.
    NotFound,
    /// No usable state root (`XDG_STATE_HOME` / `HOME` both unusable).
    NoStateDir,
    /// File or snapshot exceeds a `MAX_SESSION_*` bound.
    TooLarge {
        /// Which bound tripped (static label, never content).
        what: &'static str,
        /// Observed size.
        actual: usize,
        /// Enforced limit.
        limit: usize,
    },
    /// File or snapshot is structurally invalid (whole file rejected).
    Corrupt(&'static str),
    /// Version mismatch (whole file rejected).
    UnsupportedVersion(u32),
    /// Filesystem failure (message only, never file contents).
    Io(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "session file not found"),
            Self::NoStateDir => write!(f, "no session state dir"),
            Self::TooLarge {
                what,
                actual,
                limit,
            } => {
                write!(f, "session {what} too large ({actual} > {limit})")
            }
            Self::Corrupt(why) => write!(f, "session file corrupt ({why})"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported session version ({v})"),
            Self::Io(msg) => write!(f, "session io error ({msg})"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<crate::atomic_io::IoError> for SessionError {
    fn from(err: crate::atomic_io::IoError) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<crate::atomic_io::LoadError> for SessionError {
    fn from(err: crate::atomic_io::LoadError) -> Self {
        match err {
            crate::atomic_io::LoadError::NotFound => Self::NotFound,
            crate::atomic_io::LoadError::TooLarge { actual, limit } => Self::TooLarge {
                what: "session file",
                actual,
                limit,
            },
            crate::atomic_io::LoadError::Io(msg) => Self::Io(msg),
        }
    }
}

/// One pane's recorded attachment: which binding backed the leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneAttachment {
    /// The leaf owned the primary grid at capture.
    Primary,
    /// The leaf owned a private pane session at capture.
    Session,
    /// Session-less leaf: persists no state by construction.
    Detached,
}

impl PaneAttachment {
    /// Canonical file token (`"primary" | "session" | "detached"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Session => "session",
            Self::Detached => "detached",
        }
    }

    /// Parses a file token; `None` on anything else (fail-closed).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "primary" => Some(Self::Primary),
            "session" => Some(Self::Session),
            "detached" => Some(Self::Detached),
            _ => None,
        }
    }
}

impl std::fmt::Display for PaneAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Content route serving a leaf. Only `Terminal` is live; a future route
/// token in a v2 file is rejected fail-closed, never defaulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneRoute {
    /// Terminal-backed leaf.
    Terminal,
}

impl PaneRoute {
    /// Canonical file token (`"terminal"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
        }
    }

    /// Parses a file token; `None` on anything else (fail-closed).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "terminal" => Some(Self::Terminal),
            _ => None,
        }
    }
}

impl std::fmt::Display for PaneRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-leaf presentation mode. Canonical lowercase tokens; anything else
/// is rejected fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PresentationMode {
    /// Normal tiled leaf.
    #[default]
    Tiled,
    /// Floating leaf.
    Floating,
    /// Full-bleed base leaf.
    Fullscreen,
    /// Scratchpad leaf.
    Scratchpad,
}

impl PresentationMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tiled => "tiled",
            Self::Floating => "floating",
            Self::Fullscreen => "fullscreen",
            Self::Scratchpad => "scratchpad",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tiled" => Some(Self::Tiled),
            "floating" => Some(Self::Floating),
            "fullscreen" => Some(Self::Fullscreen),
            "scratchpad" => Some(Self::Scratchpad),
            _ => None,
        }
    }
}

impl std::fmt::Display for PresentationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Persisted layout tree: identity plus geometry only.
#[derive(Debug, Clone, PartialEq)]
pub enum LayoutNode {
    /// One live leaf with grid geometry.
    Leaf {
        /// Runtime pane identity.
        id: u64,
        /// Grid columns (`1..=1000`).
        cols: usize,
        /// Grid rows (`1..=1000`).
        rows: usize,
    },
    /// Two-child split with a fixed ratio.
    Split {
        /// `true` for horizontal, `false` for vertical.
        horizontal: bool,
        /// Split ratio (non-finite values normalize to `0.5` on decode).
        ratio: f32,
        /// First child.
        first: Box<LayoutNode>,
        /// Second child.
        second: Box<LayoutNode>,
    },
    /// Stacked children.
    Stack(Vec<LayoutNode>),
}

impl LayoutNode {
    /// All leaf ids in tree order.
    #[must_use]
    pub fn leaf_ids(&self) -> Vec<u64> {
        let mut ids = Vec::new();
        self.collect_leaves(&mut ids);
        ids
    }

    fn collect_leaves(&self, ids: &mut Vec<u64>) {
        match self {
            Self::Leaf { id, .. } => ids.push(*id),
            Self::Split { first, second, .. } => {
                first.collect_leaves(ids);
                second.collect_leaves(ids);
            }
            Self::Stack(children) => {
                for child in children {
                    child.collect_leaves(ids);
                }
            }
        }
    }

    /// Geometry of one leaf, if present.
    #[must_use]
    pub fn find_leaf(&self, id: u64) -> Option<(usize, usize)> {
        match self {
            Self::Leaf {
                id: leaf,
                cols,
                rows,
            } if *leaf == id => Some((*cols, *rows)),
            Self::Leaf { .. } => None,
            Self::Split { first, second, .. } => {
                first.find_leaf(id).or_else(|| second.find_leaf(id))
            }
            Self::Stack(children) => children.iter().find_map(|c| c.find_leaf(id)),
        }
    }
}

/// One pane's persisted state: optional cwd plus bounded scrollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneSnapshot {
    /// Runtime pane identity (matches one layout leaf).
    pub view: u64,
    /// Captured working directory, if any.
    pub cwd: Option<String>,
    /// Newest-first bounded scrollback lines.
    pub scrollback: Vec<String>,
    /// Recorded attachment (`None` marks a v1-legacy pane pre-migration).
    pub attach: Option<PaneAttachment>,
    /// Content route.
    pub route: PaneRoute,
    /// Requested presentation mode.
    pub mode: PresentationMode,
}

/// One workspace's persisted state.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkspaceSnapshot {
    /// Workspace sequence number (unique per file).
    pub seq: u64,
    /// Workspace name (bounded chars).
    pub name: String,
    /// Persisted layout tree.
    pub layout: LayoutNode,
    /// Focused leaf, if any.
    pub focus: Option<u64>,
    /// One record per layout leaf.
    pub panes: Vec<PaneSnapshot>,
}

/// Versioned whole-session persistable.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionSnapshot {
    /// Format version (always [`SESSION_FORMAT_VERSION`] after decode).
    pub version: u32,
    /// Workspace blocks.
    pub workspaces: Vec<WorkspaceSnapshot>,
    /// Active workspace index.
    pub active: usize,
    /// Most-recently-used workspace order (head is `active`).
    pub mru: Vec<usize>,
}

// ---------------------------------------------------------------------------
// XDG path helpers (env resolved at runtime only; injected values in tests)
// ---------------------------------------------------------------------------

/// State home from injected env values.
#[must_use]
pub fn state_home_for(xdg_state_home: Option<&str>, home: Option<&str>) -> Option<PathBuf> {
    if let Some(xdg) = xdg_state_home {
        if !xdg.trim().is_empty() {
            return Some(PathBuf::from(xdg));
        }
    }
    home.filter(|h| !h.trim().is_empty())
        .map(|h| PathBuf::from(h).join(".local").join("state"))
}

/// Live-environment state home.
#[must_use]
pub fn state_home() -> Option<PathBuf> {
    state_home_for(
        std::env::var("XDG_STATE_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

/// Session directory from injected env values.
#[must_use]
pub fn session_dir_for(xdg_state_home: Option<&str>, home: Option<&str>) -> Option<PathBuf> {
    state_home_for(xdg_state_home, home)
        .map(|base| base.join(SESSION_APP_DIR_NAME).join(SESSIONS_DIR_NAME))
}

/// Live-environment session directory.
#[must_use]
pub fn session_dir() -> Option<PathBuf> {
    session_dir_for(
        std::env::var("XDG_STATE_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

/// Session file path from injected env values.
#[must_use]
pub fn session_file_for(xdg_state_home: Option<&str>, home: Option<&str>) -> Option<PathBuf> {
    session_dir_for(xdg_state_home, home).map(|dir| dir.join(SESSION_FILE_NAME))
}

/// Live-environment session file path.
#[must_use]
pub fn session_file() -> Option<PathBuf> {
    session_file_for(
        std::env::var("XDG_STATE_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

// ---------------------------------------------------------------------------
// Field escaping (backslash-only; whole-line fields may contain spaces)
// ---------------------------------------------------------------------------

/// Escapes one whole-line field (`\` → `\\`, LF → `\n`, CR → `\r`).
#[must_use]
pub fn escape_field(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out
}

/// Unescapes one whole-line field; rejects dangling/unknown escapes.
pub fn unescape_field(raw: &str) -> Result<String, SessionError> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            _ => return Err(SessionError::Corrupt("bad escape")),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Layout S-expression codec (single line per workspace)
// ---------------------------------------------------------------------------

/// Encodes a layout tree as one S-expression line.
#[must_use]
pub fn encode_layout(node: &LayoutNode) -> String {
    match node {
        LayoutNode::Leaf { id, cols, rows } => format!("(leaf {id} {cols} {rows})"),
        LayoutNode::Split {
            horizontal,
            ratio,
            first,
            second,
        } => {
            let axis = if *horizontal { "h" } else { "v" };
            format!(
                "(split {axis} {} {} {})",
                ratio.to_bits(),
                encode_layout(first),
                encode_layout(second)
            )
        }
        LayoutNode::Stack(children) => {
            let mut out = String::from("(stack");
            for child in children {
                out.push(' ');
                out.push_str(&encode_layout(child));
            }
            out.push(')');
            out
        }
    }
}

/// Tokenizes one layout line into atoms and parens.
fn tokenize_layout(line: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut start: Option<usize> = None;
    for (i, b) in line.bytes().enumerate() {
        match b {
            b'(' | b')' => {
                if let Some(s) = start.take() {
                    tokens.push(&line[s..i]);
                }
                tokens.push(&line[i..i + 1]);
            }
            b' ' | b'\t' => {
                if let Some(s) = start.take() {
                    tokens.push(&line[s..i]);
                }
            }
            _ => {
                if start.is_none() {
                    start = Some(i);
                }
            }
        }
    }
    if let Some(s) = start.take() {
        tokens.push(&line[s..]);
    }
    tokens
}

/// Recursive-descent layout parser with depth and leaf guards.
struct LayoutParser<'a> {
    tokens: Vec<&'a str>,
    pos: usize,
    leaves: usize,
}

impl<'a> LayoutParser<'a> {
    fn parse_node(&mut self, depth: usize) -> Result<LayoutNode, SessionError> {
        if depth > MAX_SESSION_LAYOUT_DEPTH {
            return Err(SessionError::Corrupt("layout too deep"));
        }
        let open = self
            .next()
            .ok_or(SessionError::Corrupt("layout truncated"))?;
        if open != "(" {
            return Err(SessionError::Corrupt("layout shape"));
        }
        let kind = self
            .next()
            .ok_or(SessionError::Corrupt("layout truncated"))?;
        let node = match kind {
            "leaf" => {
                let id: u64 = self
                    .next()
                    .and_then(|t| t.parse().ok())
                    .ok_or(SessionError::Corrupt("leaf id"))?;
                let cols: usize = self
                    .next()
                    .and_then(|t| t.parse().ok())
                    .ok_or(SessionError::Corrupt("leaf dims"))?;
                let rows: usize = self
                    .next()
                    .and_then(|t| t.parse().ok())
                    .ok_or(SessionError::Corrupt("leaf dims"))?;
                if !(MIN_SESSION_GRID_DIM..=MAX_SESSION_GRID_DIM).contains(&cols)
                    || !(MIN_SESSION_GRID_DIM..=MAX_SESSION_GRID_DIM).contains(&rows)
                {
                    return Err(SessionError::Corrupt("leaf dims range"));
                }
                self.leaves += 1;
                if self.leaves > MAX_SESSION_PANES_PER_WORKSPACE {
                    return Err(SessionError::Corrupt("too many panes"));
                }
                self.expect_close()?;
                LayoutNode::Leaf { id, cols, rows }
            }
            "split" => {
                let horizontal = match self.next() {
                    Some("h") => true,
                    Some("v") => false,
                    _ => return Err(SessionError::Corrupt("split axis")),
                };
                let bits: u32 = self
                    .next()
                    .and_then(|t| t.parse().ok())
                    .ok_or(SessionError::Corrupt("split ratio"))?;
                let ratio = f32::from_bits(bits);
                let ratio = if ratio.is_finite() { ratio } else { 0.5 };
                let first = self.parse_node(depth + 1)?;
                let second = self.parse_node(depth + 1)?;
                self.expect_close()?;
                LayoutNode::Split {
                    horizontal,
                    ratio,
                    first: Box::new(first),
                    second: Box::new(second),
                }
            }
            "stack" => {
                let mut children = Vec::new();
                loop {
                    match self.peek() {
                        None => return Err(SessionError::Corrupt("layout truncated")),
                        Some(")") => {
                            self.pos += 1;
                            break;
                        }
                        _ => {
                            if children.len() >= MAX_SESSION_PANES_PER_WORKSPACE {
                                return Err(SessionError::Corrupt("too many panes"));
                            }
                            children.push(self.parse_node(depth + 1)?);
                        }
                    }
                }
                LayoutNode::Stack(children)
            }
            _ => return Err(SessionError::Corrupt("layout node")),
        };
        Ok(node)
    }

    fn next(&mut self) -> Option<&'a str> {
        let token = self.tokens.get(self.pos).copied();
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    fn peek(&self) -> Option<&'a str> {
        self.tokens.get(self.pos).copied()
    }

    fn expect_close(&mut self) -> Result<(), SessionError> {
        match self.next() {
            Some(")") => Ok(()),
            _ => Err(SessionError::Corrupt("layout shape")),
        }
    }
}

/// Decodes one layout expression line into a tree.
pub fn decode_layout(line: &str) -> Result<LayoutNode, SessionError> {
    let mut parser = LayoutParser {
        tokens: tokenize_layout(line),
        pos: 0,
        leaves: 0,
    };
    if parser.tokens.is_empty() {
        return Err(SessionError::Corrupt("empty layout"));
    }
    let node = parser.parse_node(0)?;
    if parser.pos != parser.tokens.len() {
        return Err(SessionError::Corrupt("layout trailing"));
    }
    Ok(node)
}

// ---------------------------------------------------------------------------
// Snapshot validation (fail-closed pre-mutation; mirrors the Core gate)
// ---------------------------------------------------------------------------

/// Validates every bound without touching runtime state; content-free errors.
///
/// Core runs this same check before any mutation or restore; the decoder
/// below runs it again so no caller can bypass the ceilings by handing
/// bytes straight to decode.
pub fn validate_snapshot(snap: &SessionSnapshot) -> Result<(), SessionError> {
    if snap.version != SESSION_FORMAT_VERSION {
        return Err(SessionError::UnsupportedVersion(snap.version));
    }
    if snap.workspaces.is_empty() || snap.workspaces.len() > MAX_SESSION_WORKSPACES {
        return Err(SessionError::Corrupt("workspace count"));
    }
    if snap.active >= snap.workspaces.len() {
        return Err(SessionError::Corrupt("active workspace"));
    }
    if snap.mru.len() != snap.workspaces.len() {
        return Err(SessionError::Corrupt("mru length"));
    }
    {
        let mut seen = vec![false; snap.workspaces.len()];
        for &index in &snap.mru {
            if index >= snap.workspaces.len() || seen[index] {
                return Err(SessionError::Corrupt("mru order"));
            }
            seen[index] = true;
        }
    }
    if snap.mru.first() != Some(&snap.active) {
        return Err(SessionError::Corrupt("mru head"));
    }
    let mut total_panes = 0usize;
    let mut seqs = std::collections::BTreeSet::new();
    let mut all_views = std::collections::BTreeSet::new();
    for ws in &snap.workspaces {
        if !seqs.insert(ws.seq) {
            return Err(SessionError::Corrupt("workspace seq"));
        }
        if ws.name.chars().count() > MAX_SESSION_NAME_CHARS {
            return Err(SessionError::Corrupt("workspace name"));
        }
        let leaves = ws.layout.leaf_ids();
        if leaves.is_empty() {
            return Err(SessionError::Corrupt("empty workspace"));
        }
        for leaf in &leaves {
            if !all_views.insert(*leaf) {
                return Err(SessionError::Corrupt("duplicate pane"));
            }
        }
        if leaves.len() > MAX_SESSION_PANES_PER_WORKSPACE {
            return Err(SessionError::Corrupt("too many panes"));
        }
        if let Some(focus) = ws.focus {
            if !leaves.contains(&focus) {
                return Err(SessionError::Corrupt("focus not a leaf"));
            }
        }
        if ws.panes.len() != leaves.len() {
            return Err(SessionError::Corrupt("pane coverage"));
        }
        {
            let mut seen = std::collections::BTreeSet::new();
            for pane in &ws.panes {
                if !leaves.contains(&pane.view) || !seen.insert(pane.view) {
                    return Err(SessionError::Corrupt("pane coverage"));
                }
                if let Some(cwd) = &pane.cwd {
                    if cwd.len() > MAX_SESSION_CWD_BYTES {
                        return Err(SessionError::Corrupt("cwd bound"));
                    }
                }
                if pane.scrollback.len() > MAX_SESSION_SCROLLBACK_LINES_PER_PANE {
                    return Err(SessionError::Corrupt("scrollback bound"));
                }
                for line in &pane.scrollback {
                    if line.len() > MAX_SESSION_LINE_TEXT_BYTES {
                        return Err(SessionError::Corrupt("scrollback line bound"));
                    }
                }
                if pane.attach == Some(PaneAttachment::Detached)
                    && (pane.cwd.is_some() || !pane.scrollback.is_empty())
                {
                    return Err(SessionError::Corrupt("detached pane state"));
                }
            }
        }
        total_panes += ws.panes.len();
        if total_panes > MAX_SESSION_PANES_TOTAL {
            return Err(SessionError::Corrupt("too many panes"));
        }
    }
    let primaries = snap
        .workspaces
        .iter()
        .flat_map(|ws| ws.panes.iter())
        .filter(|pane| pane.attach == Some(PaneAttachment::Primary))
        .count();
    if primaries > 1 {
        return Err(SessionError::Corrupt("duplicate primary"));
    }
    Ok(())
}

/// Startup-owner derivation shared by v1 migration and legacy (`None`)
/// attachments: the active workspace's focused leaf, else its first leaf.
fn derive_startup_owner(snap: &SessionSnapshot) -> u64 {
    let ws = &snap.workspaces[snap.active];
    ws.focus
        .filter(|focus| ws.layout.leaf_ids().contains(focus))
        .unwrap_or_else(|| ws.layout.leaf_ids()[0])
}

/// Resolves one pane's recorded attachment for encode.
fn resolve_attachment(attach: Option<PaneAttachment>, view: u64, owner: u64) -> PaneAttachment {
    attach.unwrap_or(if view == owner {
        PaneAttachment::Primary
    } else {
        PaneAttachment::Session
    })
}

// ---------------------------------------------------------------------------
// Text codec (pure, bounded, content-free errors)
// ---------------------------------------------------------------------------

/// Encodes a validated snapshot to file bytes (fails closed before I/O).
///
/// # Errors
///
/// Rejects the whole snapshot when any ceiling trips, including escaped
/// whole-line fields that would exceed the decode line cap.
pub fn encode_session(snap: &SessionSnapshot) -> Result<Vec<u8>, SessionError> {
    validate_snapshot(snap)?;
    let owner = derive_startup_owner(snap);
    let mut out = String::new();
    out.push_str(SESSION_MAGIC);
    out.push_str(&SESSION_FORMAT_VERSION.to_string());
    out.push('\n');
    let mru = snap
        .mru
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    out.push_str(&format!(
        "workspaces {} active {} mru {mru}\n",
        snap.workspaces.len(),
        snap.active
    ));
    for ws in &snap.workspaces {
        let focus = ws
            .focus
            .map_or_else(|| "none".to_string(), |id| id.to_string());
        out.push_str(&format!("workspace {} {focus}\n", ws.seq));
        out.push_str(&format!("name {}\n", escape_field(&ws.name)));
        out.push_str(&format!("layout {}\n", encode_layout(&ws.layout)));
        for pane in &ws.panes {
            let (cols, rows) = ws
                .layout
                .find_leaf(pane.view)
                .ok_or(SessionError::Corrupt("pane coverage"))?;
            let cwd_flag = u8::from(pane.cwd.is_some());
            let attach = resolve_attachment(pane.attach, pane.view, owner);
            out.push_str(&format!(
                "pane {} {cols} {rows} {} {cwd_flag} {attach} {} {}\n",
                pane.view,
                pane.scrollback.len(),
                pane.route,
                pane.mode,
            ));
            if let Some(cwd) = &pane.cwd {
                out.push_str(&escape_field(cwd));
                out.push('\n');
            }
            for line in &pane.scrollback {
                out.push_str(&escape_field(line));
                out.push('\n');
            }
            out.push_str("end-pane\n");
        }
        out.push_str("end-workspace\n");
    }
    out.push_str("end-session\n");
    // Self-compatibility: escaped whole-line fields can exceed the decode
    // line cap while the raw text stays within its own bound. Reject here,
    // fail-closed before any I/O, so accepted output always decodes.
    for line in out.split('\n') {
        if line.len() > MAX_SESSION_LINE_BYTES {
            return Err(SessionError::TooLarge {
                what: "session line",
                actual: line.len(),
                limit: MAX_SESSION_LINE_BYTES,
            });
        }
    }
    let bytes = out.into_bytes();
    if bytes.len() > MAX_SESSION_FILE_BYTES {
        return Err(SessionError::TooLarge {
            what: "session file",
            actual: bytes.len(),
            limit: MAX_SESSION_FILE_BYTES,
        });
    }
    Ok(bytes)
}

/// Cursor parser over session-file lines (content-free errors throughout).
struct SessionParser<'a> {
    lines: Vec<&'a str>,
    pos: usize,
}

impl<'a> SessionParser<'a> {
    fn next(&mut self) -> Result<&'a str, SessionError> {
        let line = self
            .lines
            .get(self.pos)
            .copied()
            .ok_or(SessionError::Corrupt("truncated"))?;
        self.pos += 1;
        Ok(line)
    }

    fn expect(&mut self, marker: &'static str) -> Result<(), SessionError> {
        match self.next()? {
            line if line == marker => Ok(()),
            _ => Err(SessionError::Corrupt("marker")),
        }
    }
}

/// Decodes file bytes to a snapshot; any violation rejects the whole file.
///
/// v1 files migrate in memory (unspecified attachment, terminal route,
/// tiled mode); the returned snapshot always carries
/// [`SESSION_FORMAT_VERSION`].
///
/// # Errors
///
/// `TooLarge` on over-cap input, `UnsupportedVersion` outside
/// v1..=v2, `Corrupt` on any structural violation.
pub fn decode_session(bytes: &[u8]) -> Result<SessionSnapshot, SessionError> {
    if bytes.len() > MAX_SESSION_FILE_BYTES {
        return Err(SessionError::TooLarge {
            what: "session file",
            actual: bytes.len(),
            limit: MAX_SESSION_FILE_BYTES,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| SessionError::Corrupt("utf-8"))?;
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    for line in &lines {
        if line.len() > MAX_SESSION_LINE_BYTES {
            return Err(SessionError::TooLarge {
                what: "session line",
                actual: line.len(),
                limit: MAX_SESSION_LINE_BYTES,
            });
        }
    }
    let mut parser = SessionParser { lines, pos: 0 };
    let magic = parser.next()?;
    let version: u32 = magic
        .strip_prefix(SESSION_MAGIC)
        .and_then(|v| v.parse().ok())
        .ok_or(SessionError::Corrupt("magic"))?;
    if !(SESSION_MIN_DECODE_VERSION..=SESSION_FORMAT_VERSION).contains(&version) {
        return Err(SessionError::UnsupportedVersion(version));
    }
    let header = parser.next()?;
    let (count, active, mru) = parse_workspaces_header(header)?;
    if count == 0 || count > MAX_SESSION_WORKSPACES {
        return Err(SessionError::Corrupt("workspace count"));
    }
    let mut workspaces = Vec::with_capacity(count);
    let mut total_panes = 0usize;
    for _ in 0..count {
        let ws = parse_workspace(&mut parser, &mut total_panes, version)?;
        workspaces.push(ws);
    }
    parser.expect("end-session")?;
    if parser.pos != parser.lines.len() {
        return Err(SessionError::Corrupt("trailing"));
    }
    // Migration normalizes here: downstream only ever sees the current
    // model version.
    let snap = SessionSnapshot {
        version: SESSION_FORMAT_VERSION,
        workspaces,
        active,
        mru,
    };
    validate_snapshot(&snap)?;
    Ok(snap)
}

/// Parses `workspaces <n> active <a> mru <m0,m1,...>`.
fn parse_workspaces_header(line: &str) -> Result<(usize, usize, Vec<usize>), SessionError> {
    let rest = line
        .strip_prefix("workspaces ")
        .ok_or(SessionError::Corrupt("header"))?;
    let (count_raw, rest) = rest
        .split_once(" active ")
        .ok_or(SessionError::Corrupt("header"))?;
    let (active_raw, mru_raw) = rest
        .split_once(" mru ")
        .ok_or(SessionError::Corrupt("header"))?;
    let count: usize = count_raw
        .parse()
        .map_err(|_| SessionError::Corrupt("header"))?;
    let active: usize = active_raw
        .parse()
        .map_err(|_| SessionError::Corrupt("header"))?;
    if mru_raw.is_empty() {
        return Err(SessionError::Corrupt("mru order"));
    }
    let mut mru = Vec::new();
    for part in mru_raw.split(',') {
        mru.push(
            part.parse()
                .map_err(|_| SessionError::Corrupt("mru order"))?,
        );
    }
    Ok((count, active, mru))
}

/// Parses one `workspace ... end-workspace` block.
fn parse_workspace(
    parser: &mut SessionParser<'_>,
    total_panes: &mut usize,
    version: u32,
) -> Result<WorkspaceSnapshot, SessionError> {
    let head = parser.next()?;
    let head = head
        .strip_prefix("workspace ")
        .ok_or(SessionError::Corrupt("workspace"))?;
    let (seq_raw, focus_raw) = head
        .split_once(' ')
        .ok_or(SessionError::Corrupt("workspace"))?;
    let seq: u64 = seq_raw
        .parse()
        .map_err(|_| SessionError::Corrupt("workspace seq"))?;
    let focus = match focus_raw {
        "none" => None,
        raw => Some(raw.parse().map_err(|_| SessionError::Corrupt("focus"))?),
    };
    let name_line = parser.next()?;
    let name = unescape_field(
        name_line
            .strip_prefix("name ")
            .ok_or(SessionError::Corrupt("name"))?,
    )?;
    let layout_line = parser.next()?;
    let layout = decode_layout(
        layout_line
            .strip_prefix("layout ")
            .ok_or(SessionError::Corrupt("layout"))?,
    )?;
    let leaves = layout.leaf_ids();
    let mut panes = Vec::new();
    loop {
        let line = parser.next()?;
        if line == "end-workspace" {
            break;
        }
        let pane = parse_pane(parser, line, &layout, version)?;
        panes.push(pane);
        *total_panes += 1;
        if *total_panes > MAX_SESSION_PANES_TOTAL {
            return Err(SessionError::Corrupt("too many panes"));
        }
    }
    if panes.len() != leaves.len() {
        return Err(SessionError::Corrupt("pane coverage"));
    }
    Ok(WorkspaceSnapshot {
        seq,
        name,
        layout,
        focus,
        panes,
    })
}

/// Parses one `pane ... end-pane` block; `head` is the already-read header.
///
/// v1 headers carry five fields and migrate with an unspecified
/// attachment, the terminal route, and a tiled mode. v2 headers append
/// `<attach> <route> <mode>`; the token count is exact per version.
fn parse_pane(
    parser: &mut SessionParser<'_>,
    head: &str,
    layout: &LayoutNode,
    version: u32,
) -> Result<PaneSnapshot, SessionError> {
    let head = head
        .strip_prefix("pane ")
        .ok_or(SessionError::Corrupt("pane"))?;
    let parts: Vec<&str> = head.split(' ').collect();
    let (id_raw, cols_raw, rows_raw, count_raw, cwd_raw, attach, route, mode) = match version {
        1 => {
            let [id_raw, cols_raw, rows_raw, count_raw, cwd_raw] = parts.as_slice() else {
                return Err(SessionError::Corrupt("pane"));
            };
            (
                *id_raw,
                *cols_raw,
                *rows_raw,
                *count_raw,
                *cwd_raw,
                None,
                PaneRoute::Terminal,
                PresentationMode::Tiled,
            )
        }
        _ => {
            let [
                id_raw,
                cols_raw,
                rows_raw,
                count_raw,
                cwd_raw,
                attach_raw,
                route_raw,
                mode_raw,
            ] = parts.as_slice()
            else {
                return Err(SessionError::Corrupt("pane"));
            };
            (
                *id_raw,
                *cols_raw,
                *rows_raw,
                *count_raw,
                *cwd_raw,
                Some(PaneAttachment::parse(attach_raw).ok_or(SessionError::Corrupt("attach"))?),
                PaneRoute::parse(route_raw).ok_or(SessionError::Corrupt("route"))?,
                PresentationMode::parse(mode_raw).ok_or(SessionError::Corrupt("mode"))?,
            )
        }
    };
    let id: u64 = id_raw
        .parse()
        .map_err(|_| SessionError::Corrupt("pane id"))?;
    let cols: usize = cols_raw
        .parse()
        .map_err(|_| SessionError::Corrupt("pane dims"))?;
    let rows: usize = rows_raw
        .parse()
        .map_err(|_| SessionError::Corrupt("pane dims"))?;
    if !(MIN_SESSION_GRID_DIM..=MAX_SESSION_GRID_DIM).contains(&cols)
        || !(MIN_SESSION_GRID_DIM..=MAX_SESSION_GRID_DIM).contains(&rows)
    {
        return Err(SessionError::Corrupt("pane dims range"));
    }
    let view = id;
    let (leaf_cols, leaf_rows) = layout
        .find_leaf(view)
        .ok_or(SessionError::Corrupt("pane coverage"))?;
    if leaf_cols != cols || leaf_rows != rows {
        return Err(SessionError::Corrupt("pane dims mismatch"));
    }
    let count: usize = count_raw
        .parse()
        .map_err(|_| SessionError::Corrupt("pane lines"))?;
    if count > MAX_SESSION_SCROLLBACK_LINES_PER_PANE {
        return Err(SessionError::Corrupt("scrollback bound"));
    }
    let cwd = match cwd_raw {
        "0" => None,
        "1" => {
            let raw = parser.next()?;
            let decoded = unescape_field(raw)?;
            if decoded.len() > MAX_SESSION_CWD_BYTES {
                return Err(SessionError::Corrupt("cwd bound"));
            }
            Some(decoded)
        }
        _ => return Err(SessionError::Corrupt("pane")),
    };
    let mut scrollback = Vec::with_capacity(count);
    for _ in 0..count {
        let raw = parser.next()?;
        let decoded = unescape_field(raw)?;
        if decoded.len() > MAX_SESSION_LINE_TEXT_BYTES {
            return Err(SessionError::Corrupt("scrollback line bound"));
        }
        scrollback.push(decoded);
    }
    parser.expect("end-pane")?;
    Ok(PaneSnapshot {
        view,
        cwd,
        scrollback,
        attach,
        route,
        mode,
    })
}
