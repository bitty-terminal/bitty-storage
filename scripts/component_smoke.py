#!/usr/bin/env python3
"""Packaged protocol smoke for the `storage` component (bitty#2495, #2491).

This script is the release-matrix entry point: it takes a packaged tarball,
proves that the archive carries exactly the descriptor and the executable, that
the digest matches, and that the packaged binary speaks storage protocol v1.

Usage:
    scripts/component_smoke.py --archive dist/x86_64-unknown-linux-gnu.tar.gz
    scripts/component_smoke.py --archive PATH --expect-target TRIPLE
    scripts/component_smoke.py --binary target/debug/bitty-storage

The archive form extracts into a private temporary directory, runs the
descriptor checks, and then drives the binary. The binary form skips the
archive and descriptor checks and is meant for local iteration.

Every read is bounded before allocation. The script never signals by name: it
kills only the process handle it spawned. Python 3.8+, standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import queue
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── protocol constants (mirror src/component/protocol.rs) ───────────────────

PROTOCOL_VERSION = 1
FRAME_HEADER_BYTES = 4
MAX_FRAME_BYTES = 256 * 1024
MAX_NAMESPACES = 64
MAX_NAMESPACE_NAME_BYTES = 64
MAX_KEY_BYTES = 128
MAX_VALUE_BYTES = 128 * 1024
MAX_ROWS = 4096
MAX_SNAPSHOT_BYTES = 1024 * 1024
MAX_BATCH_ROWS = 128
MAX_BATCH_BYTES = 240 * 1024
MAX_READ_ROWS = 128
MAX_READ_BYTES = 240 * 1024
MAX_COMPONENT_NAME_BYTES = 32
MAX_VERSION_BYTES = 64
MAX_ERROR_MESSAGE_BYTES = 256

TAG_HELLO = 0x01
TAG_HELLO_ACK = 0x02
TAG_OPEN_NAMESPACE = 0x10
TAG_READ_SNAPSHOT = 0x11
TAG_COMMIT_BATCH = 0x12
TAG_ROLLBACK = 0x13
TAG_SHUTDOWN = 0x3F
TAG_NAMESPACE_OPENED = 0x20
TAG_SNAPSHOT_CHUNK = 0x21
TAG_COMMITTED = 0x22
TAG_ROLLED_BACK = 0x23
TAG_ERROR = 0x2F
TAG_SHUTDOWN_ACK = 0x3E

COMPONENT_NAME = "storage"
COMPONENT_EXECUTABLE = "bitty-storage"
WINDOWS_EXECUTABLE = "bitty-storage.exe"
ZERO_DIGEST = "0" * 64
EXIT_OK = 0
EXIT_PROTOCOL = 3

ERROR_KINDS = {
    1: "protocol",
    2: "invalid_request",
    3: "budget",
    4: "unsupported",
    5: "unknown_namespace",
    6: "stale_revision",
    7: "locked",
    8: "corrupt_state",
    9: "io",
    10: "internal",
    11: "uncertain",
}

VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class SmokeError(RuntimeError):
    """A smoke check failed."""


# ── bounded codec ───────────────────────────────────────────────────────────


class Decoder:
    """Bounds-checked reader over one frame payload."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.pos = 0

    def take(self, length: int) -> bytes:
        end = self.pos + length
        if end > len(self.payload):
            raise SmokeError("truncated frame")
        chunk = self.payload[self.pos : end]
        self.pos = end
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "big")

    def boolean(self) -> bool:
        value = self.u8()
        if value not in (0, 1):
            raise SmokeError("invalid boolean")
        return bool(value)

    def bytes_bounded(self, limit: int) -> bytes:
        length = self.u32()
        if length > limit:
            raise SmokeError(f"byte field of {length} exceeds {limit}")
        return self.take(length)

    def str_bounded(self, limit: int) -> str:
        try:
            return self.bytes_bounded(limit).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SmokeError("invalid utf-8 field") from exc

    def request(self) -> int:
        value = self.u64()
        if value == 0:
            raise SmokeError("zero request id")
        return value

    def row(self) -> dict[str, Any]:
        return {
            "key": self.str_bounded(MAX_KEY_BYTES),
            "value": self.bytes_bounded(MAX_VALUE_BYTES),
        }

    def rows_bounded(self, count_limit: int, byte_limit: int) -> list[dict[str, Any]]:
        count = self.u32()
        if count > count_limit:
            raise SmokeError(f"row count {count} exceeds {count_limit}")
        rows = []
        total = 0
        for _ in range(count):
            row = self.row()
            total += len(row["key"]) + len(row["value"])
            if total > byte_limit:
                raise SmokeError("row bytes exceed the page bound")
            rows.append(row)
        return rows

    def finish(self) -> None:
        if self.pos != len(self.payload):
            raise SmokeError("trailing bytes after the last field")


class Encoder:
    """Bounds-checked writer for one frame payload."""

    def __init__(self) -> None:
        self.parts: list[bytes] = []

    def u8(self, value: int) -> None:
        self.parts.append(struct.pack(">B", value))

    def u16(self, value: int) -> None:
        self.parts.append(struct.pack(">H", value))

    def u32(self, value: int) -> None:
        self.parts.append(struct.pack(">I", value))

    def u64(self, value: int) -> None:
        self.parts.append(struct.pack(">Q", value))

    def boolean(self, value: bool) -> None:
        self.u8(1 if value else 0)

    def bytes_bounded(self, data: bytes, limit: int) -> None:
        if len(data) > limit:
            raise SmokeError(f"byte field of {len(data)} exceeds {limit}")
        self.u32(len(data))
        self.parts.append(data)

    def str_bounded(self, value: str, limit: int) -> None:
        self.bytes_bounded(value.encode("utf-8"), limit)

    def request(self, value: int) -> None:
        if value == 0:
            raise SmokeError("zero request id")
        self.u64(value)

    def build(self) -> bytes:
        payload = b"".join(self.parts)
        if not payload or len(payload) > MAX_FRAME_BYTES:
            raise SmokeError("payload exceeds the frame bound")
        return struct.pack(">I", len(payload)) + payload


def encode_message(message: dict[str, Any]) -> bytes:
    """Encode one client request, applying every wire bound."""

    kind = message["type"]
    enc = Encoder()
    if kind == "Hello":
        enc.u8(TAG_HELLO)
        enc.u16(message["min"])
        enc.u16(message["max"])
        enc.str_bounded(message["component"], MAX_COMPONENT_NAME_BYTES)
        enc.str_bounded(message["version"], MAX_VERSION_BYTES)
    elif kind == "OpenNamespace":
        enc.u8(TAG_OPEN_NAMESPACE)
        enc.request(message["request"])
        enc.str_bounded(message["namespace"], MAX_NAMESPACE_NAME_BYTES)
    elif kind == "ReadSnapshot":
        if message["max_rows"] > MAX_READ_ROWS:
            raise SmokeError("max_rows exceeds the page bound")
        if message["max_bytes"] > MAX_READ_BYTES:
            raise SmokeError("max_bytes exceeds the page bound")
        enc.u8(TAG_READ_SNAPSHOT)
        enc.request(message["request"])
        enc.str_bounded(message["namespace"], MAX_NAMESPACE_NAME_BYTES)
        enc.u32(message["start_row"])
        enc.u32(message["max_rows"])
        enc.u32(message["max_bytes"])
    elif kind == "CommitBatch":
        upserts = message["upserts"]
        deletes = message["deletes"]
        if len(upserts) > MAX_BATCH_ROWS or len(deletes) > MAX_BATCH_ROWS:
            raise SmokeError("batch row count exceeds the bound")
        enc.u8(TAG_COMMIT_BATCH)
        enc.request(message["request"])
        enc.str_bounded(message["namespace"], MAX_NAMESPACE_NAME_BYTES)
        enc.u64(message["expected_revision"])
        batch_bytes = 0
        enc.u32(len(upserts))
        seen: set[str] = set()
        for row in upserts:
            if row["key"] in seen:
                raise SmokeError("duplicate upsert key")
            seen.add(row["key"])
            enc.str_bounded(row["key"], MAX_KEY_BYTES)
            enc.bytes_bounded(row["value"], MAX_VALUE_BYTES)
            batch_bytes += len(row["key"]) + len(row["value"]) + 8
        enc.u32(len(deletes))
        seen.clear()
        for key in deletes:
            if key in seen:
                raise SmokeError("duplicate delete key")
            seen.add(key)
            enc.str_bounded(key, MAX_KEY_BYTES)
            batch_bytes += len(key) + 4
        if batch_bytes > MAX_BATCH_BYTES:
            raise SmokeError("batch bytes exceed the bound")
    elif kind == "Rollback":
        enc.u8(TAG_ROLLBACK)
        enc.request(message["request"])
        enc.str_bounded(message["namespace"], MAX_NAMESPACE_NAME_BYTES)
        enc.u64(message["expected_revision"])
    elif kind == "Shutdown":
        enc.u8(TAG_SHUTDOWN)
    else:  # pragma: no cover - programming error
        raise SmokeError(f"cannot encode {kind}")
    return enc.build()


def decode_message(payload: bytes) -> dict[str, Any]:
    """Decode one server frame, applying every wire bound."""

    dec = Decoder(payload)
    tag = dec.u8()
    if tag == TAG_HELLO_ACK:
        message = {
            "type": "HelloAck",
            "protocol": dec.u16(),
            "component": dec.str_bounded(MAX_COMPONENT_NAME_BYTES),
            "version": dec.str_bounded(MAX_VERSION_BYTES),
        }
    elif tag == TAG_NAMESPACE_OPENED:
        message = {
            "type": "NamespaceOpened",
            "request": dec.request(),
            "namespace": dec.str_bounded(MAX_NAMESPACE_NAME_BYTES),
            "revision": dec.u64(),
            "rows": dec.u32(),
            "bytes": dec.u64(),
        }
    elif tag == TAG_SNAPSHOT_CHUNK:
        message = {
            "type": "SnapshotChunk",
            "request": dec.request(),
            "namespace": dec.str_bounded(MAX_NAMESPACE_NAME_BYTES),
            "revision": dec.u64(),
            "start_row": dec.u32(),
            "rows": dec.rows_bounded(MAX_READ_ROWS, MAX_READ_BYTES),
            "total_rows": dec.u32(),
            "total_bytes": dec.u64(),
            "done": dec.boolean(),
        }
    elif tag == TAG_COMMITTED:
        message = {
            "type": "Committed",
            "request": dec.request(),
            "namespace": dec.str_bounded(MAX_NAMESPACE_NAME_BYTES),
            "revision": dec.u64(),
            "rows_written": dec.u32(),
            "rows_removed": dec.u32(),
            "bytes_written": dec.u64(),
            "total_rows": dec.u32(),
            "total_bytes": dec.u64(),
        }
    elif tag == TAG_ROLLED_BACK:
        message = {
            "type": "RolledBack",
            "request": dec.request(),
            "namespace": dec.str_bounded(MAX_NAMESPACE_NAME_BYTES),
            "revision": dec.u64(),
            "restored_revision": dec.u64(),
            "total_rows": dec.u32(),
            "total_bytes": dec.u64(),
        }
    elif tag == TAG_ERROR:
        request = dec.u64()
        code = dec.u8()
        message = {
            "type": "Error",
            "request": request,
            "kind_code": code,
            "kind": ERROR_KINDS.get(code, "unknown"),
            "message": dec.str_bounded(MAX_ERROR_MESSAGE_BYTES),
        }
    elif tag == TAG_SHUTDOWN_ACK:
        message = {"type": "ShutdownAck"}
    else:
        raise SmokeError(f"unknown tag 0x{tag:02x}")
    dec.finish()
    return message


# ── component process ───────────────────────────────────────────────────────


@dataclass
class Component:
    """One spawned component plus a bounded, threaded frame reader."""

    binary: Path
    root: Path
    timeout: float
    process: subprocess.Popen[bytes] = field(init=False)
    messages: queue.Queue[tuple[str, Any]] = field(init=False)
    stderr: list[bytes] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        self.messages = queue.Queue()
        self.process = subprocess.Popen(
            [str(self.binary), "--root", str(self.root)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        threading.Thread(
            target=self._read_frames,
            args=(self.process.stdout, self.messages),
            name="component-reader",
            daemon=True,
        ).start()
        threading.Thread(
            target=self._drain_stderr,
            args=(self.process.stderr,),
            name="component-stderr",
            daemon=True,
        ).start()

    @staticmethod
    def _read_frames(stream: Any, sink: queue.Queue[tuple[str, Any]]) -> None:
        try:
            while True:
                header = Component._read_exact(stream, FRAME_HEADER_BYTES)
                if header is None:
                    sink.put(("eof", None))
                    return
                (length,) = struct.unpack(">I", header)
                # Bound before allocating the payload buffer.
                if length == 0:
                    sink.put(("error", "empty frame"))
                    return
                if length > MAX_FRAME_BYTES:
                    sink.put(("error", f"frame of {length} bytes exceeds the bound"))
                    return
                payload = Component._read_exact(stream, length)
                if payload is None:
                    sink.put(("error", "truncated frame"))
                    return
                sink.put(("message", decode_message(payload)))
        except (OSError, SmokeError) as exc:
            sink.put(("error", str(exc)))

    @staticmethod
    def _read_exact(stream: Any, length: int) -> bytes | None:
        chunks = []
        remaining = length
        while remaining:
            chunk = stream.read(remaining)
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _drain_stderr(self, stream: Any) -> None:
        # Keep reading to EOF so the child can never block on a full pipe,
        # but retain only a bounded head for diagnostics.
        total = 0
        while True:
            chunk = stream.readline(4096)
            if not chunk:
                return
            if total < 16 * 1024:
                self.stderr.append(chunk)
            total += len(chunk)

    def send_raw(self, data: bytes) -> None:
        assert self.process.stdin is not None
        try:
            self.process.stdin.write(data)
            self.process.stdin.flush()
        except OSError as exc:
            raise SmokeError(f"component stdin closed: {exc}") from exc

    def send(self, message: dict[str, Any]) -> None:
        self.send_raw(encode_message(message))

    def recv(self) -> dict[str, Any]:
        try:
            kind, value = self.messages.get(timeout=self.timeout)
        except queue.Empty as exc:
            raise SmokeError("timed out waiting for a frame") from exc
        if kind == "eof":
            raise SmokeError("component closed stdout unexpectedly")
        if kind == "error":
            raise SmokeError(f"component stream error: {value}")
        return value

    def expect_type(self, expected: str) -> dict[str, Any]:
        message = self.recv()
        if message["type"] != expected:
            raise SmokeError(f"expected {expected}, got {message}")
        return message

    def handshake(self) -> dict[str, Any]:
        self.send(
            {
                "type": "Hello",
                "min": PROTOCOL_VERSION,
                "max": PROTOCOL_VERSION,
                "component": COMPONENT_NAME,
                "version": "smoke",
            }
        )
        return self.expect_type("HelloAck")

    def open_namespace(self, request: int, namespace: str) -> dict[str, Any]:
        self.send({"type": "OpenNamespace", "request": request, "namespace": namespace})
        return self.recv()

    def commit(
        self,
        request: int,
        namespace: str,
        expected_revision: int,
        upserts: list[tuple[str, bytes]],
        deletes: list[str] | None = None,
    ) -> dict[str, Any]:
        self.send(
            {
                "type": "CommitBatch",
                "request": request,
                "namespace": namespace,
                "expected_revision": expected_revision,
                "upserts": [{"key": key, "value": value} for key, value in upserts],
                "deletes": deletes or [],
            }
        )
        return self.recv()

    def read_page(
        self,
        request: int,
        namespace: str,
        start_row: int,
        max_rows: int,
        max_bytes: int,
    ) -> dict[str, Any]:
        self.send(
            {
                "type": "ReadSnapshot",
                "request": request,
                "namespace": namespace,
                "start_row": start_row,
                "max_rows": max_rows,
                "max_bytes": max_bytes,
            }
        )
        return self.recv()

    def read_all(self, namespace: str) -> tuple[int, list[dict[str, Any]]]:
        rows: list[dict[str, Any]] = []
        start = 0
        request = 2000
        while True:
            page = self.read_page(request, namespace, start, MAX_READ_ROWS, 0)
            request += 1
            if page["type"] != "SnapshotChunk":
                raise SmokeError(f"expected SnapshotChunk, got {page}")
            rows.extend(page["rows"])
            start += len(page["rows"])
            if page["done"]:
                if start != page["total_rows"]:
                    raise SmokeError("final page does not match total_rows")
                return page["revision"], rows

    def rollback(
        self, request: int, namespace: str, expected_revision: int
    ) -> dict[str, Any]:
        self.send(
            {
                "type": "Rollback",
                "request": request,
                "namespace": namespace,
                "expected_revision": expected_revision,
            }
        )
        return self.recv()

    def shutdown(self) -> None:
        self.send({"type": "Shutdown"})
        self.expect_type("ShutdownAck")
        if self.wait() != EXIT_OK:
            raise SmokeError("clean shutdown did not exit 0")

    def wait(self, timeout: float | None = None) -> int:
        try:
            return self.process.wait(timeout=timeout or self.timeout)
        except subprocess.TimeoutExpired as exc:
            self.terminate()
            raise SmokeError("component did not exit") from exc

    def terminate(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            pass
        self.close_stdin()

    def close_stdin(self) -> None:
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass

    def diagnostics(self) -> str:
        return b"".join(self.stderr).decode("utf-8", "replace").strip()


def expect_error(
    message: dict[str, Any], kind: str, request: int | None = None
) -> None:
    if message["type"] != "Error":
        raise SmokeError(f"expected Error({kind}), got {message}")
    if message["kind"] != kind:
        raise SmokeError(f"expected Error({kind}), got {message}")
    if request is not None and message["request"] != request:
        raise SmokeError(f"expected error for request {request}, got {message}")


def expect_committed(message: dict[str, Any], revision: int) -> None:
    if message["type"] != "Committed":
        raise SmokeError(f"expected Committed({revision}), got {message}")
    if message["revision"] != revision:
        raise SmokeError(f"expected revision {revision}, got {message}")


def expect_opened(message: dict[str, Any], revision: int) -> None:
    if message["type"] != "NamespaceOpened":
        raise SmokeError(f"expected NamespaceOpened({revision}), got {message}")
    if message["revision"] != revision:
        raise SmokeError(f"expected revision {revision}, got {message}")


def expect_rolled_back(message: dict[str, Any], revision: int, restored: int) -> None:
    if message["type"] != "RolledBack":
        raise SmokeError(f"expected RolledBack({revision}), got {message}")
    if (message["revision"], message["restored_revision"]) != (revision, restored):
        raise SmokeError(f"expected rollback to restore {restored}, got {message}")


def row_map(rows: list[dict[str, Any]]) -> dict[str, bytes]:
    return {row["key"]: row["value"] for row in rows}


# ── checks ──────────────────────────────────────────────────────────────────


def check_handshake(binary: Path, root: Path, timeout: float) -> None:
    component = Component(binary, root, timeout)
    try:
        ack = component.handshake()
        if ack["protocol"] != PROTOCOL_VERSION:
            raise SmokeError(f"negotiated protocol {ack['protocol']}")
        if ack["component"] != COMPONENT_NAME:
            raise SmokeError(f"component name {ack['component']}")
        if not VERSION_RE.match(ack["version"]):
            raise SmokeError(f"component version {ack['version']} is not semver")
        component.shutdown()
    finally:
        component.terminate()


def check_commit_read_rollback(binary: Path, root: Path, timeout: float) -> None:
    component = Component(binary, root, timeout)
    try:
        component.handshake()
        opened = component.open_namespace(1, "smoke")
        expect_opened(opened, 0)
        committed = component.commit(
            2,
            "smoke",
            0,
            [("alpha", b"one"), ("beta", b"two" * 2048)],
        )
        expect_committed(committed, 1)

        # Paged read: one row per page, ordered by key.
        page = component.read_page(3, "smoke", 0, 1, 0)
        if page["type"] != "SnapshotChunk":
            raise SmokeError(f"expected SnapshotChunk, got {page}")
        if [row["key"] for row in page["rows"]] != ["alpha"] or page["done"]:
            raise SmokeError(f"unexpected first page {page}")
        page = component.read_page(4, "smoke", 1, 1, 0)
        if [row["key"] for row in page["rows"]] != ["beta"] or not page["done"]:
            raise SmokeError(f"unexpected second page {page}")

        # A stale revision is typed and changes nothing.
        stale = component.commit(5, "smoke", 0, [("alpha", b"stale")])
        expect_error(stale, "stale_revision", request=5)
        revision, rows = component.read_all("smoke")
        if revision != 1 or row_map(rows) != {
            "alpha": b"one",
            "beta": b"two" * 2048,
        }:
            raise SmokeError("stale commit changed the snapshot")

        # A second commit installs revision 1 as the rollback image.
        expect_committed(component.commit(6, "smoke", 1, [("gamma", b"three")]), 2)

        # Rollback publishes revision 1 as revision 3.
        rolled = component.rollback(7, "smoke", 2)
        expect_rolled_back(rolled, 3, 1)
        revision, rows = component.read_all("smoke")
        if revision != 3 or row_map(rows) != {
            "alpha": b"one",
            "beta": b"two" * 2048,
        }:
            raise SmokeError("rollback did not restore the previous revision")

        # A second rollback toggles back to revision 2.
        rolled = component.rollback(8, "smoke", 3)
        expect_rolled_back(rolled, 4, 2)
        component.shutdown()
    finally:
        component.terminate()


def check_read_budget(binary: Path, root: Path, timeout: float) -> None:
    component = Component(binary, root, timeout)
    try:
        component.handshake()
        component.open_namespace(1, "budget")
        expect_committed(component.commit(2, "budget", 0, [("large", b"x" * 4096)]), 1)
        # One row exceeds the requested page budget: request-scoped, no
        # namespace mutation, connection stays usable.
        page = component.read_page(3, "budget", 0, 0, 1024)
        expect_error(page, "budget", request=3)
        revision, rows = component.read_all("budget")
        if revision != 1 or len(rows) != 1:
            raise SmokeError("rejected read changed the snapshot")
        component.shutdown()
    finally:
        component.terminate()


def check_oversized_batch_is_a_protocol_error(
    binary: Path, root: Path, timeout: float
) -> None:
    component = Component(binary, root, timeout)
    try:
        component.handshake()
        component.open_namespace(1, "bounds")
        # Hand-encode 129 upserts: the codec must refuse before mutation.
        enc = Encoder()
        enc.u8(TAG_COMMIT_BATCH)
        enc.request(2)
        enc.str_bounded("bounds", MAX_NAMESPACE_NAME_BYTES)
        enc.u64(0)
        enc.u32(MAX_BATCH_ROWS + 1)
        for index in range(MAX_BATCH_ROWS + 1):
            key = f"k{index:03d}"
            enc.str_bounded(key, MAX_KEY_BYTES)
            enc.bytes_bounded(b"v", MAX_VALUE_BYTES)
        enc.u32(0)
        component.send_raw(enc.build())
        expect_error(component.recv(), "protocol", request=0)
        if component.wait() != EXIT_PROTOCOL:
            raise SmokeError("a protocol violation must exit 3")
    finally:
        component.terminate()


def check_frame_failures(binary: Path, root: Path, timeout: float) -> None:
    cases = [
        ("empty", struct.pack(">I", 0)),
        ("oversized", struct.pack(">I", MAX_FRAME_BYTES + 1)),
        ("garbage", struct.pack(">I", 5) + b"\xff\x00\x00\x00\x00"),
    ]
    for name, frame in cases:
        component = Component(binary, root / name, timeout)
        try:
            component.handshake()
            component.send_raw(frame)
            expect_error(component.recv(), "protocol", request=0)
            if component.wait() != EXIT_PROTOCOL:
                raise SmokeError(f"{name} frame did not exit 3")
        finally:
            component.terminate()

    # A path-shaped namespace must fail in the codec, not reach the store.
    component = Component(binary, root / "path", timeout)
    try:
        component.handshake()
        enc = Encoder()
        enc.u8(TAG_OPEN_NAMESPACE)
        enc.request(1)
        enc.u32(len("../escape"))
        enc.parts.append(b"../escape")
        component.send_raw(enc.build())
        expect_error(component.recv(), "protocol", request=0)
        if component.wait() != EXIT_PROTOCOL:
            raise SmokeError("a path-shaped namespace did not exit 3")
    finally:
        component.terminate()


def check_handshake_denial(binary: Path, root: Path, timeout: float) -> None:
    cases = [
        ("component", (1, 1, "net", "smoke")),
        ("protocol", (2, 3, COMPONENT_NAME, "smoke")),
        ("inverted", (3, 2, COMPONENT_NAME, "smoke")),
    ]
    for name, (low, high, component, version) in cases:
        process_root = root / name
        instance = Component(binary, process_root, timeout)
        try:
            instance.send(
                {
                    "type": "Hello",
                    "min": low,
                    "max": high,
                    "component": component,
                    "version": version,
                }
            )
            expect_error(instance.recv(), "protocol", request=0)
            if instance.wait() != EXIT_PROTOCOL:
                raise SmokeError(f"{name} handshake denial did not exit 3")
        finally:
            instance.terminate()


def check_lock_contention(binary: Path, root: Path, timeout: float) -> None:
    first = Component(binary, root, timeout)
    second = Component(binary, root, timeout)
    try:
        first.handshake()
        second.handshake()
        expect_opened(first.open_namespace(1, "shared"), 0)
        expect_error(second.open_namespace(1, "shared"), "locked", request=1)
        # The first component still owns the namespace and can commit.
        expect_committed(first.commit(2, "shared", 0, [("key", b"value")]), 1)
        second.shutdown()
        first.shutdown()
    finally:
        second.terminate()
        first.terminate()

    # The lock is released by exit, so a third component can open it.
    third = Component(binary, root, timeout)
    try:
        third.handshake()
        expect_opened(third.open_namespace(1, "shared"), 1)
        revision, rows = third.read_all("shared")
        if revision != 1 or row_map(rows) != {"key": b"value"}:
            raise SmokeError("reopened namespace lost the committed row")
        third.shutdown()
    finally:
        third.terminate()


def check_crash_after_ack(binary: Path, root: Path, timeout: float) -> None:
    component = Component(binary, root, timeout)
    try:
        component.handshake()
        component.open_namespace(1, "crash")
        expect_committed(component.commit(2, "crash", 0, [("durable", b"payload")]), 1)
        component.process.kill()
        component.wait()
    finally:
        component.terminate()

    reopened = Component(binary, root, timeout)
    try:
        reopened.handshake()
        expect_opened(reopened.open_namespace(1, "crash"), 1)
        revision, rows = reopened.read_all("crash")
        if revision != 1 or row_map(rows) != {"durable": b"payload"}:
            raise SmokeError("acknowledged commit did not survive SIGKILL")
        reopened.shutdown()
    finally:
        reopened.terminate()


CHECKS = [
    ("handshake and clean shutdown", check_handshake),
    ("commit, read, rollback", check_commit_read_rollback),
    ("request-scoped read budget", check_read_budget),
    ("oversized batch is a protocol error", check_oversized_batch_is_a_protocol_error),
    ("empty, garbage, oversized, and path-shaped frames", check_frame_failures),
    ("handshake denial", check_handshake_denial),
    ("cross-process lock contention", check_lock_contention),
    ("crash after acknowledged commit", check_crash_after_ack),
]


# ── descriptor and archive ──────────────────────────────────────────────────


@dataclass
class Descriptor:
    name: str
    version: str
    protocol: tuple[int, int]
    executable: str
    sha256: str


def parse_descriptor(text: str) -> Descriptor:
    values: dict[str, str | tuple[int, int]] = {}
    in_component = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[component]":
            if in_component:
                raise SmokeError("descriptor repeats [component]")
            in_component = True
            continue
        if not in_component:
            raise SmokeError(f"descriptor line {number}: expected [component]")
        if "=" not in line:
            raise SmokeError(f"descriptor line {number}: expected key = value")
        key, value = (part.strip() for part in line.split("=", 1))
        if key in values:
            raise SmokeError(f"descriptor line {number}: duplicate {key}")
        if key == "protocol":
            match = re.fullmatch(r"\[\s*(\d+)\s*,\s*(\d+)\s*\]", value)
            if not match:
                raise SmokeError("descriptor protocol must be [min, max]")
            values[key] = (int(match.group(1)), int(match.group(2)))
        elif key in {"name", "version", "executable", "sha256"}:
            match = re.fullmatch(r'"([^"\\]*)"', value)
            if not match:
                raise SmokeError(f"descriptor {key} must be a quoted string")
            values[key] = match.group(1)
        else:
            raise SmokeError(f"descriptor line {number}: unknown key {key}")

    missing = {"name", "version", "protocol", "executable", "sha256"} - values.keys()
    if missing:
        raise SmokeError(f"descriptor is missing {sorted(missing)}")
    name = str(values["name"])
    version = str(values["version"])
    executable = str(values["executable"])
    digest = str(values["sha256"])
    protocol = values["protocol"]
    if name != COMPONENT_NAME:
        raise SmokeError(f"descriptor name {name} is not {COMPONENT_NAME}")
    if not VERSION_RE.match(version):
        raise SmokeError(f"descriptor version {version} is not strict X.Y.Z")
    if protocol != (PROTOCOL_VERSION, PROTOCOL_VERSION):
        raise SmokeError(f"descriptor protocol {protocol} is not [1, 1]")
    if executable != COMPONENT_EXECUTABLE:
        raise SmokeError(
            f"descriptor executable {executable} is not {COMPONENT_EXECUTABLE}"
        )
    if not DIGEST_RE.match(digest) or digest == ZERO_DIGEST:
        raise SmokeError("descriptor digest is not a real SHA-256")
    return Descriptor(name, version, protocol, executable, digest)


def extract_archive(archive: Path, destination: Path) -> tuple[Descriptor, Path, Path]:
    if not archive.is_file():
        raise SmokeError(f"archive is missing: {archive}")
    with tarfile.open(archive, mode="r:gz") as tar:
        members = tar.getmembers()
        names = [member.name for member in members]
        if len(members) != 2:
            raise SmokeError(f"archive must carry exactly two members, found {names}")
        if any(not member.isfile() for member in members):
            raise SmokeError(f"archive members must be regular files: {names}")
        descriptor_name = "bitty-component.toml"
        if descriptor_name not in names:
            raise SmokeError(f"archive has no {descriptor_name}: {names}")
        executable_name = next(name for name in names if name != descriptor_name)
        if executable_name not in {COMPONENT_EXECUTABLE, WINDOWS_EXECUTABLE}:
            raise SmokeError(
                f"archive executable {executable_name} is not the component"
            )
        descriptor_bytes = tar.extractfile(descriptor_name).read()  # type: ignore[union-attr]
        if len(descriptor_bytes) > 4096:
            raise SmokeError("descriptor exceeds its bound")
        executable_bytes = tar.extractfile(executable_name).read()  # type: ignore[union-attr]

    digest = hashlib.sha256(executable_bytes).hexdigest()
    descriptor = parse_descriptor(descriptor_bytes.decode("utf-8"))
    if descriptor.sha256 != digest:
        raise SmokeError(
            f"descriptor digest {descriptor.sha256} does not match the executable {digest}"
        )
    executable = destination / executable_name
    executable.write_bytes(executable_bytes)
    executable.chmod(0o755)
    descriptor_path = destination / "bitty-component.toml"
    descriptor_path.write_bytes(descriptor_bytes)
    return descriptor, executable, descriptor_path


def check_binary_version(binary: Path, expected: str | None, timeout: float) -> None:
    result = subprocess.run(
        [str(binary), "--version"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise SmokeError(
            f"--version exited {result.returncode}: {result.stderr.strip()}"
        )
    fields = result.stdout.split()
    if len(fields) != 2 or fields[0] != COMPONENT_EXECUTABLE:
        raise SmokeError(f"unexpected --version output: {result.stdout.strip()}")
    if expected is not None and fields[1] != expected:
        raise SmokeError(
            f"binary version {fields[1]} does not match descriptor {expected}"
        )


def check_manifest(
    binary: Path, descriptor: Path, descriptor_value: Descriptor, timeout: float
) -> None:
    result = subprocess.run(
        [str(binary), "--check-manifest", str(descriptor)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise SmokeError(
            f"--check-manifest exited {result.returncode}: {result.stderr.strip()}"
        )
    expected = (
        f"ok {descriptor_value.name} {descriptor_value.version} "
        f"protocol [{PROTOCOL_VERSION}, {PROTOCOL_VERSION}] {descriptor_value.executable}"
    )
    if result.stdout.strip() != expected:
        raise SmokeError(f"unexpected --check-manifest output: {result.stdout.strip()}")


# ── entry point ─────────────────────────────────────────────────────────────


def run(args: argparse.Namespace) -> int:
    timeout = args.timeout
    if timeout <= 0:
        raise SmokeError("--timeout must be positive")

    if args.archive is not None:
        if args.binary is not None:
            raise SmokeError("use either --archive or --binary, not both")
        if args.expect_target and args.archive.name != f"{args.expect_target}.tar.gz":
            raise SmokeError(
                f"archive is named {args.archive.name}, expected {args.expect_target}.tar.gz"
            )

    workdir = Path(tempfile.mkdtemp(prefix="bitty-storage-smoke-"))
    try:
        if args.archive is not None:
            descriptor, binary, descriptor_path = extract_archive(args.archive, workdir)
            print(f"ok archive {args.archive} ({descriptor.version})")
            check_manifest(binary, descriptor_path, descriptor, timeout)
            print("ok descriptor and digest")
            check_binary_version(binary, descriptor.version, timeout)
        else:
            binary = args.binary
            check_binary_version(binary, None, timeout)

        for index, (name, check) in enumerate(CHECKS):
            root = workdir / f"root-{index}"
            check(binary, root, timeout)
            print(f"ok {name}")

        print(f"PASS {len(CHECKS)} protocol checks")
        return 0
    finally:
        if args.keep:
            print(f"kept {workdir}", file=sys.stderr)
        else:
            shutil.rmtree(workdir, ignore_errors=True)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Packaged protocol smoke for the storage component.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive", type=Path, help="packaged .tar.gz to verify")
    source.add_argument("--binary", type=Path, help="already-built bitty-storage")
    parser.add_argument(
        "--expect-target",
        help="the archive basename must be <target>.tar.gz",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="per-message and per-process timeout in seconds (default: 20)",
    )
    parser.add_argument(
        "--keep", action="store_true", help="keep the temporary directory"
    )
    args = parser.parse_args(argv)

    started = time.monotonic()
    try:
        code = run(args)
    except SmokeError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    except (OSError, tarfile.TarError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started
    print(f"smoke completed in {elapsed:.1f}s")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
