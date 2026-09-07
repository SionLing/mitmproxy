"""
mitmproxy addon: record every HTTP flow into a local SQLite database,
so that Claude Code (or any other tool) can query traffic with SQL.

Usage:
    uv run mitmdump -s recorder/traffic_recorder.py
    uv run mitmdump -s recorder/traffic_recorder.py --set traffic_db=/path/to/traffic.db

Query side (read-only, WAL mode allows concurrent reads while mitmdump writes):
    sqlite3 recorder/traffic.db "SELECT host, path, status FROM flows ORDER BY id DESC LIMIT 10"
"""

import json
import sqlite3
import threading
import time
from pathlib import Path

from mitmproxy import ctx
from mitmproxy import http

MAX_BODY_BYTES = 256 * 1024
"""Bodies larger than this are truncated (a marker is appended)."""

RETENTION_SECONDS = 7 * 24 * 3600
"""Records older than this are deleted on startup."""

TEXTUAL_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-javascript",
    "application/x-www-form-urlencoded",
    "application/graphql",
    "application/yaml",
    "application/problem+json",
    "image/svg+xml",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            REAL NOT NULL,
  duration_ms   INTEGER,
  method        TEXT,
  scheme        TEXT,
  host          TEXT NOT NULL,
  port          INTEGER,
  path          TEXT,
  status        INTEGER,
  req_headers   TEXT,
  resp_headers  TEXT,
  req_body      TEXT,
  resp_body     TEXT,
  req_size      INTEGER,
  resp_size     INTEGER,
  error         TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_host_ts ON flows(host, ts);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts);
"""

TRUNCATED_MARKER = "\n...[truncated by traffic_recorder]"


def is_textual(content_type: str) -> bool:
    content_type = content_type.lower().split(";")[0].strip()
    return any(content_type.startswith(t) for t in TEXTUAL_CONTENT_TYPES)


def extract_body(content: bytes | None, content_type: str) -> str | None:
    """Return a text representation of a message body, or None for binary/empty."""
    if not content:
        return None
    if not is_textual(content_type):
        return None
    text = content.decode("utf-8", errors="replace")
    if len(text) > MAX_BODY_BYTES:
        text = text[:MAX_BODY_BYTES] + TRUNCATED_MARKER
    return text


def flow_to_row(flow: http.HTTPFlow) -> tuple:
    req = flow.request
    resp = flow.response
    error = flow.error.msg if flow.error else None

    duration_ms = None
    if resp and req.timestamp_start and resp.timestamp_end:
        duration_ms = int((resp.timestamp_end - req.timestamp_start) * 1000)

    return (
        req.timestamp_start or time.time(),
        duration_ms,
        req.method,
        req.scheme,
        req.host,
        req.port,
        req.path,
        resp.status_code if resp else None,
        json.dumps(dict(req.headers), ensure_ascii=False),
        json.dumps(dict(resp.headers), ensure_ascii=False) if resp else None,
        extract_body(req.content, req.headers.get("content-type", "")),
        extract_body(resp.content, resp.headers.get("content-type", ""))
        if resp
        else None,
        len(req.content) if req.content is not None else None,
        len(resp.content) if resp and resp.content is not None else None,
        error,
    )


class TrafficRecorder:
    def __init__(self, db_path: str | None = None):
        # db_path is injectable for tests; normally comes from the traffic_db option.
        self._db_path_override = db_path
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    def load(self, loader):
        loader.add_option(
            name="traffic_db",
            typespec=str,
            default=str(Path(__file__).parent / "traffic.db"),
            help="Path to the SQLite database used by traffic_recorder.",
        )

    def running(self):
        self.open(self._db_path_override or ctx.options.traffic_db)

    def open(self, db_path: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            self._conn.execute(
                "DELETE FROM flows WHERE ts < ?", (time.time() - RETENTION_SECONDS,)
            )
            self._conn.commit()

    def close(self):
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    def done(self):
        self.close()

    def _insert(self, flow: http.HTTPFlow):
        if self._conn is None:
            return
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO flows (
                  ts, duration_ms, method, scheme, host, port, path, status,
                  req_headers, resp_headers, req_body, resp_body,
                  req_size, resp_size, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                flow_to_row(flow),
            )
            self._conn.commit()

    def response(self, flow: http.HTTPFlow):
        self._insert(flow)

    def error(self, flow: http.HTTPFlow):
        # Flows that failed (DNS, TCP reset, TLS errors, ...) never reach `response`.
        if flow.response is None:
            self._insert(flow)


addons = [TrafficRecorder()]
