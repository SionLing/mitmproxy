import json
import sqlite3
import time

import pytest
from traffic_recorder import extract_body
from traffic_recorder import is_textual
from traffic_recorder import MAX_BODY_BYTES
from traffic_recorder import RETENTION_SECONDS
from traffic_recorder import TrafficRecorder
from traffic_recorder import TRUNCATED_MARKER

from mitmproxy import flow
from mitmproxy.test import tflow


@pytest.fixture
def recorder(tmp_path):
    r = TrafficRecorder(db_path=str(tmp_path / "traffic.db"))
    r.open(r._db_path_override)
    yield r
    r.close()


def query_all(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM flows").fetchall()
    finally:
        conn.close()


class TestExtractBody:
    def test_textual(self):
        assert extract_body(b'{"a": 1}', "application/json") == '{"a": 1}'

    def test_binary_skipped(self):
        assert extract_body(b"\x89PNG...", "image/png") is None

    def test_empty(self):
        assert extract_body(b"", "application/json") is None
        assert extract_body(None, "application/json") is None

    def test_truncation(self):
        big = "x" * (MAX_BODY_BYTES + 100)
        out = extract_body(big.encode(), "text/plain")
        assert out.endswith(TRUNCATED_MARKER)
        assert len(out) == MAX_BODY_BYTES + len(TRUNCATED_MARKER)

    def test_charset_parameter(self):
        assert is_textual("application/json; charset=utf-8")
        assert is_textual("text/html; charset=UTF-8")
        assert not is_textual("image/png")


class TestRecorder:
    def test_records_response(self, recorder, tmp_path):
        f = tflow.tflow(resp=True)
        f.request.headers["content-type"] = "application/json"
        f.request.content = b'{"q": 1}'
        f.response.headers["content-type"] = "application/json"
        f.response.content = b'{"ok": true}'
        recorder.response(f)

        rows = query_all(tmp_path / "traffic.db")
        assert len(rows) == 1
        row = rows[0]
        assert row["host"] == f.request.host
        assert row["method"] == "GET"
        assert row["status"] == 200
        assert row["req_body"] == '{"q": 1}'
        assert row["resp_body"] == '{"ok": true}'
        assert json.loads(row["req_headers"])["content-type"] == "application/json"
        assert row["error"] is None
        assert row["duration_ms"] is not None and row["duration_ms"] >= 0

    def test_records_error_flow(self, recorder, tmp_path):
        f = tflow.tflow(err=flow.Error("connection killed"))
        recorder.error(f)

        rows = query_all(tmp_path / "traffic.db")
        assert len(rows) == 1
        assert rows[0]["status"] is None
        assert rows[0]["error"] == "connection killed"

    def test_error_hook_ignores_flows_with_response(self, recorder, tmp_path):
        f = tflow.tflow(resp=True, err=flow.Error("late error"))
        recorder.error(f)
        assert query_all(tmp_path / "traffic.db") == []

    def test_binary_body_stores_size_only(self, recorder, tmp_path):
        f = tflow.tflow(resp=True)
        f.response.headers["content-type"] = "image/png"
        f.response.content = b"\x89PNG" * 10
        recorder.response(f)

        row = query_all(tmp_path / "traffic.db")[0]
        assert row["resp_body"] is None
        assert row["resp_size"] == 40

    def test_retention_cleanup(self, tmp_path):
        db = str(tmp_path / "traffic.db")
        r1 = TrafficRecorder(db_path=db)
        r1.open(db)
        f = tflow.tflow(resp=True)
        r1.response(f)
        # Age the record beyond the retention window.
        with r1._lock:
            r1._conn.execute(
                "UPDATE flows SET ts = ?", (time.time() - RETENTION_SECONDS - 60,)
            )
            r1._conn.commit()
        r1.close()

        # Reopening (i.e. addon restart) must drop the stale record.
        r2 = TrafficRecorder(db_path=db)
        r2.open(db)
        assert query_all(db) == []
        r2.close()

    def test_wal_mode_allows_concurrent_read(self, recorder, tmp_path):
        f = tflow.tflow(resp=True)
        recorder.response(f)
        # A second connection reads while the writer connection stays open.
        rows = query_all(tmp_path / "traffic.db")
        assert len(rows) == 1

    def test_insert_before_open_is_noop(self):
        r = TrafficRecorder(db_path="/nonexistent-dir/should-not-be-created.db")
        r.response(tflow.tflow(resp=True))  # must not raise
