import sqlite3

import pytest
from alert_watch import Event
from alert_watch import fetch_events
from traffic_recorder import TrafficRecorder

from mitmproxy import flow
from mitmproxy.test import tflow


@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "traffic.db")
    r = TrafficRecorder(db_path=db_path)
    r.open(db_path)

    def add(host, path="/", status=200, error=None):
        f = tflow.tflow(resp=status is not None, err=bool(error))
        f.request.host = host
        f.request.path = path
        if f.response:
            f.response.status_code = status
        if error:
            f.error = flow.Error(error)
            f.response = None
        r.response(f) if not error else r.error(f)

    add("ok.example.com", "/fine", 200)
    add("api.example.com", "/boom", 500)
    add("api.example.com", "/bad-request", 404)
    add("dead.example.com", "/unreachable", None, "connection refused")
    r.close()

    conn = sqlite3.connect(db_path)
    yield conn
    conn.close()


class TestFetchEvents:
    def test_5xx_and_errors_alert_by_default(self, db):
        events, last_id = fetch_events(db, 0)
        reasons = [(e.host, e.reason) for e in events]
        assert ("api.example.com", "HTTP 500") in reasons
        assert ("dead.example.com", "connection error") in reasons
        # 200 and unwatched 4xx stay quiet
        assert not any(r[0] == "ok.example.com" for r in reasons)
        assert ("api.example.com", "HTTP 404") not in reasons
        assert last_id == 4

    def test_watched_host_4xx_alerts(self, db):
        events, _ = fetch_events(db, 0, hosts=["example.com"])
        assert any(e.path == "/bad-request" for e in events)

    def test_all_matching_reports_everything_on_watched_host(self, db):
        events, _ = fetch_events(db, 0, hosts=["api.example.com"], all_matching=True)
        paths = {e.path for e in events}
        assert {"/boom", "/bad-request"} <= paths

    def test_watched_host_matches_subdomains(self, db):
        events, _ = fetch_events(db, 0, hosts=["example.com"], all_matching=True)
        assert any(e.host == "ok.example.com" for e in events)

    def test_incremental_watermark(self, db):
        _, last_id = fetch_events(db, 0)
        events, _ = fetch_events(db, last_id)
        assert events == []


class TestEventFormat:
    def test_format(self):
        e = Event(
            7, 1757232000.0, "GET", "api.example.com", "/boom", 500, None, "HTTP 500"
        )
        line = e.format()
        assert (
            "HTTP 500" in line and "GET api.example.com/boom" in line and "#7" in line
        )

    def test_format_with_error(self):
        e = Event(
            8,
            1757232000.0,
            "GET",
            "dead.example.com",
            "/x",
            None,
            "connection refused",
            "connection error",
        )
        assert "error=connection refused" in e.format()
