import time

import pytest
from mcp_server import block_domain
from mcp_server import clear_flows
from mcp_server import discover_token
from mcp_server import domain_stats
from mcp_server import get_flow
from mcp_server import list_blocked
from mcp_server import list_flows
from mcp_server import load_config
from mcp_server import search_flows
from mcp_server import unblock_domain
from traffic_recorder import TrafficRecorder

from mitmproxy.test import tflow


@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "traffic.db")
    r = TrafficRecorder(db_path=db_path)
    r.open(db_path)

    def add(
        host="api.example.com",
        path="/v1/users",
        status=200,
        body='{"ok": true}',
        age=10,
    ):
        f = tflow.tflow(resp=True)
        f.request.host = host
        f.request.path = path
        f.request.timestamp_start = time.time() - age
        f.response.status_code = status
        f.response.headers["content-type"] = "application/json"
        f.response.content = body.encode()
        r.response(f)

    add()
    add(host="static.example.com", path="/app.js", status=200)
    add(host="api.other.org", path="/health", status=503, body="down")
    r.close()
    return db_path


class TestListFlows:
    def test_all(self, db):
        rows = list_flows(db)
        assert len(rows) == 3
        assert "req_body" not in rows[0]  # bodies excluded from listings

    def test_host_filter_matches_subdomains(self, db):
        rows = list_flows(db, host="example.com")
        assert {r["host"] for r in rows} == {"api.example.com", "static.example.com"}

    def test_status_filter(self, db):
        rows = list_flows(db, status=503)
        assert len(rows) == 1
        assert rows[0]["host"] == "api.other.org"

    def test_since_filter(self, db):
        assert list_flows(db, since_seconds=5) == []
        assert len(list_flows(db, since_seconds=60)) == 3


class TestGetFlow:
    def test_without_body(self, db):
        flow_id = list_flows(db)[0]["id"]
        f = get_flow(db, flow_id)
        assert f["resp_body"].startswith("<")
        assert f["req_headers"]

    def test_with_body(self, db):
        flow_id = list_flows(db, host="api.example.com")[0]["id"]
        f = get_flow(db, flow_id, include_body=True)
        assert f["resp_body"] == '{"ok": true}'

    def test_missing(self, db):
        assert get_flow(db, 9999) is None


class TestDomainStats:
    def test_aggregates(self, db):
        stats = {s["host"]: s for s in domain_stats(db)}
        assert stats["api.example.com"]["requests"] == 1
        assert stats["api.other.org"]["errors_5xx"] == 1
        assert stats["static.example.com"]["errors_4xx"] == 0


class TestSearchFlows:
    def test_path_match(self, db):
        rows = search_flows(db, "health")
        assert len(rows) == 1
        assert rows[0]["host"] == "api.other.org"

    def test_body_match(self, db):
        assert len(search_flows(db, '"ok"')) == 2

    def test_no_match(self, db):
        assert search_flows(db, "nonexistent-token") == []


class TestClearFlows:
    def test_clear_all(self, db):
        result = clear_flows(db)
        assert result["deleted"] == 3
        assert list_flows(db, since_seconds=999999) == []

    def test_clear_by_host_includes_subdomains(self, db):
        result = clear_flows(db, host="example.com")
        assert result["deleted"] == 2
        remaining = list_flows(db, since_seconds=999999)
        assert [r["host"] for r in remaining] == ["api.other.org"]

    def test_clear_by_age(self, db):
        # Fixture flows are all ~10s old; nothing older than an hour.
        assert clear_flows(db, older_than_seconds=3600)["deleted"] == 0
        assert clear_flows(db, older_than_seconds=0)["deleted"] == 3

    def test_clear_empty_db(self, db):
        clear_flows(db)
        assert clear_flows(db)["deleted"] == 0


class TestBlocklist:
    @pytest.fixture
    def config(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("ignore_hosts:\n  - example.org\n")
        return str(cfg)

    def test_block_and_list(self, config):
        result = block_domain(config, "ads.example.com")
        assert result["added"] is True
        assert result["entry"] == "/~d '(^|[.])ads[.]example[.]com$'/403"
        assert "config file" in result["persisted"]

        rows = list_blocked(config)
        assert rows == [{"domain": "ads.example.com", "status": 403}]

    def test_entry_is_valid_and_matches(self, config):
        # The generated entry must parse as a mitmproxy filter and match the
        # domain plus subdomains (but not suffix lookalikes).
        from mitmproxy import flowfilter
        from mitmproxy.test import tflow

        block_domain(config, "example.com")
        entry = load_config(config)["block_list"][0]
        spec = entry[1 : entry.rindex("/")]  # strip separators and status
        pf = flowfilter.parse(spec)
        assert pf is not None
        for host, expected in [
            ("example.com", True),
            ("api.example.com", True),
            ("notexample.com", False),
            ("other.org", False),
        ]:
            f = tflow.tflow()
            f.request.host = host
            assert bool(pf(f)) is expected, host

    def test_block_persists_to_config_file(self, config):
        block_domain(config, "a.com")
        # A fresh read (no mitmweb) sees the entry, other keys untouched.
        assert list_blocked(config) == [{"domain": "a.com", "status": 403}]
        assert "ignore_hosts" in open(config).read()

    def test_custom_status(self, config):
        block_domain(config, "a.com", status=444)
        assert list_blocked(config) == [{"domain": "a.com", "status": 444}]

    def test_block_is_idempotent(self, config):
        assert block_domain(config, "a.com")["added"] is True
        assert block_domain(config, "a.com")["added"] is False
        assert len(list_blocked(config)) == 1

    def test_normalizes_input(self, config):
        assert (
            block_domain(config, "https://API.Example.com:8443/v1?x=1")["domain"]
            == "api.example.com"
        )
        assert block_domain(config, "*.static.example.com")["domain"] == (
            "static.example.com"
        )

    def test_rejects_empty_domain(self, config):
        with pytest.raises(ValueError):
            block_domain(config, "  ")

    def test_unblock(self, config):
        block_domain(config, "a.com")
        block_domain(config, "b.com")
        assert unblock_domain(config, "a.com")["removed"] is True
        assert unblock_domain(config, "a.com")["removed"] is False
        assert list_blocked(config) == [{"domain": "b.com", "status": 403}]

    def test_unblock_last_entry_removes_key(self, config):
        block_domain(config, "a.com")
        unblock_domain(config, "a.com")
        assert "block_list" not in open(config).read()
        assert "ignore_hosts" in open(config).read()

    def test_unblock_normalizes_input(self, config):
        block_domain(config, "a.com")
        assert unblock_domain(config, "HTTPS://A.com/")["removed"] is True

    def test_handwritten_entries_are_preserved(self, config):
        with open(config, "a") as f:
            f.write("block_list:\n  - '/~u some-regex/404'\n")
        block_domain(config, "a.com")
        assert list_blocked(config) == [
            {"raw": "/~u some-regex/404"},
            {"domain": "a.com", "status": 403},
        ]
        unblock_domain(config, "a.com")
        assert list_blocked(config) == [{"raw": "/~u some-regex/404"}]

    def test_list_on_missing_config(self, tmp_path):
        assert list_blocked(str(tmp_path / "missing.yaml")) == []

    def test_discover_token_prefers_web_password(self):
        assert discover_token({"web_password": "abc123"}, "/nonexistent") == "abc123"
        assert discover_token({"web_password": "$argon2..."}, "/nonexistent") is None
        assert discover_token({}, "/nonexistent") is None


class TestCaptureGuide:
    def test_guide_covers_wireguard_and_endpoint_fix(self):
        from mcp_server import CAPTURE_GUIDE

        assert "--wireguard" in CAPTURE_GUIDE
        assert "--mode regular --mode wireguard" in CAPTURE_GUIDE
        assert "Endpoint" in CAPTURE_GUIDE and "51820" in CAPTURE_GUIDE
        assert "mitm.it" in CAPTURE_GUIDE
