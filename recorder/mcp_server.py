# /// script
# requires-python = ">=3.12"
# dependencies = ["mcp>=1.2"]
# ///
"""
MCP server exposing the traffic.db recorded by traffic_recorder.py to Claude Code.

Run standalone (stdio transport):
    uv run --script recorder/mcp_server.py

Register with Claude Code (project scope):
    claude mcp add traffic-recorder -- uv run --script \\
        /Users/sion/projects/mitmproxy/recorder/mcp_server.py

Configuration via environment:
    TRAFFIC_DB   path to traffic.db (default: recorder/traffic.db next to this file)

The query functions below take an explicit db_path and never import mcp,
so they can be unit-tested inside the project environment (which has no mcp).
"""

import os
import sqlite3
import time
from pathlib import Path
from typing import Any

DEFAULT_DB = str(Path(__file__).parent / "traffic.db")

FLOW_COLUMNS = (
    "id, ts, duration_ms, method, scheme, host, port, path, status,"
    " req_headers, resp_headers, req_size, resp_size, error"
)


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _rows(cursor: sqlite3.Cursor) -> list[dict[str, Any]]:
    return [dict(r) for r in cursor.fetchall()]


def list_flows(
    db_path: str,
    host: str | None = None,
    since_seconds: int = 3600,
    status: int | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List recent flows, newest first. `host` matches subdomains ('%.example.com')."""
    where = ["ts > ?"]
    params: list[Any] = [time.time() - since_seconds]
    if host:
        where.append("(host = ? OR host LIKE ?)")
        params += [host, f"%.{host.lstrip('*.')}"]
    if status is not None:
        where.append("status = ?")
        params.append(status)
    params.append(limit)
    conn = connect(db_path)
    try:
        cur = conn.execute(
            f"SELECT {FLOW_COLUMNS} FROM flows WHERE {' AND '.join(where)}"
            " ORDER BY id DESC LIMIT ?",
            params,
        )
        return _rows(cur)
    finally:
        conn.close()


def get_flow(
    db_path: str, flow_id: int, include_body: bool = False, max_body: int = 20000
) -> dict[str, Any] | None:
    """Get one flow by id. Bodies are omitted unless include_body=True (then truncated to max_body chars)."""
    conn = connect(db_path)
    try:
        row = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
        if row is None:
            return None
        flow = dict(row)
        for key in ("req_body", "resp_body"):
            body = flow.get(key)
            if not include_body:
                flow[key] = (
                    f"<{len(body)} chars, pass include_body=true>" if body else None
                )
            elif body and len(body) > max_body:
                flow[key] = body[:max_body] + "...[truncated by mcp_server]"
        return flow
    finally:
        conn.close()


def domain_stats(db_path: str, since_seconds: int = 3600) -> list[dict[str, Any]]:
    """Per-domain aggregate: request count, bytes, avg latency, 4xx/5xx counts."""
    conn = connect(db_path)
    try:
        cur = conn.execute(
            """
            SELECT host,
                   count(*)     AS requests,
                   sum(resp_size) AS total_bytes,
                   avg(duration_ms) AS avg_ms,
                   sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) AS errors_5xx,
                   sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) AS errors_4xx
            FROM flows
            WHERE ts > ?
            GROUP BY host
            ORDER BY requests DESC
            """,
            (time.time() - since_seconds,),
        )
        return _rows(cur)
    finally:
        conn.close()


def search_flows(
    db_path: str,
    pattern: str,
    since_seconds: int = 86400,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Substring search in path, req_body and resp_body."""
    like = f"%{pattern}%"
    conn = connect(db_path)
    try:
        cur = conn.execute(
            f"SELECT {FLOW_COLUMNS} FROM flows"
            " WHERE ts > ? AND (path LIKE ? OR req_body LIKE ? OR resp_body LIKE ?)"
            " ORDER BY id DESC LIMIT ?",
            (time.time() - since_seconds, like, like, like, limit),
        )
        return _rows(cur)
    finally:
        conn.close()


def create_server():
    """Build the MCP server. Imports mcp lazily so this module stays importable without it."""
    from mcp.server.mcpserver import MCPServer

    db_path = os.environ.get("TRAFFIC_DB", DEFAULT_DB)
    mcp = MCPServer("traffic-recorder")

    @mcp.tool(name="list_flows")
    def tool_list_flows(
        host: str | None = None,
        since_seconds: int = 3600,
        status: int | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List recent intercepted HTTP flows. Filter by domain (subdomains included), age, and status code."""
        return list_flows(db_path, host, since_seconds, status, limit)

    @mcp.tool(name="get_flow")
    def tool_get_flow(
        flow_id: int, include_body: bool = False
    ) -> dict[str, Any] | None:
        """Get full details of one flow by id, including headers; optionally the (truncated) bodies."""
        return get_flow(db_path, flow_id, include_body)

    @mcp.tool(name="domain_stats")
    def tool_domain_stats(since_seconds: int = 3600) -> list[dict[str, Any]]:
        """Aggregate traffic statistics per domain: counts, bytes, latency, error rates."""
        return domain_stats(db_path, since_seconds)

    @mcp.tool(name="search_flows")
    def tool_search_flows(
        pattern: str, since_seconds: int = 86400, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Search for flows whose URL or bodies contain a substring."""
        return search_flows(db_path, pattern, since_seconds, limit)

    return mcp


if __name__ == "__main__":
    create_server().run()
