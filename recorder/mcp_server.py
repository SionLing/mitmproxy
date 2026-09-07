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


def clear_flows(
    db_path: str,
    host: str | None = None,
    older_than_seconds: int | None = None,
) -> dict[str, Any]:
    """Delete flows. With no filters this wipes the entire database.

    `host` matches subdomains ('example.com' also clears 'api.example.com');
    `older_than_seconds` restricts deletion to flows older than that many seconds.
    """
    where: list[str] = []
    params: list[Any] = []
    if host:
        where.append("(host = ? OR host LIKE ?)")
        params += [host, f"%.{host.lstrip('*.')}"]
    if older_than_seconds is not None:
        where.append("ts < ?")
        params.append(time.time() - older_than_seconds)
    conn = connect(db_path)
    try:
        cur = conn.execute(
            f"DELETE FROM flows{' WHERE ' + ' AND '.join(where) if where else ''}",
            params,
        )
        conn.commit()
        return {"deleted": cur.rowcount}
    finally:
        conn.close()


CAPTURE_GUIDE = """\
# mitmproxy 流量采集操作指南

数据库由 recorder/traffic_recorder.py addon 写入；本 MCP server 只负责查询/清除。
采集进程必须由 capture.sh（或手动命令）启动。

## 启动 / 停止（统一入口）

    /Users/sion/projects/mitmproxy/recorder/capture.sh start              # Mac 本机抓包（开系统代理）
    /Users/sion/projects/mitmproxy/recorder/capture.sh start --no-proxy   # 只采集，不动系统代理
    /Users/sion/projects/mitmproxy/recorder/capture.sh start --phone      # 手机手动代理模式（监听局域网 :8080）
    /Users/sion/projects/mitmproxy/recorder/capture.sh start --wireguard  # 手机 WireGuard 模式（全量接管）
    /Users/sion/projects/mitmproxy/recorder/capture.sh stop               # 停止（关系统代理 + 停进程）
    /Users/sion/projects/mitmproxy/recorder/capture.sh status             # 状态检查

## WireGuard 模式（抓绕过系统代理的 SDK，如广告聚合平台）

原理：手机通过 WireGuard VPN 隧道接入 Mac，全部 TCP/UDP 流量被强制接管，
SDK 即使自有 DoH + 直连 socket 也无法绕过。与手动代理模式互斥。

启动命令的坑（已实测）：
- 必须显式写两个 mode：mitmweb --mode regular --mode wireguard
- 不要加 -p 8080：-p 是所有模式的默认端口，WireGuard 会抢占 8080 导致常规代理起不来
- 用 capture.sh start --wireguard 可自动避开此坑

手机端配置步骤：
1. 先关闭手机 Wi-Fi 的手动代理
2. 手机装 WireGuard App，扫描 mitmweb Web UI（http://127.0.0.1:8081/?token=...，
   见启动日志或 capture.sh 输出）里 WireGuard 卡片的二维码
3. Tunnel name 只是本地显示名，随便填
4. ⚠️ 必须手动修正 Endpoint：Mac 开着 VPN 时，mitmproxy 会把 Endpoint 误识别为
   VPN 隧道 IP（如 192.168.233.2，手机不可达）。在 WireGuard App 里编辑隧道，
   把 Endpoint 改为 Mac 的局域网 IP + 51820（如 192.168.1.163:51820）。
   可用 ipconfig getifaddr en0 查 Mac 当前局域网 IP。

## 其他已知的坑

- 证书安装页域名是 http://mitm.it（不是 mitmproxy.it，后者会 502）
- 本机 shell 的 NO_PROXY 含 127.0.0.1，curl 测本地服务要走代理需加 --noproxy ""
- Mac 开着 VPN（TUN 模式）时，所有出口流量自动走 VPN 隧道；视频 CDN 会明显变慢，
  手机可在代理设置的 bypass 列表里填媒体域名直连
- Android 7+ App 默认不信任用户 CA；有证书固定（pinning）的 App 无法解密，属正常
"""


def create_server():
    """Build the MCP server. Imports mcp lazily so this module stays importable without it."""
    from mcp.server.mcpserver import MCPServer

    db_path = os.environ.get("TRAFFIC_DB", DEFAULT_DB)
    mcp = MCPServer(
        "traffic-recorder",
        instructions=(
            "Query and analyze HTTP traffic captured by mitmproxy into SQLite. "
            "If the database is empty or stale, the capture may not be running — "
            "call the capture_guide tool for how to start it (regular / phone / wireguard modes), "
            "including how to fix the WireGuard Endpoint IP when the Mac runs a VPN."
        ),
    )

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

    @mcp.tool(name="clear_flows")
    def tool_clear_flows(
        host: str | None = None, older_than_seconds: int | None = None
    ) -> dict[str, Any]:
        """Delete recorded flows. DESTRUCTIVE: with no filters this wipes the whole database. Optionally restrict by domain or age."""
        return clear_flows(db_path, host, older_than_seconds)

    @mcp.tool(name="capture_guide")
    def tool_capture_guide() -> str:
        """Operational guide for starting/stopping the traffic capture (capture.sh), incl. WireGuard mode setup and the Endpoint IP fix for Macs running a VPN. Consult when the DB is empty/stale or the user asks how to capture phone traffic."""
        return CAPTURE_GUIDE

    return mcp


if __name__ == "__main__":
    create_server().run()
