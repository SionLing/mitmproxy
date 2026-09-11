# /// script
# requires-python = ">=3.12"
# dependencies = ["mcp>=1.2", "ruamel.yaml"]
# ///
"""
MCP server exposing the traffic.db recorded by traffic_recorder.py to Claude Code.

Run standalone (stdio transport):
    uv run --script recorder/mcp_server.py

Register with Claude Code (project scope):
    claude mcp add traffic-recorder -- uv run --script \\
        /Users/sion/projects/mitmproxy/recorder/mcp_server.py

Configuration via environment:
    TRAFFIC_DB        path to traffic.db (default: recorder/traffic.db next to this file)
    MITMPROXY_CONFIG  path to config.yaml holding the block_list option
                      (default: ~/.mitmproxy/config.yaml)
    MITMWEB_API       mitmweb API base URL used to apply block_list changes live
                      (default: http://127.0.0.1:8081)

The query functions below take an explicit db_path and never import mcp,
so they can be unit-tested inside the project environment (which has no mcp).
"""

import json
import os
import re
import sqlite3
import time
import urllib.request
from pathlib import Path
from typing import Any

import ruamel.yaml

DEFAULT_DB = str(Path(__file__).parent / "traffic.db")
DEFAULT_CONFIG = str(Path("~/.mitmproxy").expanduser() / "config.yaml")
DEFAULT_API = "http://127.0.0.1:8081"
CAPTURE_LOG = "/tmp/traffic_recorder_mitmdump.log"

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


def _normalize_domain(domain: str) -> str:
    """Accept bare domains, '*.example.com' or full URLs; return a bare domain."""
    domain = domain.strip().lower().removeprefix("*.")
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0].split(":", 1)[0]
    if not domain:
        raise ValueError("empty domain")
    return domain


def make_block_entry(domain: str, status: int = 403) -> str:
    """Build a block_list option entry ('/flow-filter/status') matching the
    domain and its subdomains. The filter regex must be quoted — mitmproxy's
    filter grammar disallows parens in bare words — and dots use character
    classes to dodge backslash-escaping across the filter and YAML layers."""
    regex = "(^|[.])" + domain.replace(".", "[.]") + "$"
    return f"/~d '{regex}'/{status}"


_ENTRY_RE = re.compile(r"/~d '\(\^\|\[\.\]\)(?P<domain>.+?)\$'/(?P<status>\d+)$")


def parse_block_entry(entry: str) -> dict[str, Any] | None:
    """Parse an entry produced by make_block_entry back into domain + status.
    Returns None for entries written by hand with other filters."""
    m = _ENTRY_RE.fullmatch(entry)
    if not m:
        return None
    return {
        "domain": m.group("domain").replace("[.]", "."),
        "status": int(m.group("status")),
    }


def load_config(config_path: str) -> dict[str, Any]:
    p = Path(config_path).expanduser()
    if not p.exists():
        return {}
    data = ruamel.yaml.YAML(typ="safe", pure=True).load(p.read_text(encoding="utf8"))
    return data or {}


def save_config(config_path: str, config: dict[str, Any]) -> None:
    p = Path(config_path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf8") as f:
        ruamel.yaml.YAML().dump(config, f)


def discover_token(config: dict[str, Any], log_path: str = CAPTURE_LOG) -> str | None:
    """Auth token for the mitmweb API: the fixed `web_password` option if set,
    otherwise the random per-boot token from the capture log."""
    pw = config.get("web_password")
    if pw and not str(pw).startswith("$"):  # argon2 hashes are unusable as tokens
        return str(pw)
    p = Path(log_path)
    if p.exists():
        tokens = re.findall(r"\?token=([0-9a-f]{32,})", p.read_text(errors="replace"))
        if tokens:
            return tokens[-1]
    return None


def _api_request(
    api_url: str, token: str, method: str, path: str, payload: Any = None
) -> Any:
    req = urllib.request.Request(
        f"{api_url}{path}",
        method=method,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        body = resp.read().decode()
        return json.loads(body) if body else None


def _live_entries(api_url: str | None, token: str | None) -> list[str] | None:
    """Current block_list from a running mitmweb, or None if unreachable."""
    if not api_url or not token:
        return None
    try:
        opts = _api_request(api_url, token, "GET", "/options")
        return list(opts["block_list"]["value"] or [])
    except Exception:
        return None


def _read_entries(
    config_path: str, api_url: str | None, token: str | None
) -> tuple[dict[str, Any], list[str], bool]:
    """(config, current block_list entries, live?) — live state wins when
    mitmweb is reachable, otherwise fall back to the config file."""
    config = load_config(config_path)
    entries = _live_entries(api_url, token)
    if entries is not None:
        return config, entries, True
    return config, list(config.get("block_list") or []), False


def _write_entries(
    config_path: str,
    config: dict[str, Any],
    entries: list[str],
    live: bool,
    api_url: str | None,
    token: str | None,
) -> str:
    if live:
        try:
            # mitmweb's Options.put persists the change to the config file.
            _api_request(api_url, token, "PUT", "/options", {"block_list": entries})
            return "mitmweb (effective immediately + saved to config)"
        except Exception:
            pass
    if entries:
        config["block_list"] = entries
    else:
        config.pop("block_list", None)
    save_config(config_path, config)
    return "config file (takes effect on next mitmproxy start)"


def block_domain(
    config_path: str,
    domain: str,
    status: int = 403,
    api_url: str | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """Add a domain to the block_list option. Subdomains are blocked too."""
    domain = _normalize_domain(domain)
    config, entries, live = _read_entries(config_path, api_url, token)
    for e in entries:
        parsed = parse_block_entry(e)
        if parsed and parsed["domain"] == domain:
            return {"domain": domain, "added": False, "entry": e}
    entry = make_block_entry(domain, status)
    persisted = _write_entries(
        config_path, config, entries + [entry], live, api_url, token
    )
    return {"domain": domain, "added": True, "entry": entry, "persisted": persisted}


def list_blocked(
    config_path: str, api_url: str | None = None, token: str | None = None
) -> list[dict[str, Any]]:
    """List the current block_list entries. Entries created via block_domain
    are returned as {domain, status}; hand-written filters as {raw}."""
    _, entries, _ = _read_entries(config_path, api_url, token)
    return [p if (p := parse_block_entry(e)) else {"raw": e} for e in entries]


def unblock_domain(
    config_path: str,
    domain: str,
    api_url: str | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """Remove a domain from the block_list option."""
    domain = _normalize_domain(domain)
    config, entries, live = _read_entries(config_path, api_url, token)
    kept = [
        e for e in entries if not (p := parse_block_entry(e)) or p["domain"] != domain
    ]
    if len(kept) == len(entries):
        return {"domain": domain, "removed": False}
    persisted = _write_entries(config_path, config, kept, live, api_url, token)
    return {"domain": domain, "removed": True, "persisted": persisted}


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
    config_path = os.environ.get("MITMPROXY_CONFIG", DEFAULT_CONFIG)
    api_url = os.environ.get("MITMWEB_API", DEFAULT_API)

    def current_token() -> str | None:
        # Resolved per call: mitmweb generates a fresh random token on every
        # restart unless web_password is set, and the latest one lands in the
        # capture log.
        return discover_token(load_config(config_path))

    mcp = MCPServer(
        "traffic-recorder",
        instructions=(
            "Query and analyze HTTP traffic captured by mitmproxy into SQLite, "
            "and manage mitmproxy's block_list option (blocked requests get an "
            "immediate 403 and never reach the server). Blocklist changes apply "
            "live when mitmweb is running and are always persisted to config.yaml; "
            "the same list is visible in the mitmweb Options UI. "
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

    @mcp.tool(name="block_domain")
    def tool_block_domain(domain: str, status: int = 403) -> dict[str, Any]:
        """Add a domain to mitmproxy's block_list option; every request to it (subdomains included) gets an empty response with the given status (444 closes the connection). Applies live when mitmweb runs, always persisted to config.yaml. Accepts 'example.com', '*.example.com' or a URL."""
        return block_domain(config_path, domain, status, api_url, current_token())

    @mcp.tool(name="list_blocked")
    def tool_list_blocked() -> list[dict[str, Any]]:
        """List mitmproxy's current block_list entries: {domain, status} for entries added via block_domain, {raw} for hand-written filters."""
        return list_blocked(config_path, api_url, current_token())

    @mcp.tool(name="unblock_domain")
    def tool_unblock_domain(domain: str) -> dict[str, Any]:
        """Remove a domain from mitmproxy's block_list option. Applies live when mitmweb runs, always persisted."""
        return unblock_domain(config_path, domain, api_url, current_token())

    @mcp.tool(name="capture_guide")
    def tool_capture_guide() -> str:
        """Operational guide for starting/stopping the traffic capture (capture.sh), incl. WireGuard mode setup and the Endpoint IP fix for Macs running a VPN. Consult when the DB is empty/stale or the user asks how to capture phone traffic."""
        return CAPTURE_GUIDE

    return mcp


if __name__ == "__main__":
    create_server().run()
