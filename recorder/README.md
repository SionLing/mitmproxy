# Traffic Recorder

Record all HTTP traffic intercepted by mitmproxy into a local SQLite database,
so Claude Code (or any tool) can filter by domain and analyze requests/responses with SQL.

## Components

| File | Purpose |
|------|---------|
| `traffic_recorder.py` | mitmproxy addon: writes every completed/failed flow into SQLite (WAL mode) |
| `queries.sql` | Ready-made SQL queries (domain filter, aggregates, 5xx, slow requests, full-text) |
| `mcp_server.py` | MCP server exposing the DB to Claude Code as tools (`list_flows`, `get_flow`, `domain_stats`, `search_flows`) |
| `alert_watch.py` | Polling watcher: prints one line per new 5xx / connection error / watched-host request |

## Quick start

```shell
# 1. Start recording (or use mitmproxy/mitmweb instead of mitmdump)
uv run mitmdump -s recorder/traffic_recorder.py

# 2. Point your apps at the proxy (127.0.0.1:8080) and generate traffic.
#    Note: curl honors NO_PROXY for localhost — use --noproxy "" to force the proxy:
curl --noproxy "" -x http://127.0.0.1:8080 --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://example.com

# 3. Query from Claude Code or any terminal
sqlite3 recorder/traffic.db "SELECT method, host, path, status FROM flows ORDER BY id DESC LIMIT 10"
```

Data is retained for 7 days (cleaned on addon startup). Text bodies are stored
truncated to 256KB; binary bodies store size only.

## Claude Code integration

**Without MCP (default):** just ask — Claude reads `recorder/traffic.db` with
`sqlite3` via Bash, using `queries.sql` patterns.

**With MCP:** register the server once:

```shell
claude mcp add traffic-recorder -- uv run --script /path/to/recorder/mcp_server.py
```

Then Claude can call `list_flows(host="baidu.com")`, `get_flow(id, include_body=true)`,
`domain_stats()`, `search_flows(pattern)` directly. Set `TRAFFIC_DB` env var to point
at a non-default database.

**Live alerts:** run in a spare terminal, or arm a Claude Code Monitor with:

```shell
uv run python recorder/alert_watch.py --db recorder/traffic.db --host api.example.com
```

Each new 5xx/connection error (and 4xx on watched hosts) prints one line.

## Tests

```shell
uv run pytest recorder/ -q
```
