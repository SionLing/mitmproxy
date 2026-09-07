# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

mitmproxy is an interactive TLS-capable intercepting proxy for HTTP/1, HTTP/2, HTTP/3, and WebSockets. It ships three frontends sharing one core: `mitmproxy` (console TUI, urwid), `mitmdump` (CLI, like tcpdump for HTTP), and `mitmweb` (web UI). Entry points are in `mitmproxy/tools/main.py`.

## Commands

This project uses **uv** — always prefix Python commands with `uv run` (never call `pytest` directly).

```shell
uv run mitmproxy --version        # dev setup: creates .venv and installs everything
uv run tox                        # full test suite (lint, mypy, pytest)
uv run pytest test/               # fast: run tests directly
uv run pytest test/mitmproxy/addons/test_anticache.py::test_simple   # single test
uv run tox -e lint                # ruff check (CI-enforced)
uv run tox -e fix                 # auto-fix lint + ruff format
uv run tox -e mypy                # type checking
uv run tox -e individual_coverage -- mitmproxy/foo.py   # required when adding new source files
```

Web UI (mitmweb) development — from `web/` (Node.js 24+):

```shell
npm install && npm start          # Vite dev server (run `uv run mitmweb` separately as backend)
npm test                          # eslint + tsc --noEmit + jest
npm run prettier                  # format
```

Never commit the compiled assets in `mitmproxy/tools/web/static` — they are regenerated at release time.

## Architecture

### Request flow: connections → layers → flows → addons

1. **Core objects**: `mitmproxy/flow.py` defines `Flow` (one client↔server conversation); protocol-specific subclasses live in `mitmproxy/http.py`, `tcp.py`, `udp.py`, `dns.py`, `websocket.py`. `mitmproxy/connection.py` models the underlying connections.

2. **Proxy core** (`mitmproxy/proxy/`): a sans-IO, layered protocol stack. Each protocol stage is a `Layer` (`proxy/layer.py`) that receives events and yields commands via generators — `def _handle_event(self, event): err = yield OpenConnection(...)` looks blocking but isn't (layers pause on blocking commands and buffer events). Layers stack dynamically: `modes.py` (proxy modes: regular/transparent/reverse/wireguard/local capture) → `tls.py` → `http/` (`layers/http/_http1.py`, `_http2.py`, `_http3.py`) → etc. `proxy/server.py` is the only IO boundary; low-level networking (UDP/QUIC, WireGuard, local redirect) delegates to the Rust extension `mitmproxy_rs`.

3. **Master event loop** (`mitmproxy/master.py`): owns the asyncio loop, `Options` (`optmanager.py`), the `CommandManager` (`command.py` — all user-invokable commands), and the `AddonManager`.

4. **Addon/hook system** (`mitmproxy/addonmanager.py`, `mitmproxy/hooks.py`): everything above the proxy core is an addon. Hooks are dataclasses (e.g. `requestheaders`, `response`, `tcp_message`) fired by layers; addons implement same-named methods. Built-in functionality lives in `mitmproxy/addons/` (~40 modules: intercept, modifyheaders, maplocal, proxyauth, save, view, ...) and is registered in `mitmproxy/addons/__init__.py` — this is where most features are implemented. Inline scripts (`mitmproxy/script/`) load user addons via `-s`.

5. **Frontends** (`mitmproxy/tools/`): `console/` (urwid TUI), `web/` (tornado server + React client in `web/`), and dump. Each has its own `Master` subclass; the web frontend's TypeScript type definitions are generated from Python by scripts in `web/gen/` (run `web/gen/all` after changing options/flow/column types).

### Testing conventions

- Tests mirror source layout: `mitmproxy/addons/foo.py` → `test/mitmproxy/addons/test_foo.py`. The `filename_matching` tox env enforces this for new files.
- Test helpers are shipped in `mitmproxy/test/` (e.g. `tflow` factories, `taddons` for a test `Master` context).
- The project targets **100% test coverage**, strictly enforced per-file by `individual_coverage` for everything not excluded in `pyproject.toml`.
- pytest config: `asyncio_mode = "auto"`, `RuntimeWarning` and `PytestUnraisableExceptionWarning` are errors.

### Code style

- Ruff for lint+format; imports are **one per line** (`force-single-line` isort style, stdlib → third-party → local-folder → first-party).
- `asyncio.create_task` is **banned** (ruff TID251) — use `mitmproxy.utils.asyncio_utils.create_task` instead to avoid the GC footgun.
- `mitmproxy/contrib/` is vendored third-party code: excluded from lint, typing, and coverage.
- Docs live in `docs/` (Hugo site; see `docs/README.md`).
