#!/usr/bin/env python3
"""
Watch traffic.db (written by traffic_recorder.py) and print one line per
noteworthy new flow: HTTP 5xx, connection errors, or requests to watched hosts.

Standalone:
    uv run python recorder/alert_watch.py --db recorder/traffic.db
    uv run python recorder/alert_watch.py --db recorder/traffic.db --host api.example.com --all-matching

With Claude Code, arm a Monitor tool with this command to get a notification
per event line; or run it in a spare terminal and watch the output.
"""

import argparse
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Event:
    id: int
    ts: float
    method: str
    host: str
    path: str
    status: int | None
    error: str | None
    reason: str

    def format(self) -> str:
        when = datetime.fromtimestamp(self.ts).strftime("%H:%M:%S")
        target = f"{self.method} {self.host}{self.path}"
        code = self.status if self.status is not None else "-"
        extra = f" error={self.error}" if self.error else ""
        return f"[{when}] {self.reason}: {target} -> {code}{extra} (flow #{self.id})"


def fetch_events(
    conn: sqlite3.Connection,
    last_id: int,
    min_status: int = 500,
    hosts: list[str] | None = None,
    all_matching: bool = False,
) -> tuple[list[Event], int]:
    """Return noteworthy flows with id > last_id, and the new high-water mark.

    Noteworthy = status >= min_status, or error set, or (with --all-matching)
    any request to a watched host. Watched hosts are always included on error.
    """
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, ts, method, host, path, status, error FROM flows"
        " WHERE id > ? ORDER BY id",
        (last_id,),
    ).fetchall()

    events: list[Event] = []
    new_last_id = last_id
    for r in rows:
        new_last_id = max(new_last_id, r["id"])
        host_hit = hosts and any(
            r["host"] == h or r["host"].endswith("." + h.lstrip("*.")) for h in hosts
        )
        if r["status"] is not None and r["status"] >= min_status:
            reason = f"HTTP {r['status']}"
        elif r["error"]:
            reason = "connection error"
        elif host_hit and all_matching:
            reason = "watched host"
        elif host_hit and r["status"] is not None and r["status"] >= 400:
            reason = f"HTTP {r['status']} on watched host"
        else:
            continue
        events.append(
            Event(
                r["id"],
                r["ts"],
                r["method"],
                r["host"],
                r["path"],
                r["status"],
                r["error"],
                reason,
            )
        )
    return events, new_last_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", required=True, help="path to traffic.db")
    parser.add_argument(
        "--interval", type=float, default=2.0, help="poll interval in seconds"
    )
    parser.add_argument(
        "--min-status", type=int, default=500, help="alert at or above this status"
    )
    parser.add_argument(
        "--host",
        action="append",
        dest="hosts",
        help="watched domain (repeatable; subdomains included). Their 4xx also alert.",
    )
    parser.add_argument(
        "--all-matching",
        action="store_true",
        help="emit every request to a watched host, not just failures",
    )
    args = parser.parse_args(argv)

    conn = sqlite3.connect(args.db)
    # Start from the current end: only alert on new traffic.
    last_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM flows").fetchone()[0]
    print(f"watching {args.db} from flow #{last_id} (Ctrl+C to stop)", flush=True)

    try:
        while True:
            events, last_id = fetch_events(
                conn, last_id, args.min_status, args.hosts, args.all_matching
            )
            for e in events:
                print(e.format(), flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
