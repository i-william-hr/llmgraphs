#!/usr/bin/env python3
"""index_traces — parse llmtrace trace files into llmgraphs' own SQLite.

Reads the live trace dir ([REDACTED:server-path]) and the daily
archive (/server/storage/llmtrace-archive) — both group-readable via the
"traces" group — and writes one row per inference span into data/llmgraphs.db.
The trace trees are opened read-only; data/ is the only path written.

One trace file = one JSON array of OpenTelemetry-style spans (Monocle export).
A file may be split across two files sharing a trace_id (~6%); rows are stored
per inference span, so that dedupes naturally. Files with no inference span
(llmtrace's "junk" definition) are recorded once with kind='junk' and skipped
forever after — the 2026-10-25/26 burst was ~389k such files.

Incremental by filename: a file is parsed at most once. A file that fails to
parse (being written concurrently) is NOT recorded, so the next run retries it.
"""

import gzip
import json
import multiprocessing
import os
import sqlite3
import sys
import time
from datetime import datetime

LIVE_DIR = "[REDACTED:server-path]"
ARCHIVE_DIR = "/server/storage/llmtrace-archive"
DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "llmgraphs.db")

BATCH = 200          # files per pool task
COMMIT_EVERY = 10    # batches between commits

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    name      TEXT PRIMARY KEY,
    kind      TEXT NOT NULL,          -- ok | junk
    n_calls   INTEGER NOT NULL DEFAULT 0,
    indexed   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS calls (
    ts                REAL,           -- inference span start, epoch seconds (UTC)
    trace_id          TEXT,
    workflow          TEXT,
    model             TEXT,
    provider          TEXT,
    prompt_tokens     INTEGER,
    completion_tokens INTEGER,
    total_tokens      INTEGER,
    duration_ms       REAL,
    status            TEXT,           -- ok | error
    cache_read        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_calls_ts    ON calls(ts);
CREATE INDEX IF NOT EXISTS idx_calls_model ON calls(model);
CREATE INDEX IF NOT EXISTS idx_calls_wf    ON calls(workflow, ts);
"""


def open_db(path):
    conn = sqlite3.connect(path, timeout=60)
    conn.executescript(SCHEMA)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def epoch(iso):
    # '2026-11-03T12:12:56.765681Z' -> float epoch
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def workflow_from_filename(name):
    # monocle_trace_<workflow>_<32hex>_<date>_<time>.json[.gz]
    parts = name.split("_")
    return parts[2] if len(parts) > 3 else "?"


def parse_file(path):
    """Return (rows, n_spans) for one trace file; raises on parse failure."""
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rb") as fh:
        spans = json.load(fh)
    if not isinstance(spans, list):
        spans = spans.get("spans", []) if isinstance(spans, dict) else []

    rows = []
    workflow = None
    for s in spans:
        attrs = s.get("attributes") or {}
        if workflow is None:
            workflow = attrs.get("workflow.name")
        if attrs.get("span.type") != "inference":
            continue
        model = attrs.get("entity.2.name")
        if not model:
            etype = attrs.get("entity.2.type") or ""
            if etype.startswith("model.llm."):
                model = etype[len("model.llm."):]
        if not model:
            continue
        meta = {}
        for ev in s.get("events") or []:
            if ev.get("name") == "metadata":
                meta = ev.get("attributes") or {}
                break
        try:
            start = epoch(s["start_time"])
            end = epoch(s["end_time"])
        except (KeyError, ValueError):
            continue
        status = (s.get("status") or {}).get("status_code") or "UNSET"
        rows.append((
            start,
            (s.get("context") or {}).get("trace_id"),
            workflow,
            model,
            attrs.get("entity.1.provider_name"),
            meta.get("prompt_tokens"),
            meta.get("completion_tokens"),
            meta.get("total_tokens"),
            max(0.0, (end - start) * 1000.0),
            "error" if status == "ERROR" else "ok",
            meta.get("cache_read_input_tokens"),
        ))
    return rows, workflow


def worker(batch):
    """Parse one batch of (name, path). Returns (rows, ok, junk, failed, wf_fix)."""
    rows, ok, junk, failed = [], [], [], 0
    for name, path in batch:
        try:
            file_rows, wf = parse_file(path)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            # usually a file mid-write; leave unrecorded so the next run retries
            failed += 1
            continue
        if file_rows:
            if not file_rows[0][2] and wf is None:
                wf = workflow_from_filename(name)
            for r in file_rows:
                if not r[2]:
                    r = (r[0], r[1], wf or workflow_from_filename(name)) + r[3:]
            rows.extend(file_rows)
            ok.append((name, "ok", len(file_rows)))
        else:
            junk.append((name, "junk", 0))
    return rows, ok, junk, failed


def scan_new(conn, roots):
    known = {r[0] for r in conn.execute("SELECT name FROM files")}
    todo = {0: [], 1: []}
    for prio, root in ((1, LIVE_DIR), (0, ARCHIVE_DIR)):
        try:
            entries = list(os.scandir(root))
        except OSError as e:
            print(f"cannot scan {root}: {e}", file=sys.stderr)
            continue
        for ent in entries:
            name = ent.name
            if not name.endswith((".json", ".json.gz")) or name in known:
                continue
            todo[prio].append((name, ent.path))
    # live dir first (fresh data), then archive bulk
    return todo[1] + todo[0]


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 2))
    ap.add_argument("--full", action="store_true", help="drop and reindex everything")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.db), exist_ok=True)
    conn = open_db(args.db)
    if args.full:
        conn.executescript("DROP TABLE IF EXISTS calls; DROP TABLE IF EXISTS files;")
        conn.executescript(SCHEMA)
    todo = scan_new(conn, (LIVE_DIR, ARCHIVE_DIR))
    total = len(todo)
    if not total:
        print("index: nothing new")
        conn.close()
        return
    print(f"index: {total} new files, {args.jobs} workers", flush=True)

    batches = [todo[i:i + BATCH] for i in range(0, total, BATCH)]
    t0 = time.time()
    done = n_calls = n_junk = n_failed = 0
    conn.execute("BEGIN")
    try:
        with multiprocessing.Pool(args.jobs) as pool:
            for rows, ok, junk, failed in pool.imap_unordered(worker, batches, chunksize=1):
                if rows:
                    conn.executemany(
                        "INSERT INTO calls (ts, trace_id, workflow, model, provider,"
                        " prompt_tokens, completion_tokens, total_tokens, duration_ms,"
                        " status, cache_read) VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
                conn.executemany(
                    "INSERT OR REPLACE INTO files (name, kind, n_calls, indexed)"
                    " VALUES (?,?,?,?)",
                    [(name, kind, n, time.time()) for name, kind, n in ok + junk])
                done += len(ok) + len(junk)
                n_calls += len(rows)
                n_junk += len(junk)
                n_failed += failed
                if (done // BATCH) % COMMIT_EVERY == 0:
                    conn.commit()
                    conn.execute("BEGIN")
                    if not args.quiet:
                        rate = done / max(time.time() - t0, 0.001)
                        print(f"  {done}/{total} files, {n_calls} calls, "
                              f"{rate:.0f} files/s", flush=True)
        conn.commit()
    finally:
        if conn.in_transaction:
            conn.rollback()

    n, first, last = conn.execute(
        "SELECT COUNT(*), MIN(ts), MAX(ts) FROM calls").fetchone()
    print(f"index: done {done} files ({n_junk} junk, {n_failed} retried later) "
          f"in {time.time()-t0:.0f}s — {n} call rows "
          f"({datetime.fromtimestamp(first) if first else '-'} .. "
          f"{datetime.fromtimestamp(last) if last else '-'})", flush=True)
    conn.close()


if __name__ == "__main__":
    main()
