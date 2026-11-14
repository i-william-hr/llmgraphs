#!/usr/bin/env python3
"""snapshot_usage — copy orlogs + llmproxy usage data into llmgraphs' data dir.

Runs as root (the source DBs are 0600 owned by their service accounts; the
unit keeps CAP_DAC_OVERRIDE for exactly that and CAP_CHOWN to hand the
outputs back to llmgraphs). Sources are opened read-only; the targets live
under [REDACTED:server-path] and are the only writes.

Both sources are WAL-mode. orlogs deletes -wal/-shm on close between ingest
batches, and under the unit's ProtectSystem=strict the filesystem is
read-only, so sqlite cannot re-create the -shm a WAL reader needs and the
first query dies with "unable to open database file" — this is why the
2026-11-06 23:00 run passed and every run from 2026-11-07 00:00 on failed.
ro_connect() retries with immutable=1, which skips wal/shm entirely; safe
because a missing -wal means no un-checkpointed frames (the writer is
between batches), and the sync is incremental by rowid anyway.

  orlogs   [REDACTED:server-path]   table spans (OTLP rows)
           -> orlogs-usage.db table ospans
           Column extraction deliberately does NOT reuse orlogs' own
           heuristics (its input-cost heuristic conflates cache-read vs
           non-cache input and misses the total). Here every value comes
           from the stored attrs JSON by exact dotted key; numeric values
           that arrive as strings are coerced.

  llmproxy [REDACTED:server-path]    table usage
           -> llmproxy-usage.db table lusage (blob columns dropped)

Both are incremental by source rowid (append-only log tables) recorded in a
meta table; re-running is idempotent and cheap.
"""

import json
import os
import pwd
import sqlite3
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ORLOGS_DB = "[REDACTED:server-path]"
LLMPROXY_DB = "[REDACTED:server-path]"
OUT_ORLOGS = os.path.join(HERE, "data", "orlogs-usage.db")
OUT_LLMPROXY = os.path.join(HERE, "data", "llmproxy-usage.db")


def ro_connect(path):
    """Read-only connection to a foreign WAL-mode database.

    The main file opens at connect(); the -shm a WAL reader needs is only
    created at the first read, so that is where the sandbox bites — probe
    with a schema read and fall back to immutable=1 if the -shm could not
    be created. immutable only ever fires when the source has no -wal, so
    it reads the fully checkpointed file.
    """
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        c.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return c
    except sqlite3.OperationalError:
        c.close()
    c = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    c.execute("SELECT count(*) FROM sqlite_master").fetchone()
    return c

OS_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS ospans (
    id                 INTEGER PRIMARY KEY,   -- orlogs spans.rowid
    ts                 REAL,
    model              TEXT,
    provider           TEXT,
    provider_slug      TEXT,
    provider_model_id  TEXT,
    status             TEXT,
    streamed           INTEGER,
    cancelled          INTEGER,
    byok               INTEGER,
    api_key_label      TEXT,
    creator_user_id    TEXT,
    app_title          TEXT,
    origin             TEXT,
    user_agent         TEXT,
    endpoint_region    TEXT,
    data_region        TEXT,
    service_tier       TEXT,
    in_tokens          INTEGER,
    non_cache_tokens   INTEGER,
    cache_read_tokens  INTEGER,
    out_tokens         INTEGER,
    cached_tokens      INTEGER,
    reasoning_tokens   INTEGER,
    cache_write_tokens INTEGER,
    cost_cache_read    REAL,
    cost_non_cache     REAL,
    cost_output        REAL,
    cost_platform      REAL,
    cost_total         REAL,
    cost_upstream      REAL,
    router_ms          REAL,
    provider_ms        REAL,
    provider_failed_ms REAL,
    client_wait_ms     REAL,
    attempt_count      INTEGER,
    first_token_ms     REAL,
    inter_token_ms     REAL,
    ttfb_ms            REAL,
    duration_ms        REAL
);
CREATE INDEX IF NOT EXISTS idx_ospans_ts     ON ospans(ts);
CREATE INDEX IF NOT EXISTS idx_ospans_model  ON ospans(model);
CREATE INDEX IF NOT EXISTS idx_ospans_prov   ON ospans(provider, ts);
"""

LS_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS lusage (
    id                INTEGER PRIMARY KEY,   -- llmproxy usage.rowid
    ts                REAL,
    key_id            TEXT,
    key_label         TEXT,
    provider          TEXT,
    model             TEXT,
    client_model      TEXT,
    stream            INTEGER,
    status            INTEGER,
    latency_ms        REAL,
    ttfb_ms           REAL,
    prompt_tokens     INTEGER,
    completion_tokens INTEGER,
    total_tokens      INTEGER,
    cost_usd          REAL,
    error             TEXT,
    trace_id          TEXT
);
CREATE INDEX IF NOT EXISTS idx_lusage_ts    ON lusage(ts);
CREATE INDEX IF NOT EXISTS idx_lusage_model ON lusage(model);
CREATE INDEX IF NOT EXISTS idx_lusage_prov  ON lusage(provider, ts);
"""

# attribute keys live under trace.metadata.* and are duplicated under
# span.metadata.*; prefer trace., fall back to span., then bare.
PREFIXES = ("trace.metadata.", "span.metadata.", "")


def _get(attrs, *keys):
    for k in keys:
        for p in PREFIXES:
            v = attrs.get(p + k)
            if v not in (None, "", []):
                return v
    return None


def _f(v):
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _i(v):
    n = _f(v)
    return int(n) if n is not None else None


def _b(v):
    if isinstance(v, bool):
        return int(v)
    n = _i(v)
    return n if n in (0, 1) else None


def _s(v):
    if v is None:
        return None
    return str(v)[:200]


def extract_orlogs_row(row):
    attrs = json.loads(row["attrs"]) if row["attrs"] else {}
    model = attrs.get("gen_ai.response.model") \
        or attrs.get("gen_ai.request.model") \
        or _get(attrs, "openrouter_generation.model")
    if not model:
        return None  # not a request span
    # provider_responses is a JSON array of per-attempt objects
    prov = _get(attrs, "openrouter.provider_name")
    if not prov:
        pr = _get(attrs, "provider_responses")
        if isinstance(pr, str):
            try:
                arr = json.loads(pr)
                if arr and isinstance(arr[0], dict):
                    prov = arr[0].get("provider_name")
            except json.JSONDecodeError:
                pass
    usage = attrs.get("gen_ai.usage.total_cost")
    usage = _f(usage) if usage is not None else None
    total = usage if usage is not None else _f(_get(attrs, "openrouter_generation.usage"))
    upstream = _f(_get(attrs, "openrouter_generation.usage_upstream"))
    up_usage = _get(attrs, "openrouter_generation.upstream_raw_response_usage")
    cached = reasoning = None
    if isinstance(up_usage, str):
        try:
            uu = json.loads(up_usage)
        except json.JSONDecodeError:
            uu = None
        if isinstance(uu, dict):
            cached = _i((uu.get("prompt_tokens_details") or {}).get("cached_tokens"))
            reasoning = _i(uu.get("reasoning_tokens"))
        elif isinstance(uu, list):
            for item in uu:
                if isinstance(item, dict):
                    cached = _i((item.get("prompt_tokens_details") or {})
                                .get("cached_tokens"))
                    reasoning = _i(item.get("reasoning_tokens"))
                    if cached is not None or reasoning is not None:
                        break
    if cached is None:
        cached = _i(attrs.get("gen_ai.usage.input_tokens.cached"))
    if reasoning is None:
        reasoning = _i(attrs.get("gen_ai.usage.output_tokens.reasoning"))
    return (
        row["id"],
        row["start_ns"] / 1e9 if row["start_ns"] else None,
        model,
        prov or row["provider"],
        _s(_get(attrs, "openrouter.provider_slug")),
        _s(_get(attrs, "openrouter.provider_model_id")),
        row["status"],
        _b(_get(attrs, "openrouter_generation.streamed")),
        _b(_get(attrs, "openrouter_generation.cancelled")),
        _b(_get(attrs, "openrouter_cost_allocation.is_byok",
                "openrouter_generation.is_byok", "is_byok")),
        _s(_get(attrs, "openrouter_generation.api_key.label",
                "openrouter.api_key_name")),
        _s(_get(attrs, "openrouter_generation.api_key.creator_user_id",
                "openrouter.creator_user_id")),
        _s(_get(attrs, "openrouter_generation.app.title")),
        _s(_get(attrs, "openrouter_generation.origin")),
        _s(_get(attrs, "openrouter_generation.user_agent")),
        _s(_get(attrs, "openrouter_generation.endpoint_region")),
        _s(_get(attrs, "openrouter_generation.data_region")),
        _s(_get(attrs, "openrouter_generation.billed_service_tier")),
        _i(_get(attrs, "openrouter_cost_allocation.input_tokens")),
        _i(_get(attrs, "openrouter_cost_allocation.non_cache_input_tokens")),
        _i(_get(attrs, "openrouter_cost_allocation.cache_read_input_tokens")),
        _i(_get(attrs, "openrouter_cost_allocation.output_tokens")),
        cached,
        reasoning,
        _i(_get(attrs, "openrouter_generation.cache_write_tokens")),
        _f(_get(attrs, "openrouter_cost_allocation.cache_read_input_cost")),
        _f(_get(attrs, "openrouter_cost_allocation.non_cache_input_cost")),
        _f(_get(attrs, "openrouter_cost_allocation.output_cost")),
        _f(_get(attrs, "openrouter_cost_allocation.platform_cost")),
        total,
        upstream,
        _f(_get(attrs, "openrouter.router_timing.router_ms")),
        _f(_get(attrs, "openrouter.router_timing.provider_ms")),
        _f(_get(attrs, "openrouter.router_timing.provider_failed_ms")),
        _f(_get(attrs, "openrouter.router_timing.client_wait_ms")),
        _i(_get(attrs, "openrouter.router_timing.attempt_count")),
        _f(_get(attrs, "openrouter.first_token_ms")),
        _f(_get(attrs, "openrouter.inter_token_latency_ms")),
        _f(_get(attrs, "openrouter.provider_time_to_first_token_ms")),
        row["duration_ms"],
    )


OS_COLS = """(id, ts, model, provider, provider_slug, provider_model_id, status,
 streamed, cancelled, byok, api_key_label, creator_user_id, app_title, origin,
 user_agent, endpoint_region, data_region, service_tier, in_tokens,
 non_cache_tokens, cache_read_tokens, out_tokens, cached_tokens,
 reasoning_tokens, cache_write_tokens, cost_cache_read, cost_non_cache,
 cost_output, cost_platform, cost_total, cost_upstream, router_ms,
 provider_ms, provider_failed_ms, client_wait_ms, attempt_count,
 first_token_ms, inter_token_ms, ttfb_ms, duration_ms)"""

LS_COLS = """(id, ts, key_id, key_label, provider, model, client_model, stream,
 status, latency_ms, ttfb_ms, prompt_tokens, completion_tokens,
 total_tokens, cost_usd, error, trace_id)"""


def sync_orlogs(out):
    out.executescript(OS_SCHEMA)
    last = int((out.execute("SELECT v FROM meta WHERE k='last_id'").fetchone() or [0])[0] or 0)
    src = ro_connect(ORLOGS_DB)
    src.row_factory = sqlite3.Row
    rows = src.execute(
        "SELECT id, name, start_ns, end_ns, status, duration_ms, attrs"
        " FROM spans WHERE id > ? ORDER BY id", (last,)).fetchall()
    n = 0
    out.execute("BEGIN")
    for row in rows:
        r = extract_orlogs_row(row)
        if r is None:
            continue  # non-request span; last_id below jumps past all of them
        out.execute(f"INSERT OR REPLACE INTO ospans {OS_COLS} VALUES "
                    f"({','.join('?' * 40)})", r)
        n += 1
    if rows:
        out.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('last_id', ?)",
                    (str(rows[-1]["id"]),))
    out.commit()
    src.close()
    return n, len(rows)


def parse_llmproxy_ts(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return datetime.fromisoformat(str(v)).timestamp()
    except ValueError:
        return None


def sync_llmproxy(out):
    out.executescript(LS_SCHEMA)
    last = int((out.execute("SELECT v FROM meta WHERE k='last_id'").fetchone() or [0])[0] or 0)
    src = ro_connect(LLMPROXY_DB)
    rows = src.execute(
        "SELECT rowid AS id, ts, key_id, key_label, provider, model, client_model,"
        " stream, status, latency_ms, ttfb_ms, prompt_tokens, completion_tokens,"
        " total_tokens, cost_usd, error, trace_id FROM usage"
        " WHERE rowid > ? ORDER BY rowid", (last,)).fetchall()
    n = 0
    out.execute("BEGIN")
    for r in rows:
        ts = parse_llmproxy_ts(r[1])
        # error strings run to 2 KB each (147 MB in the source); graphs only
        # need the gist
        err = r[15][:160] if r[15] else None
        out.execute(f"INSERT OR REPLACE INTO lusage {LS_COLS} VALUES "
                    f"({','.join('?' * 17)})",
                    (r[0], ts, r[2], r[3], r[4], r[5], r[6], r[7], r[8],
                     r[9], r[10], r[11], r[12], r[13], r[14], err, r[16]))
        n += 1
    if rows:
        out.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('last_id', ?)",
                    (str(rows[-1][0]),))
    out.commit()
    src.close()
    return n, len(rows)


def hand_over(path):
    uid = pwd.getpwnam("llmgraphs").pw_uid
    gid = pwd.getpwnam("llmgraphs").pw_gid
    os.chown(path, uid, gid)
    os.chmod(path, 0o600)
    for suffix in ("-wal", "-shm"):
        p = path + suffix
        if os.path.exists(p):
            os.chown(p, uid, gid)
            os.chmod(p, 0o600)


def main():
    os.makedirs(os.path.join(HERE, "data"), exist_ok=True)
    t0 = time.time()
    for path, schema, fn, label in (
            (OUT_ORLOGS, OS_SCHEMA, sync_orlogs, "orlogs"),
            (OUT_LLMPROXY, LS_SCHEMA, sync_llmproxy, "llmproxy")):
        out = sqlite3.connect(path, timeout=120)
        try:
            out.execute("PRAGMA journal_mode=WAL")
            out.execute("PRAGMA synchronous=NORMAL")
            new, seen = fn(out)
            out.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            out.execute("VACUUM")   # initial full sync leaves free pages
            print(f"snapshot[{label}]: {new} new rows of {seen} scanned "
                  f"in {time.time()-t0:.1f}s", flush=True)
        finally:
            out.close()
            hand_over(path)


if __name__ == "__main__":
    main()
