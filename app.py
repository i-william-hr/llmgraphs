#!/usr/bin/env python3
"""llmgraphs — LLM usage analytics dashboard for the inbox.li box.

Charts three data sources into one dark page (ECharts, vendored, no CDN):

  main     data/llmgraphs.db      calls   <- llmtrace traces (index_traces.py)
  llmproxy data/llmproxy-usage.db lusage  <- llmproxy usage  (snapshot_usage.py)
  orlogs   data/orlogs-usage.db   ospans  <- OpenRouter broadcasts (same)

Everything is aggregated per request into /api/data with a 5-minute
in-process cache; the page renders ~38 charts from that single JSON.

Served on 127.0.0.1 only (nginx: llmgraphs.inbox.li). HTTP Basic is re-checked
on every request like orlogs does: nginx swaps in the svc-llmgraphs credential
for visitors holding the central SSO cookie, so direct loopback access needs
LLMGRAPHS_USER/LLMGRAPHS_PASS from .env (systemd passes them in).
"""

import json
import math
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone

from flask import Flask, Response, request

HERE = os.path.dirname(os.path.abspath(__file__))
DB_MAIN = os.path.join(HERE, "data", "llmgraphs.db")
DB_LLMPROXY = os.path.join(HERE, "data", "llmproxy-usage.db")
DB_ORLOGS = os.path.join(HERE, "data", "orlogs-usage.db")

PORT = int(os.environ.get("LLMGRAPHS_PORT", "[REDACTED:loopback-port]"))
USER = os.environ.get("LLMGRAPHS_USER") or ""
PASS = os.environ.get("LLMGRAPHS_PASS") or ""
if not USER or not PASS:
    raise SystemExit("LLMGRAPHS_USER/LLMGRAPHS_PASS must be set (see .env)")

CACHE_TTL = 300
_cache = {"t": 0.0, "data": None}

app = Flask(__name__, static_folder=os.path.join(HERE, "static"))

LAT_BUCKETS = [(500, "<0.5s"), (1000, "0.5-1s"), (2000, "1-2s"), (5000, "2-5s"),
               (10000, "5-10s"), (30000, "10-30s"), (60000, "30-60s"),
               (180000, "1-3m"), (float("inf"), ">3m")]
CTOK_BUCKETS = [(50, "<50"), (100, "50-100"), (250, "100-250"), (500, "250-500"),
                (1000, "500-1k"), (5000, "1-5k"), (10000, "5-10k"),
                (float("inf"), ">10k")]
TTFT_BUCKETS = [(100, "<100ms"), (250, "100-250ms"), (500, "250-500ms"),
                (1000, "0.5-1s"), (2000, "1-2s"), (5000, "2-5s"),
                (float("inf"), ">5s")]


def bucketize(vals_sql, buckets):
    """vals_sql yields (bucket_value,) -> (labels, counts)."""
    counts = [0] * len(buckets)
    for (v,) in vals_sql:
        if v is None:
            continue
        for i, (hi, _) in enumerate(buckets):
            if v < hi:
                counts[i] += 1
                break
    return [lab for _, lab in buckets], counts


def pctl(vals, p):
    if not vals:
        return None
    vals = sorted(vals)
    k = (len(vals) - 1) * p / 100.0
    f, c = math.floor(k), math.ceil(k)
    if f == c:
        return round(vals[int(k)], 1)
    return round(vals[f] + (vals[c] - vals[f]) * (k - f), 1)


def pivot(rows, top=10, other="other"):
    """rows of (day, key, value) -> (days, keys, series dict) with a
    contiguous day axis and a collapsed long tail."""
    days = sorted({r[0] for r in rows})
    totals = {}
    for _, k, v in rows:
        totals[k] = totals.get(k, 0) + (v or 0)
    keys = [k for k, _ in sorted(totals.items(), key=lambda kv: -kv[1])[:top]
            if k]
    tail = [k for k in totals if k not in keys]
    if tail:
        keys.append(other)
    series = {k: [0] * len(days) for k in keys}
    idx = {d: i for i, d in enumerate(days)}
    for d, k, v in rows:
        if k not in series:
            k = other
        series[k][idx[d]] = v or 0
    return days, keys, series


SEED_SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    name TEXT PRIMARY KEY, kind TEXT NOT NULL, n_calls INTEGER NOT NULL DEFAULT 0,
    indexed REAL NOT NULL);
CREATE TABLE IF NOT EXISTS calls (
    ts REAL, trace_id TEXT, workflow TEXT, model TEXT, provider TEXT,
    prompt_tokens INTEGER, completion_tokens INTEGER, total_tokens INTEGER,
    duration_ms REAL, status TEXT, cache_read INTEGER);
"""


def conn():
    if not os.path.exists(DB_MAIN):
        # index hasn't produced anything yet; serve empty states instead of 503
        seed = sqlite3.connect(DB_MAIN, timeout=30)
        try:
            seed.executescript(SEED_SCHEMA)
            seed.commit()
        finally:
            seed.close()
    c = sqlite3.connect(f"file:{DB_MAIN}?mode=ro", uri=True, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA query_only=1")
    # snapshot DBs are read via schema-qualified names (llmproxy.lusage,
    # orlogs.ospans); attach readonly when they exist yet
    for alias, path in (("llmproxy", DB_LLMPROXY), ("orlogs", DB_ORLOGS)):
        if os.path.exists(path):
            c.execute("ATTACH DATABASE ? AS " + alias,
                      (f"file:{path}?mode=ro",))
    return c


def section_a(c):
    q = c.execute
    k = q("SELECT COUNT(*) n, SUM(total_tokens) tok, SUM(prompt_tokens) pt,"
          " SUM(completion_tokens) ct, MIN(ts) f, MAX(ts) l,"
          " COUNT(DISTINCT model) m, SUM(status='error') e,"
          " AVG(duration_ms) ams FROM calls").fetchone()
    traces = q("SELECT COUNT(*) FROM files WHERE kind='ok'").fetchone()[0]
    if not k["n"]:
        return {"empty": True, "traces": traces}
    days_all = [r[0] for r in q("SELECT DISTINCT date(ts,'unixepoch') d FROM calls")]

    cw = pivot(q("SELECT date(ts,'unixepoch') d, workflow, COUNT(*) n FROM calls"
                 " GROUP BY d, workflow").fetchall(), top=8)
    td = q("SELECT date(ts,'unixepoch') d, SUM(prompt_tokens) p,"
           " SUM(completion_tokens) ct FROM calls GROUP BY d").fetchall()
    mt = q("SELECT model, COUNT(*) n, SUM(total_tokens) t FROM calls"
           " GROUP BY model ORDER BY n DESC").fetchall()
    top_models = [r["model"] for r in mt[:8]]
    mtime_rows = q("SELECT date(ts,'unixepoch') d, model, COUNT(*) n FROM calls"
                   " GROUP BY d, model").fetchall()
    mtime_rows = [(d, m if m in top_models else "other", n) for d, m, n in mtime_rows]
    mtime = pivot(mtime_rows, top=9)
    # NOT INDEXED on purpose: grouping by workflow would otherwise use
    # idx_calls_wf, which does not cover model/total_tokens -- sqlite then
    # probes the table by rowid once per call row in near-random order, and
    # with the box swapping that is ~35s instead of a ~0.7s sequential scan.
    wm = q("SELECT workflow, model, COUNT(*) n, SUM(total_tokens) t"
           " FROM calls NOT INDEXED"
           " GROUP BY workflow, model").fetchall()
    lh = bucketize(q("SELECT duration_ms FROM calls").fetchall(), LAT_BUCKETS)
    lat = {}
    for r in q("SELECT date(ts,'unixepoch') d, duration_ms FROM calls").fetchall():
        lat.setdefault(r[0], []).append(r[1])
    ed = q("SELECT date(ts,'unixepoch') d, COUNT(*) n, SUM(status='error') e"
           " FROM calls GROUP BY d ORDER BY d").fetchall()
    em = q("SELECT model, COUNT(*) n, SUM(status='error') e FROM calls"
           " GROUP BY model HAVING e > 0 ORDER BY e DESC LIMIT 12").fetchall()
    wh = q("SELECT CAST(strftime('%w', ts, 'unixepoch') AS INT) w,"
           " CAST(strftime('%H', ts, 'unixepoch') AS INT) h, COUNT(*) n"
           " FROM calls GROUP BY w, h").fetchall()
    cal = q("SELECT date(ts,'unixepoch') d, COUNT(*) n FROM calls GROUP BY d"
            " ORDER BY d").fetchall()
    sc = q("SELECT ts, total_tokens, duration_ms, workflow FROM calls"
           " WHERE rowid % 37 = 0 LIMIT 9000").fetchall()
    ch = bucketize(q("SELECT completion_tokens FROM calls").fetchall(), CTOK_BUCKETS)
    life = q("SELECT model, MIN(ts) f, MAX(ts) l FROM calls GROUP BY model"
             " ORDER BY COUNT(*) DESC LIMIT 15").fetchall()
    cache = q("SELECT date(ts,'unixepoch') d, SUM(cache_read) c,"
              " SUM(prompt_tokens) p FROM calls WHERE cache_read IS NOT NULL"
              " GROUP BY d ORDER BY d").fetchall()

    # radar: workflows on calls/day, tokens/day, latency, error rate
    wfs = [r[0] for r in q("SELECT workflow, COUNT(*) n FROM calls GROUP BY"
                           " workflow ORDER BY n DESC LIMIT 6")]
    radar = {}
    for wf in wfs:
        # NOT INDEXED for the same reason as wm above: for a big workflow the
        # idx_calls_wf prefix walks every row of it by rowid (~21s for
        # llmproxy's 350k rows); a sequential scan over all of calls is ~0.3s.
        r = q("SELECT COUNT(*) n, SUM(total_tokens) t, AVG(duration_ms) ams,"
              " 100.0*SUM(status='error')/COUNT(*) e,"
              " COUNT(DISTINCT date(ts,'unixepoch')) days"
              " FROM calls NOT INDEXED WHERE workflow=?", (wf,)).fetchone()
        radar[wf] = [r["n"] / max(r["days"], 1), (r["t"] or 0) / max(r["days"], 1),
                     r["ams"] or 0, r["e"] or 0.0]
    rmax = [max((radar[w][i] for w in radar), default=1) or 1 for i in range(4)]

    return {
        "kpis": {"calls": k["n"], "tokens": k["tok"], "prompt": k["pt"],
                 "completion": k["ct"], "models": k["m"], "errors": k["e"],
                 "avg_ms": round(k["ams"] or 0), "traces": traces,
                 "first": k["f"], "last": k["l"], "days": len(days_all)},
        "calls_day": {"days": cw[0], "keys": cw[1], "series": cw[2]},
        "tokens_day": {"days": [r["d"] for r in td],
                       "prompt": [r["p"] or 0 for r in td],
                       "completion": [r["ct"] or 0 for r in td]},
        "model_calls": [[r["model"], r["n"]] for r in mt[:12]],
        "model_tokens": [[r["model"], r["t"] or 0] for r in mt[:12]],
        "model_time": {"days": mtime[0], "keys": mtime[1], "series": mtime[2]},
        "wf_model": [[r["workflow"], r["model"], r["n"], r["t"] or 0] for r in wm],
        "lat_hist": {"labels": lh[0], "counts": lh[1]},
        "lat_day": {"days": sorted(lat),
                    "p50": [pctl(lat[d], 50) for d in sorted(lat)],
                    "p95": [pctl(lat[d], 95) for d in sorted(lat)]},
        "err_day": {"days": [r["d"] for r in ed],
                    "rate": [round(100.0 * (r["e"] or 0) / r["n"], 2) for r in ed]},
        "err_model": {"models": [r["model"] for r in em],
                      "counts": [r["e"] for r in em],
                      "rates": [round(100.0 * r["e"] / r["n"], 1) for r in em]},
        "heat_wh": [[r["h"], (r["w"] + 6) % 7, r["n"]] for r in wh],
        "calendar": [[r["d"], r["n"]] for r in cal],
        "scatter": [[r["ts"], r["total_tokens"] or 0, round(r["duration_ms"] or 0),
                     r["workflow"]] for r in sc],
        "ctok_hist": {"labels": ch[0], "counts": ch[1]},
        "lifespans": {"models": [r["model"] for r in life],
                      "span": [[round(r["f"]), round(r["l"])] for r in life]},
        "radar": {"indicators": ["calls/day", "tokens/day", "avg latency",
                                 "error rate %"],
                  "max": rmax, "series": radar},
        "cache_day": {"days": [r["d"] for r in cache],
                      "share": [round(100.0 * r["c"] / r["p"], 1) if r["p"] else 0
                                for r in cache]},
    }


def section_b(c):
    if not os.path.exists(DB_LLMPROXY):
        return {"empty": True}
    k = c.execute("SELECT COUNT(*) n, SUM(cost_usd) cost,"
                  " SUM(cost_usd IS NOT NULL) priced, COUNT(DISTINCT model) m,"
                  " MIN(ts) f, MAX(ts) l FROM llmproxy.lusage").fetchone()
    if not k["n"]:
        return {"empty": True}
    sd = c.execute("SELECT date(ts,'unixepoch') d, SUM(cost_usd) cost, COUNT(*) n"
                   " FROM llmproxy.lusage GROUP BY d ORDER BY d").fetchall()
    cm = c.execute("SELECT model, SUM(cost_usd) cost FROM llmproxy.lusage"
                   " WHERE cost_usd IS NOT NULL GROUP BY model"
                   " ORDER BY cost DESC LIMIT 15").fetchall()
    ps = c.execute("SELECT provider, SUM(cost_usd) cost FROM llmproxy.lusage"
                   " WHERE cost_usd IS NOT NULL GROUP BY provider"
                   " ORDER BY cost DESC").fetchall()
    tc = c.execute("SELECT model, SUM(total_tokens) t, SUM(cost_usd) c, COUNT(*) n"
                   " FROM llmproxy.lusage GROUP BY model HAVING c IS NOT NULL"
                   " AND c > 0 ORDER BY c DESC LIMIT 15").fetchall()
    sk = c.execute("SELECT COALESCE(key_label,'?') lbl, SUM(cost_usd) cost"
                   " FROM llmproxy.lusage WHERE cost_usd IS NOT NULL"
                   " GROUP BY lbl ORDER BY cost DESC LIMIT 15").fetchall()
    top = [r[0] for r in c.execute("SELECT model FROM llmproxy.lusage"
                                   " GROUP BY model ORDER BY COUNT(*) DESC"
                                   " LIMIT 10").fetchall()]
    marks = ",".join("?" * len(top))
    lat = {}
    for m, lms, tms in c.execute(f"SELECT model, latency_ms, ttfb_ms FROM"
                                 f" llmproxy.lusage WHERE model IN ({marks})"
                                 f" AND (latency_ms IS NOT NULL OR ttfb_ms IS NOT"
                                 f" NULL)", top):
        lat.setdefault(m, [[], []])
        if lms is not None:
            lat[m][0].append(lms)
        if tms is not None:
            lat[m][1].append(tms)
    ep = c.execute("SELECT date(ts,'unixepoch') d, provider, COUNT(*) e FROM"
                   " llmproxy.lusage WHERE status >= 400 OR error IS NOT NULL"
                   " GROUP BY d, provider").fetchall()
    provs = sorted({r["provider"] for r in ep},
                   key=lambda p: -sum(r["e"] for r in ep if r["provider"] == p))[:6]
    ep = [r for r in ep if r["provider"] in provs]
    return {
        "kpis": {"requests": k["n"], "spend": round(k["cost"] or 0, 2),
                 "priced": k["priced"], "models": k["m"],
                 "first": k["f"], "last": k["l"]},
        "spend_day": {"days": [r["d"] for r in sd],
                      "cost": [round(r["cost"] or 0, 4) for r in sd],
                      "requests": [r["n"] for r in sd]},
        "cost_model": {"models": [r["model"] for r in cm],
                       "cost": [round(r["cost"] or 0, 4) for r in cm]},
        "provider_share": [[r["provider"], round(r["cost"] or 0, 4)] for r in ps],
        "tok_cost": [[r["model"], r["t"] or 0, round(r["c"] or 0, 4), r["n"]]
                     for r in tc],
        "lat_model": {"models": top,
                      "p50": [pctl(lat[m][0], 50) for m in top],
                      "p95": [pctl(lat[m][0], 95) for m in top],
                      "t_p50": [pctl(lat[m][1], 50) for m in top],
                      "t_p95": [pctl(lat[m][1], 95) for m in top]},
        "spend_key": {"labels": [r["lbl"] for r in sk],
                      "cost": [round(r["cost"] or 0, 4) for r in sk]},
        "err_heat": {"days": sorted({r["d"] for r in ep}),
                     "providers": provs,
                     "data": [[r["d"], r["provider"], r["e"]] for r in ep]},
    }


def section_c(c):
    if not os.path.exists(DB_ORLOGS):
        return {"empty": True}
    k = c.execute("SELECT COUNT(*) n, SUM(cost_total) cost, SUM(in_tokens) it,"
                  " SUM(out_tokens) ot, AVG(first_token_ms) ttft, MIN(ts) f,"
                  " MAX(ts) l, SUM(byok=1) byok FROM orlogs.ospans").fetchone()
    if not k["n"]:
        return {"empty": True}
    sd = c.execute("SELECT date(ts,'unixepoch') d,"
                   " SUM(COALESCE(cost_cache_read,0)+COALESCE(cost_non_cache,0)) i,"
                   " SUM(COALESCE(cost_output,0)) o,"
                   " SUM(COALESCE(cost_platform,0)) p,"
                   " SUM(COALESCE(cost_total,0)) t, COUNT(*) n"
                   " FROM orlogs.ospans GROUP BY d ORDER BY d").fetchall()
    cm = c.execute("SELECT model, SUM(COALESCE(cost_cache_read,0)) cr,"
                   " SUM(COALESCE(cost_non_cache,0)) nc,"
                   " SUM(COALESCE(cost_output,0)) o,"
                   " SUM(COALESCE(cost_platform,0)) p,"
                   " SUM(COALESCE(cost_total,0)) t FROM orlogs.ospans"
                   " GROUP BY model ORDER BY t DESC LIMIT 12").fetchall()
    ps = c.execute("SELECT provider, SUM(COALESCE(cost_total,0)) c, COUNT(*) n"
                   " FROM orlogs.ospans GROUP BY provider ORDER BY c DESC"
                   " LIMIT 12").fetchall()
    tc = c.execute("SELECT model, SUM(COALESCE(in_tokens,0)+COALESCE(out_tokens,0))"
                   " tok, SUM(COALESCE(cost_total,0)) c, COUNT(*) n FROM orlogs.ospans"
                   " GROUP BY model ORDER BY c DESC LIMIT 15").fetchall()
    top = [r[0] for r in c.execute("SELECT model FROM orlogs.ospans GROUP BY model"
                                   " ORDER BY COUNT(*) DESC LIMIT 8").fetchall()]
    marks = ",".join("?" * len(top))
    rp = {}
    for m, rms, pms in c.execute(f"SELECT model, router_ms, provider_ms FROM"
                                 f" orlogs.ospans WHERE model IN ({marks})", top):
        rp.setdefault(m, [[], []])
        if rms is not None:
            rp[m][0].append(rms)
        if pms is not None:
            rp[m][1].append(pms)
    ttft = bucketize(c.execute("SELECT first_token_ms FROM orlogs.ospans").fetchall(),
                     TTFT_BUCKETS)
    it = c.execute("SELECT model, AVG(inter_token_ms) a, COUNT(*) n FROM orlogs.ospans"
                   " WHERE inter_token_ms IS NOT NULL GROUP BY model"
                   " ORDER BY n DESC LIMIT 10").fetchall()
    at = c.execute("SELECT COALESCE(attempt_count,1) a, COUNT(*) n FROM orlogs.ospans"
                   " GROUP BY a ORDER BY a LIMIT 6").fetchall()
    st = c.execute("SELECT COALESCE(streamed, -1) s, COUNT(*) n FROM orlogs.ospans"
                   " GROUP BY s").fetchall()
    ep = c.execute("SELECT date(ts,'unixepoch') d, provider, COUNT(*) e FROM"
                   " orlogs.ospans WHERE status='error' GROUP BY d, provider").fetchall()
    provs_e = sorted({r["provider"] for r in ep},
                     key=lambda p: -sum(r["e"] for r in ep if r["provider"] == p))[:6]
    ep = [r for r in ep if r["provider"] in provs_e]
    sk = c.execute("SELECT COALESCE(api_key_label,'?') lbl,"
                   " SUM(COALESCE(cost_total,0)) c, COUNT(*) n FROM orlogs.ospans"
                   " GROUP BY lbl ORDER BY c DESC LIMIT 12").fetchall()
    er = c.execute("SELECT COALESCE(endpoint_region,'?') r, COUNT(*) n,"
                   " SUM(COALESCE(cost_total,0)) c FROM orlogs.ospans"
                   " GROUP BY r ORDER BY n DESC LIMIT 8").fetchall()
    dr = c.execute("SELECT COALESCE(data_region,'?') r, COUNT(*) n FROM orlogs.ospans"
                   " GROUP BY r ORDER BY n DESC LIMIT 8").fetchall()
    return {
        "kpis": {"requests": k["n"], "spend": round(k["cost"] or 0, 4),
                 "in_tokens": k["it"], "out_tokens": k["ot"],
                 "ttft": round(k["ttft"] or 0), "byok": k["byok"],
                 "first": k["f"], "last": k["l"]},
        "spend_day": {"days": [r["d"] for r in sd],
                      "input": [round(r["i"] or 0, 4) for r in sd],
                      "output": [round(r["o"] or 0, 4) for r in sd],
                      "platform": [round(r["p"] or 0, 4) for r in sd],
                      "total": [round(r["t"] or 0, 4) for r in sd],
                      "requests": [r["n"] for r in sd]},
        "cost_model": {"models": [r["model"] for r in cm],
                       "cache": [round(r["cr"] or 0, 4) for r in cm],
                       "noncache": [round(r["nc"] or 0, 4) for r in cm],
                       "output": [round(r["o"] or 0, 4) for r in cm],
                       "platform": [round(r["p"] or 0, 4) for r in cm]},
        "provider_share": [[r["provider"], round(r["c"] or 0, 4)] for r in ps],
        "tok_cost": [[r["model"], r["tok"] or 0, round(r["c"] or 0, 4), r["n"]]
                     for r in tc],
        "router_provider": {"models": top,
                            "r_p50": [pctl(rp[m][0], 50) for m in top],
                            "r_p95": [pctl(rp[m][0], 95) for m in top],
                            "p_p50": [pctl(rp[m][1], 50) for m in top],
                            "p_p95": [pctl(rp[m][1], 95) for m in top]},
        "ttft_hist": {"labels": ttft[0], "counts": ttft[1]},
        "inter_token": {"models": [r["model"] for r in it],
                        "avg": [round(r["a"] or 0, 1) for r in it]},
        "attempts": {"n": [r["a"] for r in at], "counts": [r["n"] for r in at]},
        "streamed": [[("streamed" if r["s"] == 1 else
                       "not streamed" if r["s"] == 0 else "unknown"), r["n"]]
                     for r in st],
        "err_heat": {"days": sorted({r["d"] for r in ep}),
                     "providers": provs_e,
                     "data": [[r["d"], r["provider"], r["e"]] for r in ep]},
        "spend_key": {"labels": [r["lbl"] for r in sk],
                      "cost": [round(r["c"] or 0, 4) for r in sk],
                      "requests": [r["n"] for r in sk]},
        "regions": {"endpoint": [[r["r"], r["n"], round(r["c"] or 0, 4)] for r in er],
                    "data": [[r["r"], r["n"]] for r in dr]},
    }


def build_data():
    c = conn()
    try:
        return {
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "a": section_a(c),
            "b": section_b(c),
            "c": section_c(c),
        }
    finally:
        c.close()


@app.before_request
def require_login():
    auth = request.authorization
    if not auth or not secrets.compare_digest(auth.username or "", USER) \
            or not secrets.compare_digest(auth.password or "", PASS):
        return Response("llmgraphs: auth required\n", 401,
                        {"WWW-Authenticate": 'Basic realm="llmgraphs"'})


@app.get("/healthz")
def healthz():
    return "ok\n"


@app.get("/api/data")
def api_data():
    now = time.time()
    if _cache["data"] is None or now - _cache["t"] > CACHE_TTL:
        try:
            _cache["data"] = build_data()
            _cache["t"] = now
        except sqlite3.Error as e:
            return Response(f"database not ready: {e}\n", 503)
    return _cache["data"]


@app.get("/")
def index():
    return Response(PAGE.replace("__FRESH__", str(int(CACHE_TTL / 60))),
                    mimetype="text/html")


# --------------------------------------------------------------------------
# the page: dark theme, one grid of cards, ECharts vendored locally.
# Plain string on purpose (no format()/Jinja) — braces below are literal JS.
# --------------------------------------------------------------------------
PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>llmgraphs · inbox.li</title>
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<link rel="icon" type="image/x-icon" href="/static/favicon.ico">
<script src="/static/echarts.min.js"></script>
<style>
:root{--bg:#0d1117;--card:#161b22;--edge:#21262d;--txt:#c9d1d9;--dim:#8b949e;
      --acc:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
     font:14px/1.45 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
header{position:sticky;top:0;z-index:9;background:rgba(13,17,23,.94);
       border-bottom:1px solid var(--edge);padding:10px 18px;
       display:flex;flex-wrap:wrap;gap:8px;align-items:baseline}
header h1{font-size:17px;margin:0 14px 0 0}
header h1 b{color:var(--acc)}
header .nav a{color:var(--dim);text-decoration:none;margin-right:12px;font-size:13px}
header .nav a:hover{color:var(--acc)}
#fresh{margin-left:auto;color:var(--dim);font-size:12px}
main{padding:16px;max-width:1700px;margin:0 auto}
h2.sec{border-bottom:1px solid var(--edge);padding-bottom:6px;margin:26px 0 4px;
       font-size:15px;color:var(--acc)}
h2.sec small{color:var(--dim);font-weight:400;margin-left:10px}
.kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
.kpi{background:var(--card);border:1px solid var(--edge);border-radius:8px;
     padding:8px 14px;min-width:110px}
.kpi .v{font-size:19px;font-weight:600;color:var(--acc)}
.kpi .l{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.4px}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}
.card{background:var(--card);border:1px solid var(--edge);border-radius:8px;
      padding:10px 12px 6px;min-width:0}
.card h3{margin:2px 0 6px;font-size:13px;font-weight:600;color:var(--txt)}
.card h3 small{color:var(--dim);font-weight:400}
.w3{grid-column:span 3}.w4{grid-column:span 4}.w5{grid-column:span 5}
.w6{grid-column:span 6}.w8{grid-column:span 8}.w12{grid-column:span 12}
.chart{width:100%;height:300px}
.h340{height:340px}.h380{height:380px}
@media(max-width:1200px){.w3,.w4{grid-column:span 6}}
@media(max-width:820px){.w3,.w4,.w5,.w6,.w8{grid-column:span 12}}
footer{color:var(--dim);font-size:12px;padding:18px;border-top:1px solid var(--edge);
       margin-top:26px}
</style></head><body>
<header>
  <h1><b>llmgraphs</b> · LLM usage across inbox.li</h1>
  <nav class="nav">
    <a href="#a">A · internal calls</a><a href="#b">B · llmproxy cost</a>
    <a href="#c">C · OpenRouter</a>
  </nav>
  <span id="fresh">data refreshed every __FRESH__ min</span>
</header>
<main>
  <div class="kpis" id="kpis"></div>

  <h2 class="sec" id="a">A · Internal LLM calls <small>— llmtrace traces (all workflows)</small></h2>
  <div class="grid">
    <div class="card w8"><h3>LLM calls per day <small>by workflow</small></h3><div id="a-calls-day" class="chart"></div></div>
    <div class="card w4"><h3>Calls by model <small>share, top 12</small></h3><div id="a-model-calls" class="chart"></div></div>
    <div class="card w6"><h3>Tokens per day <small>prompt vs completion</small></h3><div id="a-tokens-day" class="chart"></div></div>
    <div class="card w6"><h3>Model share by tokens <small>treemap</small></h3><div id="a-model-tokens" class="chart h340"></div></div>
    <div class="card w12"><h3>Top models over time <small>calls/day, stacked</small></h3><div id="a-model-time" class="chart h340"></div></div>
    <div class="card w6"><h3>Workflow → model <small>sunburst, sized by tokens</small></h3><div id="a-sunburst" class="chart h380"></div></div>
    <div class="card w6"><h3>Token flow <small>workflow → model sankey</small></h3><div id="a-sankey" class="chart h380"></div></div>
    <div class="card w4"><h3>Call latency distribution <small>log buckets</small></h3><div id="a-lat-hist" class="chart"></div></div>
    <div class="card w4"><h3>Daily latency <small>p50 / p95</small></h3><div id="a-lat-day" class="chart"></div></div>
    <div class="card w4"><h3>Error rate per day <small>% of calls</small></h3><div id="a-err-day" class="chart"></div></div>
    <div class="card w6"><h3>Errors by model <small>count + rate</small></h3><div id="a-err-model" class="chart"></div></div>
    <div class="card w6"><h3>Activity by weekday × hour <small>UTC</small></h3><div id="a-heat-wh" class="chart h340"></div></div>
    <div class="card w8"><h3>Calendar of call volume <small>per day</small></h3><div id="a-calendar" class="chart h340"></div></div>
    <div class="card w4"><h3>Completion size <small>tokens per call</small></h3><div id="a-ctok-hist" class="chart"></div></div>
    <div class="card w6"><h3>Duration vs tokens <small>sampled calls</small></h3><div id="a-scatter" class="chart h340"></div></div>
    <div class="card w6"><h3>Model lifespans <small>first → last seen, top 15</small></h3><div id="a-lifespan" class="chart h340"></div></div>
    <div class="card w5"><h3>Workflow radar <small>normalized profile</small></h3><div id="a-radar" class="chart h340"></div></div>
    <div class="card w4"><h3>Cache-read share <small>% of prompt tokens</small></h3><div id="a-cache" class="chart"></div></div>
    <div class="card w3"><h3>Calls by workflow <small>total</small></h3><div id="a-wf-share" class="chart"></div></div>
  </div>

  <h2 class="sec" id="b">B · llmproxy cost &amp; latency <small>— llmproxy.db (all providers, internal view)</small></h2>
  <div class="kpis" id="kpis-b"></div>
  <div class="grid">
    <div class="card w6"><h3>Spend per day <small>USD + requests</small></h3><div id="b-spend-day" class="chart"></div></div>
    <div class="card w6"><h3>Spend by model <small>USD, top 15</small></h3><div id="b-cost-model" class="chart"></div></div>
    <div class="card w4"><h3>Spend by provider <small>USD share</small></h3><div id="b-provider" class="chart"></div></div>
    <div class="card w4"><h3>Tokens vs cost <small>bubble = requests</small></h3><div id="b-tok-cost" class="chart h340"></div></div>
    <div class="card w4"><h3>Spend by API key <small>key_label</small></h3><div id="b-spend-key" class="chart"></div></div>
    <div class="card w6"><h3>Latency by model <small>p50 / p95 ms</small></h3><div id="b-lat-model" class="chart"></div></div>
    <div class="card w6"><h3>TTFB by model <small>p50 / p95 ms</small></h3><div id="b-ttfb-model" class="chart"></div></div>
    <div class="card w12"><h3>Errors by provider per day <small>heatmap</small></h3><div id="b-err-heat" class="chart h340"></div></div>
  </div>

  <h2 class="sec" id="c">C · OpenRouter billing <small>— orlogs broadcasts (billing view, live since 2026-11-06)</small></h2>
  <div class="kpis" id="kpis-c"></div>
  <div class="grid">
    <div class="card w6"><h3>Spend per day <small>cache / non-cache / output / platform</small></h3><div id="c-spend-day" class="chart"></div></div>
    <div class="card w6"><h3>Cost split by model <small>stacked USD</small></h3><div id="c-cost-model" class="chart"></div></div>
    <div class="card w4"><h3>Cost by provider <small>USD share</small></h3><div id="c-provider" class="chart"></div></div>
    <div class="card w4"><h3>Tokens vs cost <small>bubble = requests</small></h3><div id="c-tok-cost" class="chart h340"></div></div>
    <div class="card w4"><h3>Streamed share <small>requests</small></h3><div id="c-streamed" class="chart"></div></div>
    <div class="card w6"><h3>Router vs provider latency <small>p50 / p95 ms</small></h3><div id="c-router-provider" class="chart"></div></div>
    <div class="card w6"><h3>Time to first token <small>TTFT distribution</small></h3><div id="c-ttft-hist" class="chart"></div></div>
    <div class="card w4"><h3>Inter-token latency <small>avg ms by model</small></h3><div id="c-inter-token" class="chart"></div></div>
    <div class="card w4"><h3>Retry attempts <small>per request</small></h3><div id="c-attempts" class="chart"></div></div>
    <div class="card w4"><h3>Endpoint region <small>requests + cost</small></h3><div id="c-regions" class="chart"></div></div>
    <div class="card w6"><h3>Spend by API key <small>OpenRouter keys</small></h3><div id="c-spend-key" class="chart"></div></div>
    <div class="card w6"><h3>Errors by provider per day <small>heatmap</small></h3><div id="c-err-heat" class="chart"></div></div>
    <div class="card w6"><h3>Data region <small>requests</small></h3><div id="c-data-region" class="chart"></div></div>
    <div class="card w6"><h3>Cost per request by region <small>avg USD</small></h3><div id="c-region-eff" class="chart"></div></div>
  </div>
</main>
<footer id="foot">llmgraphs · internal analytics · sources: llmtrace (traces + archive), llmproxy.db, orlogs (openrouter.inbox.li)</footer>
<script>
"use strict";
const charts = [];
const PAL = ['#5b8ff9','#5ad8a6','#f6bd16','#e8684a','#6dc8ec','#9270ca','#ff9d4d',
             '#269a99','#ff99c3','#a0d911','#13c2c2','#722ed1','#fa8c16','#eb2f96',
             '#52c41a','#2f54eb','#faad14','#f5222d'];
const el = id => document.getElementById(id);
function show(id, opt){
  const dom = el(id); if(!dom) return;
  if(!opt.series || !opt.series.length ||
     opt.series.every(s => !s.data || !s.data.length)){ return empty(id); }
  const c = echarts.init(dom);
  opt.backgroundColor = 'transparent';
  opt.textStyle = {color:'#8b949e'};
  opt.tooltip = opt.tooltip || {trigger:'axis'};
  opt.legend = Object.assign({textStyle:{color:'#8b949e'},top:0,type:'scroll',
    pageTextStyle:{color:'#8b949e'},inactiveColor:'#3a4250'}, opt.legend||{});
  if(!opt.grid) opt.grid = {left:8,right:16,top:30,bottom:8,containLabel:true};
  c.setOption(opt); charts.push(c);
}
function empty(id, msg){
  const dom = el(id); if(!dom) return;
  const c = echarts.init(dom);
  c.setOption({graphic:[{type:'text',left:'center',top:'middle',
    style:{text:msg||'no data yet',fill:'#4b5563',fontSize:14}}]});
  charts.push(c);
}
const kfmt = n => n==null ? '-' : Math.abs(n)>=1e9 ? (n/1e9).toFixed(1)+'G'
  : Math.abs(n)>=1e6 ? (n/1e6).toFixed(1)+'M'
  : Math.abs(n)>=1e3 ? (n/1e3).toFixed(1)+'k' : String(n);
const mfmt = v => v==null ? '-' : '$' + (Math.abs(v)>=1000 ? kfmt(v) : v.toFixed(2));
const d10 = t => new Date(t*1000).toISOString().slice(0,10);

function kpis(elId, items){
  el(elId).innerHTML = items.map(([l,v]) =>
    '<div class="kpi"><div class="v">'+v+'</div><div class="l">'+l+'</div></div>').join('');
}

/* ---------- section A ---------- */
function drawA(a){
  if(a.empty){
    document.querySelector('#a').insertAdjacentHTML('afterend',
      '<p style="color:#4b5563">no indexed traces yet — the indexer may still be running.</p>');
    ['a-calls-day','a-model-calls','a-tokens-day','a-model-tokens','a-model-time',
     'a-sunburst','a-sankey','a-lat-hist','a-lat-day','a-err-day','a-err-model',
     'a-heat-wh','a-calendar','a-ctok-hist','a-scatter','a-lifespan','a-radar',
     'a-cache','a-wf-share'].forEach(id=>empty(id));
    return;
  }
  kpis('kpis', [
    ['LLM calls', kfmt(a.kpis.calls)], ['tokens', kfmt(a.kpis.tokens)],
    ['traces', kfmt(a.kpis.traces)], ['models', a.kpis.models],
    ['avg latency', a.kpis.avg_ms+' ms'],
    ['errors', kfmt(a.kpis.errors)], ['days', a.kpis.days],
    ['span', d10(a.kpis.first)+' → '+d10(a.kpis.last)],
  ]);
  show('a-calls-day', {xAxis:{type:'category',data:a.calls_day.days},
    yAxis:{type:'value',axisLabel:{formatter:kfmt}},
    series:a.calls_day.keys.map((k,i)=>({name:k,type:'bar',stack:'x',
      data:a.calls_day.series[k],color:PAL[i%PAL.length],
      emphasis:{focus:'series'}}))});
  show('a-model-calls', {tooltip:{trigger:'item',formatter:'{b}: {c} ({d}%)'},
    series:[{type:'pie',radius:['42%','70%'],
      data:a.model_calls.map(([m,n],i)=>({name:m,value:n,
        itemStyle:{color:PAL[i%PAL.length]}})),
      label:{color:'#8b949e',fontSize:10,formatter:'{b}\n{d}%'}}]});
  show('a-tokens-day', {xAxis:{type:'category',data:a.tokens_day.days},
    yAxis:{type:'value',axisLabel:{formatter:kfmt}},
    series:[{name:'prompt',type:'line',stack:'t',areaStyle:{opacity:.35},
      data:a.tokens_day.prompt,color:'#5b8ff9',symbol:'none'},
      {name:'completion',type:'line',stack:'t',areaStyle:{opacity:.45},
      data:a.tokens_day.completion,color:'#5ad8a6',symbol:'none'}]});
  show('a-model-tokens', {series:[{type:'treemap',roam:false,nodeClick:false,
    breadcrumb:{show:false},
    data:a.model_tokens.map(([m,t],i)=>({name:m,value:t,
      itemStyle:{color:PAL[i%PAL.length]}})),
    label:{color:'#0d1117',fontSize:10}}]});
  show('a-model-time', {xAxis:{type:'category',data:a.model_time.days},
    yAxis:{type:'value',axisLabel:{formatter:kfmt}},
    series:a.model_time.keys.map((k,i)=>({name:k,type:'line',stack:'m',
      areaStyle:{opacity:.3},symbol:'none',data:a.model_time.series[k],
      color:PAL[i%PAL.length]}))});
  const sb = {};
  a.wf_model.forEach(([wf,m,n,t]) => {
    (sb[wf] = sb[wf] || []).push({name:m,value:t||n});
  });
  show('a-sunburst', {tooltip:{},series:[{type:'sunburst',radius:['12%','90%'],
    data:Object.entries(sb).map(([wf,ch])=>({name:wf,children:ch})),
    label:{color:'#c9d1d9',fontSize:10,rotate:'radial'}}]});
  const sn_nodes = Object.keys(sb).concat(
    Object.values(sb).flatMap(ch=>ch.map(x=>x.name)));
  show('a-sankey', {series:[{type:'sankey',left:10,right:140,top:10,bottom:10,
    data:[...new Set(sn_nodes)].map(n=>({name:n})),
    links:Object.entries(sb).flatMap(([wf,ch])=>ch.map(x=>(
      {source:wf,target:x.name,value:x.value}))),
    label:{color:'#c9d1d9',fontSize:10},
    lineStyle:{color:'gradient',opacity:.3},emphasis:{focus:'adjacency'}}]});
  show('a-lat-hist', {xAxis:{type:'category',data:a.lat_hist.labels,
      axisLabel:{rotate:30}},
    yAxis:{type:'log',axisLabel:{formatter:kfmt}},
    series:[{type:'bar',data:a.lat_hist.counts,color:'#6dc8ec',
      barCategoryGap:'15%'}]});
  show('a-lat-day', {xAxis:{type:'category',data:a.lat_day.days},
    yAxis:{type:'value',name:'ms',nameTextStyle:{color:'#8b949e'}},
    series:[{name:'p50',type:'line',data:a.lat_day.p50,color:'#5ad8a6',symbol:'none'},
      {name:'p95',type:'line',data:a.lat_day.p95,color:'#e8684a',symbol:'none'}]});
  show('a-err-day', {xAxis:{type:'category',data:a.err_day.days},
    yAxis:{type:'value',axisLabel:{formatter:'{value}%'}},
    series:[{type:'line',data:a.err_day.rate,color:'#f85149',
      areaStyle:{opacity:.2},symbol:'none'}]});
  show('a-err-model', {grid:{left:8,right:56,top:10,bottom:8,containLabel:true},
    xAxis:{type:'value',axisLabel:{formatter:kfmt}},
    yAxis:{type:'category',data:a.err_model.models.slice().reverse(),
      axisLabel:{fontSize:10,width:150,overflow:'truncate'}},
    series:[{type:'bar',data:a.err_model.counts.slice().reverse(),color:'#f85149',
      label:{show:true,position:'right',color:'#8b949e',
      formatter:p=>' '+a.err_model.rates[a.err_model.models.length-1-p.dataIndex]+'%'}}]});
  show('a-heat-wh', {tooltip:{position:'top'},
    grid:{left:8,right:16,top:10,bottom:40,containLabel:true},
    xAxis:{type:'category',data:[...Array(24).keys()].map(h=>String(h).padStart(2,'0')),
      splitArea:{show:false}},
    yAxis:{type:'category',data:['Mon','Tue','Wed','Thu','Fri','Sat','Sun']},
    visualMap:{min:0,max:Math.max(...a.heat_wh.map(x=>x[2]),1),calculable:false,
      orient:'horizontal',left:'center',bottom:0,
      inRange:{color:['#161b22','#1d3a6b','#58a6ff','#c9e3ff']}},
    series:[{type:'heatmap',data:a.heat_wh}]});
  show('a-calendar', {tooltip:{},
    visualMap:{min:0,max:Math.max(...a.calendar.map(x=>x[1]),1),calculable:false,
      orient:'horizontal',left:'center',bottom:0,
      inRange:{color:['#161b22','#1d3a6b','#58a6ff','#c9e3ff']}},
    calendar:{range:[a.calendar[0][0], a.calendar[a.calendar.length-1][0]],
      cellSize:['auto',16],top:40,left:50,right:20,
      itemStyle:{color:'#161b22',borderColor:'#0d1117'},
      splitLine:{lineStyle:{color:'#30363d'}},
      dayLabel:{color:'#8b949e'},monthLabel:{color:'#8b949e'},
      yearLabel:{show:false}},
    series:[{type:'heatmap',coordinateSystem:'calendar',data:a.calendar}]});
  show('a-ctok-hist', {xAxis:{type:'category',data:a.ctok_hist.labels,
      axisLabel:{rotate:30}},
    yAxis:{type:'log',axisLabel:{formatter:kfmt}},
    series:[{type:'bar',data:a.ctok_hist.counts,color:'#9270ca',
      barCategoryGap:'15%'}]});
  const wfKeys = [...new Set(a.scatter.map(p=>p[3]))];
  show('a-scatter', {legend:{},tooltip:{},
    xAxis:{type:'value',name:'tokens',nameTextStyle:{color:'#8b949e'},
      axisLabel:{formatter:kfmt},scale:true},
    yAxis:{type:'value',name:'ms',nameTextStyle:{color:'#8b949e'},
      axisLabel:{formatter:kfmt},scale:true},
    series:wfKeys.map((wf,i)=>({name:wf,type:'scatter',symbolSize:4,
      data:a.scatter.filter(p=>p[3]===wf).map(p=>[p[1],p[2]]),
      itemStyle:{color:PAL[i%PAL.length],opacity:.55}}))});
  show('a-lifespan', {grid:{left:8,right:30,top:10,bottom:8,containLabel:true},
    xAxis:{type:'time'},
    yAxis:{type:'category',data:a.lifespans.models.slice().reverse(),
      axisLabel:{fontSize:10,width:150,overflow:'truncate'}},
    series:[{type:'bar',stack:'l',itemStyle:{color:'transparent'},barWidth:'55%',
      tooltip:{show:false},silent:true,
      data:a.lifespans.span.slice().reverse().map(s=>s[0]*1000)},
      {type:'bar',stack:'l',barWidth:'55%',color:'#58a6ff',
      data:a.lifespans.span.slice().reverse().map(s=>(s[1]-s[0])*1000)}]});
  show('a-radar', {tooltip:{},legend:{type:'scroll'},
    radar:{indicator:a.radar.indicators.map(n=>({name:n,max:100})),
      axisName:{color:'#8b949e',fontSize:10},
      splitLine:{lineStyle:{color:'#21262d'}},
      splitArea:{show:false},axisLine:{lineStyle:{color:'#21262d'}}},
    series:[{type:'radar',data:Object.entries(a.radar.series).map(([wf,v],i)=>(
      {name:wf,value:v.map((x,i)=>+(x/a.radar.max[i]*100).toFixed(1)),
      lineStyle:{color:PAL[i%PAL.length]},itemStyle:{color:PAL[i%PAL.length]},
      areaStyle:{opacity:.12}}))}]});
  show('a-cache', {xAxis:{type:'category',data:a.cache_day.days},
    yAxis:{type:'value',axisLabel:{formatter:'{value}%'},max:100},
    series:[{type:'line',data:a.cache_day.share,color:'#f6bd16',
      areaStyle:{opacity:.2},symbol:'none'}]});
  const wfTot = {};
  a.wf_model.forEach(([wf,,n]) => wfTot[wf]=(wfTot[wf]||0)+n);
  const wfe = Object.entries(wfTot).sort((x,y)=>y[1]-x[1]);
  show('a-wf-share', {tooltip:{trigger:'item',formatter:'{b}: {c} ({d}%)'},
    series:[{type:'pie',radius:'75%',
      data:wfe.map(([w,n],i)=>({name:w,value:n,
        itemStyle:{color:PAL[i%PAL.length]}})),
      label:{color:'#8b949e',fontSize:10,formatter:'{b}\n{d}%'}}]});
}

/* ---------- section B ---------- */
function drawB(b){
  const all = ['b-spend-day','b-cost-model','b-provider','b-tok-cost',
               'b-spend-key','b-lat-model','b-ttfb-model','b-err-heat'];
  if(b.empty){ all.forEach(id=>empty(id,'no llmproxy data yet')); return; }
  kpis('kpis-b', [
    ['requests', kfmt(b.kpis.requests)],
    ['spend', '$'+b.kpis.spend.toFixed(2)],
    ['priced requests', kfmt(b.kpis.priced)],
    ['models', b.kpis.models],
    ['window', d10(b.kpis.first)+' → '+d10(b.kpis.last)],
  ]);
  show('b-spend-day', {xAxis:{type:'category',data:b.spend_day.days},
    yAxis:[{type:'value',axisLabel:{formatter:v=>'$'+v}},
           {type:'value',axisLabel:{formatter:kfmt},splitLine:{show:false}}],
    series:[{name:'USD',type:'bar',data:b.spend_day.cost,color:'#5ad8a6'},
      {name:'requests',type:'line',yAxisIndex:1,data:b.spend_day.requests,
      color:'#5b8ff9',symbol:'none'}]});
  show('b-cost-model', {grid:{left:8,right:80,top:10,bottom:8,containLabel:true},
    xAxis:{type:'value',axisLabel:{formatter:v=>'$'+v}},
    yAxis:{type:'category',data:b.cost_model.models.slice().reverse(),
      axisLabel:{fontSize:10,width:180,overflow:'truncate'}},
    series:[{type:'bar',color:'#5ad8a6',data:b.cost_model.cost.slice().reverse(),
      label:{show:true,position:'right',color:'#8b949e',
      formatter:p=>mfmt(p.value)}}]});
  show('b-provider', {tooltip:{trigger:'item',formatter:'{b}: ${c} ({d}%)'},
    series:[{type:'pie',radius:['38%','68%'],
      data:b.provider_share.map(([p,c],i)=>({name:p,value:c,
        itemStyle:{color:PAL[i%PAL.length]}})),
      label:{color:'#8b949e',fontSize:10,formatter:'{b}\n{d}%'}}]});
  show('b-tok-cost', {tooltip:{formatter:p=>p.data[3]+': '+mfmt(p.data[2])},
    xAxis:{type:'value',name:'tokens',nameTextStyle:{color:'#8b949e'},
      axisLabel:{formatter:kfmt},scale:true},
    yAxis:{type:'value',name:'USD',nameTextStyle:{color:'#8b949e'},scale:true,
      axisLabel:{formatter:v=>'$'+v}},
    series:[{type:'scatter',data:b.tok_cost.map(r=>[r[1],r[2],r[3],r[0]]),
      symbolSize:d=>Math.max(8,Math.sqrt(d[3])*2),
      itemStyle:{color:'#5ad8a6',opacity:.7},
      label:{show:true,formatter:p=>p.data[3],position:'top',
        color:'#8b949e',fontSize:10}}]});
  show('b-spend-key', {grid:{left:8,right:80,top:10,bottom:8,containLabel:true},
    xAxis:{type:'value',axisLabel:{formatter:v=>'$'+v}},
    yAxis:{type:'category',data:b.spend_key.labels.slice().reverse(),
      axisLabel:{fontSize:10,width:160,overflow:'truncate'}},
    series:[{type:'bar',color:'#6dc8ec',data:b.spend_key.cost.slice().reverse(),
      label:{show:true,position:'right',color:'#8b949e',
      formatter:p=>mfmt(p.value)}}]});
  show('b-lat-model', {xAxis:{type:'category',data:b.lat_model.models,
      axisLabel:{rotate:25,fontSize:10,width:110,overflow:'truncate'}},
    yAxis:{type:'value',name:'ms',nameTextStyle:{color:'#8b949e'}},
    series:[{name:'p50',type:'bar',data:b.lat_model.p50,color:'#5b8ff9'},
      {name:'p95',type:'bar',data:b.lat_model.p95,color:'#e8684a'}]});
  show('b-ttfb-model', {xAxis:{type:'category',data:b.lat_model.models,
      axisLabel:{rotate:25,fontSize:10,width:110,overflow:'truncate'}},
    yAxis:{type:'value',name:'ms',nameTextStyle:{color:'#8b949e'}},
    series:[{name:'ttfb p50',type:'bar',data:b.lat_model.t_p50,color:'#9270ca'},
      {name:'ttfb p95',type:'bar',data:b.lat_model.t_p95,color:'#ff9d4d'}]});
  drawHeat('b-err-heat', b.err_heat);
}

/* ---------- section C ---------- */
function drawC(s){
  const all = ['c-spend-day','c-cost-model','c-provider','c-tok-cost',
               'c-streamed','c-router-provider','c-ttft-hist','c-inter-token',
               'c-attempts','c-regions','c-spend-key','c-err-heat',
               'c-data-region','c-region-eff'];
  if(s.empty){
    all.forEach(id=>empty(id,'no OpenRouter broadcasts yet — fills as orlogs receives them'));
    return;
  }
  kpis('kpis-c', [
    ['requests', kfmt(s.kpis.requests)],
    ['spend', '$'+s.kpis.spend.toFixed(2)],
    ['in tokens', kfmt(s.kpis.in_tokens)],
    ['out tokens', kfmt(s.kpis.out_tokens)],
    ['avg TTFT', s.kpis.ttft+' ms'],
    ['byok', kfmt(s.kpis.byok)],
    ['since', new Date(s.kpis.first*1000).toISOString().slice(0,16).replace('T',' ')],
  ]);
  show('c-spend-day', {xAxis:{type:'category',data:s.spend_day.days},
    yAxis:{type:'value',axisLabel:{formatter:v=>'$'+v}},
    series:[
      {name:'cache+input',type:'line',stack:'c',areaStyle:{opacity:.4},
        symbol:'none',data:s.spend_day.input,color:'#f6bd16'},
      {name:'output',type:'line',stack:'c',areaStyle:{opacity:.4},
        symbol:'none',data:s.spend_day.output,color:'#5b8ff9'},
      {name:'platform',type:'line',stack:'c',areaStyle:{opacity:.4},
        symbol:'none',data:s.spend_day.platform,color:'#9270ca'},
      {name:'total',type:'line',symbol:'none',lineStyle:{type:'dashed'},
        data:s.spend_day.total,color:'#c9d1d9'}]});
  show('c-cost-model', {legend:{},
    grid:{left:8,right:80,top:30,bottom:8,containLabel:true},
    xAxis:{type:'value',axisLabel:{formatter:v=>'$'+v}},
    yAxis:{type:'category',data:s.cost_model.models.slice().reverse(),
      axisLabel:{fontSize:10,width:180,overflow:'truncate'}},
    series:['cache','noncache','output','platform'].map((k,i)=>(
      {name:k,type:'bar',stack:'m',color:PAL[i+3],
      data:s.cost_model[k].slice().reverse()}))});
  show('c-provider', {tooltip:{trigger:'item',formatter:'{b}: ${c} ({d}%)'},
    series:[{type:'pie',radius:['38%','68%'],
      data:s.provider_share.map(([p,c],i)=>({name:p,value:c,
        itemStyle:{color:PAL[i%PAL.length]}})),
      label:{color:'#8b949e',fontSize:10,formatter:'{b}\n{d}%'}}]});
  show('c-tok-cost', {tooltip:{formatter:p=>p.data[3]+': '+mfmt(p.data[2])},
    xAxis:{type:'value',name:'tokens',nameTextStyle:{color:'#8b949e'},
      axisLabel:{formatter:kfmt},scale:true},
    yAxis:{type:'value',name:'USD',nameTextStyle:{color:'#8b949e'},scale:true,
      axisLabel:{formatter:v=>'$'+v}},
    series:[{type:'scatter',data:s.tok_cost.map(r=>[r[1],r[2],r[3],r[0]]),
      symbolSize:d=>Math.max(8,Math.sqrt(d[3])*2),
      itemStyle:{color:'#5b8ff9',opacity:.7},
      label:{show:true,formatter:p=>p.data[3],position:'top',
        color:'#8b949e',fontSize:10}}]});
  show('c-streamed', {tooltip:{trigger:'item'},
    series:[{type:'pie',radius:['38%','68%'],
      data:s.streamed.map(([n,v],i)=>({name:n,value:v,
        itemStyle:{color:i?'#30363d':'#58a6ff'}})),
      label:{color:'#8b949e',formatter:'{b}\n{d}%'}}]});
  show('c-router-provider', {legend:{},
    xAxis:{type:'category',data:s.router_provider.models,
      axisLabel:{rotate:25,fontSize:10,width:110,overflow:'truncate'}},
    yAxis:{type:'value',name:'ms',nameTextStyle:{color:'#8b949e'}},
    series:[{name:'router p50',type:'bar',data:s.router_provider.r_p50,color:'#5b8ff9'},
      {name:'router p95',type:'bar',data:s.router_provider.r_p95,color:'#a0d911'},
      {name:'provider p50',type:'bar',data:s.router_provider.p_p50,color:'#eb2f96'},
      {name:'provider p95',type:'bar',data:s.router_provider.p_p95,color:'#ff9d4d'}]});
  show('c-ttft-hist', {xAxis:{type:'category',data:s.ttft_hist.labels,
      axisLabel:{rotate:30}},
    yAxis:{type:'value',axisLabel:{formatter:kfmt}},
    series:[{type:'bar',data:s.ttft_hist.counts,color:'#269a99',
      barCategoryGap:'15%'}]});
  show('c-inter-token', {grid:{left:8,right:70,top:10,bottom:8,containLabel:true},
    xAxis:{type:'value',name:'ms'},
    yAxis:{type:'category',data:s.inter_token.models.slice().reverse(),
      axisLabel:{fontSize:10,width:180,overflow:'truncate'}},
    series:[{type:'bar',color:'#722ed1',
      data:s.inter_token.avg.slice().reverse(),
      label:{show:true,position:'right',color:'#8b949e',
      formatter:p=>p.value+' ms'}}]});
  show('c-attempts', {xAxis:{type:'category',data:s.attempts.n.map(String)},
    yAxis:{type:'log',axisLabel:{formatter:kfmt}},
    series:[{type:'bar',data:s.attempts.counts,color:'#fa8c16',
      barCategoryGap:'15%',
      label:{show:true,position:'top',color:'#8b949e'}}]});
  const regs = s.regions.endpoint;
  show('c-regions', {legend:{},xAxis:{type:'category',data:regs.map(r=>r[0])},
    yAxis:{type:'value',axisLabel:{formatter:kfmt}},
    series:[{name:'requests',type:'bar',data:regs.map(r=>r[1]),color:'#5b8ff9'},
      {name:'USD',type:'bar',data:regs.map(r=>+r[2].toFixed(3)),color:'#f6bd16'}]});
  show('c-spend-key', {grid:{left:8,right:80,top:10,bottom:8,containLabel:true},
    xAxis:{type:'value',axisLabel:{formatter:v=>'$'+v}},
    yAxis:{type:'category',data:s.spend_key.labels.slice().reverse(),
      axisLabel:{fontSize:10,width:150,overflow:'truncate'}},
    series:[{type:'bar',color:'#13c2c2',data:s.spend_key.cost.slice().reverse(),
      label:{show:true,position:'right',color:'#8b949e',
      formatter:p=>mfmt(p.value)}}]});
  drawHeat('c-err-heat', s.err_heat);
  show('c-data-region', {xAxis:{type:'category',data:s.regions.data.map(r=>r[0])},
    yAxis:{type:'value',axisLabel:{formatter:kfmt}},
    series:[{type:'bar',data:s.regions.data.map(r=>r[1]),color:'#6dc8ec'}]});
  show('c-region-eff', {xAxis:{type:'category',data:regs.map(r=>r[0])},
    yAxis:{type:'value',axisLabel:{formatter:v=>'$'+v}},
    series:[{type:'bar',
      data:regs.map(r=>+(r[2]/Math.max(r[1],1)).toFixed(4)),color:'#e8684a'}]});
}

function drawHeat(id, h){
  if(!h || !h.data || !h.data.length || !h.days.length){
    const dom = el(id); if(dom) empty(id, 'no errors recorded'); return;
  }
  const dIdx = {}; h.days.forEach((d,i)=>dIdx[d]=i);
  const pIdx = {}; h.providers.forEach((p,i)=>pIdx[p]=i);
  const data = h.data.map(([d,p,n])=>[dIdx[d], pIdx[p], n]);
  show(id, {tooltip:{position:'top'},
    grid:{left:8,right:16,top:10,bottom:40,containLabel:true},
    xAxis:{type:'category',data:h.days,
      axisLabel:{rotate:30,fontSize:10}},
    yAxis:{type:'category',data:h.providers,axisLabel:{fontSize:10}},
    visualMap:{min:0,max:Math.max(...data.map(x=>x[2]),1),calculable:false,
      orient:'horizontal',left:'center',bottom:0,
      inRange:{color:['#161b22','#6b2737','#f85149','#ffb3ad']}},
    series:[{type:'heatmap',data}]});
}

fetch('/api/data').then(r=>r.json()).then(data => {
  el('foot').textContent = 'llmgraphs · generated ' + data.generated +
    ' · sources: llmtrace (traces + archive), llmproxy.db, orlogs (openrouter.inbox.li)';
  drawA(data.a); drawB(data.b); drawC(data.c);
  window.addEventListener('resize', () => charts.forEach(c=>c.resize()));
});
</script></body></html>
"""

if __name__ == "__main__":
    try:
        from waitress import serve
        serve(app, host="127.0.0.1", port=PORT, threads=8)
    except ImportError:
        app.run(host="127.0.0.1", port=PORT)
