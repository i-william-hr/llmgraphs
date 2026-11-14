# llmgraphs

LLM usage analytics dashboard: https://llmgraphs.inbox.li (internal-only,
internal-CA cert, behind the central SSO). Graphs, nothing else.

Box-wide conventions: see [`[REDACTED:server-path]`](../AGENTS.md) —
git-as-owner, no public remotes, push via `push-to-gitea.sh`, nginx changes
only through `apply.sh`.

## What it does

Read-only aggregator + chart page over three sources it does not own:

| source | local file | written by |
|---|---|---|
| llmtrace traces | `data/llmgraphs.db` (`calls`) | `index_traces.py` scans `[REDACTED:server-path]` + `/server/storage/llmtrace-archive` (read via the `traces` group) |
| llmproxy usage | `data/llmproxy-usage.db` (`lusage`) | `snapshot_usage.py` (runs as root, keeps CAP_DAC_OVERRIDE) |
| OpenRouter broadcasts | `data/orlogs-usage.db` (`ospans`) | `snapshot_usage.py` re-extracts `[REDACTED:server-path]` by exact attr key — orlogs' own cost columns are heuristic and wrong for cache vs non-cache input |

All three targets live under `data/` — the only writable path. The trace
trees are opened read-only; nothing here ever writes to llmtrace, llmproxy or
orlogs.

Systemd: `[REDACTED:systemd-unit]` (web), `llmgraphs-index.{service,timer}`
(15 min), `llmgraphs-snapshot.{service,timer}` (hourly). Canonical unit files
in `[REDACTED:server-path]`, real-file copies in `/etc/systemd/system/` per
README-users.md.

No prompt/completion text is ever stored here — metadata only (models,
tokens, cost, latency, status).
