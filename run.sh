#!/bin/bash
# llmgraphs - LLM usage analytics graphs, port [REDACTED:loopback-port] (nginx: llmgraphs.inbox.li/)
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "Creating venv (uses system site packages)…"
    python3 -m venv venv --system-site-packages
fi
source venv/bin/activate

if [ -f .env ]; then
    set -a; source .env; set +a
fi

export PYTHONUNBUFFERED=1
exec python3 app.py
