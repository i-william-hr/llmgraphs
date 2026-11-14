# llmgraphs — LLM usage analytics

> Built with Python · Shell · JavaScript (Python, Flask).

A read-only analytics dashboard with charts over three sources it does not own: llmtrace traces, llmproxy usage, and orlogs/OpenRouter spans. It shows metadata only — token counts, cost, latency, model mix — and never prompt text.

## Installation

```bash
git clone https://github.com/i-william-hr/llmgraphs.git
cd llmgraphs
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

## Usage

```bash
python3 app.py
```

The app.py entry point binds loopback only and expects a reverse proxy in front for TLS.

## Tests

```bash
python3 -m unittest discover
```

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).
