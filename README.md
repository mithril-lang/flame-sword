# Flame Sword

Flame Sword is Mithril Fund's fork of [ARTEX](https://github.com/IlyassCODEX/ARTEX), named after the [mythological flaming sword](https://en.wikipedia.org/wiki/Flaming_sword_(mythology)). It retains ARTEX's reconnaissance modules and sends AI analysis requests to the Mithril inference API.

## Local setup

Use Python 3.11 and an installed `nmap` binary. On macOS, port 5000 is often used by AirPlay; this fork defaults to port 5055.

```sh
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -r requirements.txt
cp .env.example .env
.venv/bin/python app.py
```

Open http://127.0.0.1:5055. The server binds to loopback with the debugger disabled. This is a local development server; scan only systems you own or are authorized to assess.

On macOS, keep it running independently of the terminal with `./scripts/local-server.sh start`. Use `stop`, `restart`, or `status` to manage it. This uses a session-scoped launchd job; it does not install automatic login startup. Logs are in the ignored `.local/` directory. After adding a key to `.env`, use `./scripts/local-server.sh restart`.

## Mithril inference

Set `MITHRIL_API_KEY` in the ignored `.env` file or inject it through your secret manager. Do not commit credentials. Environment variables take precedence over `.env`. Restart the server after changing configuration.

For 1Password, set `MITHRIL_API_KEY_REF=op://vault/item/field` instead. The server calls `op read` at startup and keeps the resolved key in process memory. The CLI must be installed and authorized. A direct `MITHRIL_API_KEY` takes precedence. Resolution failures leave AI unconfigured without logging secret values or CLI output.

- API: `https://api.mithril.fund/v1/chat/completions`
- Default model: `qwen/qwen3.8-27b`; override with `MITHRIL_MODEL`.
- `FLAME_SWORD_PORT` overrides the local listening port.
- **Check connection** fetches the live model catalog. It does not prove authenticated inference or available AI credit.
- AI analysis sends condensed findings for the owner and hunter perspectives to Mithril. No findings are sent when the API key is missing or the `ai` scan option is false.
- Missing credentials, invalid responses and API failures use rule-based analysis with visible warnings. HTTP 401/403 means authentication or access must be checked; HTTP 429 requires checking credit and request limits. Requests are not automatically retried.

The server exposes credential-free configuration at `/api/mithril/status` and an explicit model-catalog check at `POST /api/mithril/check`.

## Verification

```sh
.venv/bin/python -m pytest -q
curl http://127.0.0.1:5055/health
curl -X POST http://127.0.0.1:5055/api/mithril/check
```

Catalog reachability, authenticated inference, and a completed target scan are separate checks. The upstream scanning heuristics and reports have not undergone a full accuracy or security audit.

## Upstream provenance

The initial fork preserves ARTEX at commit `a6d9650846bd1b743d03b26ebba46a16ffde3b06`. Original documentation is in [README.upstream.md](README.upstream.md). Upstream has no license file at that revision; this fork does not add or imply a new license for upstream code.
