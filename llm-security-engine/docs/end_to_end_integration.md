# End-to-End Integration Guide

This guide explains how to connect the TypeScript SOC API Server (`soc-backend/`) to the Python Local LLM Security Engine (`llm-security-engine/`).

There are two setups. **Start with Setup A** — it requires no extra tools and works on any developer machine.

---

## Setup A — Fully local (recommended for development)

Both services run on the same machine. The SOC backend calls the engine directly over localhost. No tunnel, no cloud account, no extra software.

```
Your machine
├── Terminal 1 → uvicorn (port 8000) ← Python engine + Ollama
├── Terminal 2 → pnpm run dev (port 3000) ← SOC API backend
└── Terminal 3 → curl http://localhost:3000/api/analyze ...
```

### Prerequisites

- Ollama installed and running (`ollama serve`)
- `phi4-mini` pulled (`ollama pull phi4-mini`)
- Python 3.10+ with engine dependencies installed (`pip install -r requirements.txt`)
- Node.js 20+ with SOC backend dependencies installed (`pnpm install`)

### Step 1 — Start the Python engine

```bash
cd llm-security-engine
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Verify:
```bash
curl http://localhost:8000/health
# Expected: "status": "ok", "ollama": {"reachable": true}
```

### Step 2 — Configure the SOC backend

In the `soc-backend/` directory, create `.env.local` (or edit it if it exists):

```env
PORT=3000
LOCAL_LLM_ENGINE_BASE_URL=http://localhost:8000
```

That is the entire configuration for local development. No API keys, no tunnel URL.

### Step 3 — Start the SOC backend

```bash
cd soc-backend
pnpm run dev
```

You should see:
```
{"level":"info","port":3000,"msg":"Server listening"}
```

### Step 4 — Verify the connection

Check that the SOC backend can reach the engine:

```bash
curl http://localhost:3000/api/provider-health
```

Expected:
```json
{
  "provider_mode": "local_security_engine",
  "configured_base_url": "http://localhost:8000",
  "engine_reachable": true,
  "engine_status": "ok",
  "model_name": "phi4-mini",
  "auth_configured": false,
  "engine_error": null
}
```

### Step 5 — Send a test analysis request

```bash
curl -X POST http://localhost:3000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "description": "57 failed SSH login attempts followed by one successful login from 185.220.101.1.",
    "source_ip": "185.220.101.1",
    "event_type": "authentication_failure",
    "severity": "high"
  }'
```

This takes 10–60 seconds while Ollama runs inference. Expected response:
```json
{
  "attack_classification": "credential_access",
  "risk_score": 88,
  "false_positive_likelihood": 0.05,
  "reason": "...",
  "fallback_used": false,
  "engine_reachable": true,
  "soc_provider_mode": "local_security_engine"
}
```

Key things to check:
- `engine_reachable: true` — the SOC backend reached the engine
- `fallback_used: false` — the full analysis pipeline worked
- `contract_validation_failed: false` — the response passed schema validation

The full request path: `curl → SOC backend (port 3000) → engine (port 8000) → Ollama (port 11434)`. Everything on localhost.

---

## Setup B — Remote SOC backend (advanced)

Use this only if the SOC backend is deployed to a server and the Python engine runs on a separate local machine. In this case the two services cannot communicate over localhost, so you need a tunnel.

```
Remote server              Cloudflare Tunnel       Your local machine
SOC backend (port 3000) → trycloudflare.com →  Python engine (port 8000)
                                                       │
                                                 Ollama (port 11434)
```

### When you need this

- SOC backend is running on a VPS, cloud instance, or any machine that is not the same as the one running Ollama
- You want to keep inference local (no cloud LLM costs, no data leaving your network)

### When you do NOT need this

- Both services are on the same machine → use Setup A

### Step 1 — Start the Python engine (on your local machine)

```bash
cd llm-security-engine
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Step 2 — Start the Cloudflare Tunnel (on your local machine)

Install `cloudflared` from [developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/).

```bash
cloudflared tunnel --url http://localhost:8000
```

Wait for a line like:
```
Your quick Tunnel has been created! Visit it at:
https://random-name.trycloudflare.com
```

Copy that URL.

> **The URL changes every restart.** For a stable URL, create a named tunnel with `cloudflared tunnel create my-engine`. See the [Cloudflare Tunnel docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/).

### Step 3 — Configure the SOC backend (on the remote server)

On the server where the SOC backend runs, set:

```env
LOCAL_LLM_ENGINE_BASE_URL=https://random-name.trycloudflare.com
```

Use `https://` — the tunnel only serves HTTPS.

If you want the engine to require authentication:
```env
LOCAL_LLM_ENGINE_API_KEY=your-secret-key   # must match engine's LOCAL_LLM_API_KEY
```

### Step 4 — Restart the SOC backend

Environment variables are only loaded at startup:

```bash
# Direct process:
Ctrl+C → restart

# systemd:
sudo systemctl restart soc-api-server

# NSSM (Windows):
nssm restart SocApiServer
```

### Step 5 — Verify

```bash
curl https://your-soc-server.example.com/api/provider-health
```

`engine_reachable` should be `true`. If it is `false`, the tunnel URL is wrong or the tunnel is not running.

---

## Environment variable reference

### Python engine (`llm-security-engine/.env`)

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `phi4-mini` | Model name |
| `OLLAMA_TIMEOUT` | `60` | Seconds to wait for Ollama |
| `LOCAL_LLM_API_KEY` | *(unset)* | If set, callers must send `X-API-Key` |
| `API_PORT` | `8000` | Engine listen port |

### SOC backend (`soc-backend/.env.local`)

| Variable | Default | Description |
|---|---|---|
| `PORT` | *(required)* | SOC backend listen port (e.g. `3000`) |
| `LOCAL_LLM_ENGINE_BASE_URL` | *(required for analysis)* | Engine URL (`http://localhost:8000` for local dev) |
| `LOCAL_LLM_ENGINE_API_KEY` | *(unset)* | Must match engine's `LOCAL_LLM_API_KEY` if set |
| `LOCAL_LLM_ENGINE_TIMEOUT_MS` | `90000` | Request timeout (ms) — increase for slow machines |
| `SOC_API_KEY` | *(unset)* | If set, callers to SOC backend must send `X-API-Key` |

---

## Debugging failures

### `engine_reachable: false` from `/api/provider-health`

1. Is the Python engine running? → `curl http://localhost:8000/health`
2. Is `LOCAL_LLM_ENGINE_BASE_URL` correct? → check `.env.local`
3. (Setup B only) Is the tunnel running and URL correct?
4. Did you restart the SOC backend after changing env vars?

### `fallback_used: true` with `engine_error` set

The engine was reachable but failed internally:
- `"connection refused"` → Ollama is not running → `ollama serve`
- `"timed out"` → Model is slow → increase `OLLAMA_TIMEOUT` in engine `.env`
- `"model not found"` → `ollama pull phi4-mini`

### `fallback_used: true`, `engine_reachable: false`

The SOC backend cannot reach the engine at all. Go back to Step 1.

### HTTP 503 from SOC backend

`LOCAL_LLM_ENGINE_BASE_URL` is not set. Add it to `.env.local` and restart.

### HTTP 401 / 403 from SOC backend

`SOC_API_KEY` is set but caller is missing `X-API-Key`. Either add the header or unset `SOC_API_KEY`.

### HTTP 401 from the engine (shows as `engine_error` in SOC response)

Engine has `LOCAL_LLM_API_KEY` set but SOC backend is not sending it. Add `LOCAL_LLM_ENGINE_API_KEY` to SOC backend `.env.local`.

---

## Testing auth end-to-end

If you have enabled authentication on both sides:

```bash
# Missing SOC key → 401
curl -X POST http://localhost:3000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"description": "test"}'

# Correct SOC key → 200 (engine key is forwarded transparently)
curl -X POST http://localhost:3000/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-soc-key" \
  -d '{"description": "SSH brute force from 185.220.101.1."}'
```
