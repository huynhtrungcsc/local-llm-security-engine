# End-to-End Integration Guide

This guide explains exactly how to connect the TypeScript SOC API Server to this Python Local LLM Security Engine running on your local machine. It covers startup order, required environment variables, how to verify each layer, and how to debug failures.

---

## Overview of what you are connecting

```
SOC API Server           Cloudflare Tunnel         Local LLM Security Engine
(your server)      →→→  (your machine)    →→→     (your machine, port 8000)
Express/TypeScript        HTTPS proxy               Python/FastAPI
                                                          │
                                                      Ollama (port 11434)
                                                          │
                                                      phi4-mini model
```

---

## Prerequisites

Before starting, confirm you have:

- [ ] Ollama installed and running on your local machine
- [ ] `phi4-mini` model pulled (`ollama pull phi4-mini`)
- [ ] Python 3.10+ and dependencies installed in `llm-security-engine/`
- [ ] `cloudflared` installed ([download here](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/))
- [ ] The SOC API Server (`soc-backend/`) deployed and running

---

## Required environment variables

### On your local machine — Local LLM Security Engine (`.env`)

```env
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=phi4-mini
OLLAMA_TIMEOUT=60

# Optional: enable auth so only your SOC backend can call the engine
# LOCAL_LLM_API_KEY=your-engine-secret-key
```

### On the SOC API Server — `soc-backend/`

Set these in the SOC backend's environment. Create or edit `.env.local` in the `soc-backend/` directory:

```env
# Required: the tunnel URL printed by cloudflared
LOCAL_LLM_ENGINE_BASE_URL=https://your-random-name.trycloudflare.com

# Required if LOCAL_LLM_API_KEY is set in the engine's .env
# LOCAL_LLM_ENGINE_API_KEY=your-engine-secret-key

# Optional: request timeout in milliseconds (default 90000 = 90s)
# LOCAL_LLM_ENGINE_TIMEOUT_MS=90000

# Optional: protect the SOC API with its own inbound key
# SOC_API_KEY=your-inbound-secret-key
```

When `LOCAL_LLM_ENGINE_BASE_URL` is set, the SOC backend automatically switches to `local_security_engine` mode. No need to set `PROVIDER_MODE` explicitly.

---

## Exact startup order

Start each component in this order. Each depends on the one before it.

### Step 1 — Start Ollama (if not already running)

On Windows, Ollama starts automatically as a background service after installation. Check the system tray.

On Linux/macOS, if Ollama is not already running:
```bash
ollama serve
```

Verify:
```bash
curl http://localhost:11434/api/tags
```
You should see a JSON response listing available models.

### Step 2 — Start the Local LLM Security Engine

```bash
cd llm-security-engine
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Verify:
```bash
curl http://localhost:8000/health
```

Expected: `"status": "ok"` and `"ollama": {"reachable": true}`.

If `ollama.reachable` is `false`, the engine cannot reach Ollama. Go back to Step 1.

### Step 3 — Start the Cloudflare Tunnel

In a separate terminal on your local machine:
```bash
cloudflared tunnel --url http://localhost:8000
```

Wait for output like:
```
2024-01-15T10:00:00Z INF +----------------------------+
2024-01-15T10:00:00Z INF |  Your quick Tunnel has been created! Visit it at  |
2024-01-15T10:00:00Z INF |  https://random-name.trycloudflare.com            |
+----------------------------+
```

Copy that URL. You will need it in the next step.

> **The tunnel URL changes every time you restart cloudflared.** For a stable URL that does not change between restarts, you can create a free named tunnel: install `cloudflared`, log in with `cloudflared login`, then create and run a named tunnel with `cloudflared tunnel create my-engine` and `cloudflared tunnel run my-engine`. See the [Cloudflare Tunnel docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/) for the full setup. For most development use, the quick tunnel is fine — just update the URL in the SOC backend's environment after each restart.

### Step 4 — Configure the SOC backend environment

On the machine where the SOC backend runs, open `soc-backend/.env.local` and set:

```env
LOCAL_LLM_ENGINE_BASE_URL=https://random-name.trycloudflare.com
```

Replace `random-name` with the actual subdomain printed by cloudflared in Step 3.

If you set `LOCAL_LLM_API_KEY` in the engine's `.env`, also add:

```env
LOCAL_LLM_ENGINE_API_KEY=your-engine-secret-key
```

### Step 5 — Restart the SOC API Server

Environment variables are only loaded when the server starts. After editing `.env.local`, restart the SOC backend process to pick up the new values:

```bash
# If running directly:
Ctrl+C   # stop
node dist/index.js   # or: pnpm run dev

# If running as a systemd service:
sudo systemctl restart soc-api-server

# If running as an NSSM service on Windows:
nssm restart SocApiServer
```

Within a few seconds the server restarts and picks up the new `LOCAL_LLM_ENGINE_BASE_URL`.

---

## Verification sequence

After all four components are running, verify from the outside in:

### 1. Verify Ollama is reachable from the engine

```bash
curl http://localhost:8000/debug/ping-ollama
```

Expected: `"reachable": true`, `"model_available": true`.

### 2. Verify the tunnel is reachable

```bash
curl https://your-random-name.trycloudflare.com/health
```

This should return the same response as calling the local health endpoint. If it times out or returns a Cloudflare error page, the tunnel is not running or the URL is wrong.

### 3. Verify the SOC backend can reach the engine

Call the SOC backend's provider-health endpoint. The URL depends on where your SOC backend is deployed:

```bash
curl https://your-soc-server.example.com/api/provider-health
```

Expected response:
```json
{
  "provider_mode": "local_security_engine",
  "configured_base_url": "https://your-random-name.trycloudflare.com",
  "engine_reachable": true,
  "engine_status": "ok",
  "model_name": "phi4-mini",
  "auth_configured": false,
  "latency_ms": 320.5,
  "engine_error": null
}
```

If `engine_reachable` is `false`, the SOC backend cannot reach the engine through the tunnel. Check the tunnel URL in the SOC backend's environment variables.

### 4. Verify a full analysis round-trip

```bash
curl -X POST https://your-soc-server.example.com/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-Request-ID: integration-test-001" \
  -d '{
    "description": "Outbound connection to known C2 domain every 60 seconds from internal workstation.",
    "source_ip": "10.0.0.45",
    "event_type": "dns_lookup",
    "severity": "high"
  }'
```

This request travels: your terminal → SOC backend → Cloudflare Tunnel → local engine → Ollama → back.

It will take 30–90 seconds on a CPU. Expected response:
```json
{
  "attack_classification": "command_and_control",
  "risk_score": 88,
  "fallback_used": false,
  "engine_reachable": true,
  "contract_validation_failed": false,
  "soc_provider_mode": "local_security_engine",
  "request_id": "integration-test-001",
  ...
}
```

Key things to check:
- `fallback_used: false` — the full analysis pipeline worked
- `engine_reachable: true` — the engine was reachable through the tunnel
- `contract_validation_failed: false` — the engine's response passed schema validation
- `soc_provider_mode: "local_security_engine"` — the SOC backend is in the right mode

---

## How to debug failures

### `engine_reachable: false` in `/api/provider-health`

The SOC backend cannot reach the engine. Check in order:
1. Is the engine running? (`curl http://localhost:8000/health` from your local machine)
2. Is the tunnel running? (`cloudflared tunnel --url http://localhost:8000` in terminal)
3. Is the tunnel URL correct in the SOC backend's environment? (It changes every time you restart cloudflared)
4. Did you restart the SOC API Server after updating the URL?

### `fallback_used: true` with `engine_error` set

The engine was reachable but failed internally. Check `engine_error`:

- `"Ollama connection refused"` → Start Ollama on your local machine
- `"Ollama request timed out"` → The model is slow. Increase `LOCAL_LLM_ENGINE_TIMEOUT_MS` in the SOC backend's environment (try `120000` for 2 minutes)
- `"Model 'phi4-mini' not found"` → Run `ollama pull phi4-mini`

### `contract_validation_failed: true`

The engine returned HTTP 200 but the response body did not match the expected schema. This usually means:
- The engine is running an old version that does not return all expected fields
- There is a version mismatch between the SOC backend and the engine

Check both are running the latest version of the code.

### HTTP 401 from the SOC backend

The caller is missing the `X-API-Key` header (if `SOC_API_KEY` is configured in the SOC backend).

### HTTP 401 from the engine (visible as `engine_error` in the SOC response)

The SOC backend is missing or sending the wrong `LOCAL_LLM_ENGINE_API_KEY`. Compare the value in the SOC backend's `.env.local` with `LOCAL_LLM_API_KEY` in the engine's `.env`.

### HTTP 429

Either the SOC backend or the engine is rate-limiting requests. Check:
- SOC backend environment for `RATE_LIMIT_MAX` and `RATE_LIMIT_WINDOW_MS`
- Engine `.env` for `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW_SECONDS`

---

## Common integration mistakes

**Forgetting to restart the SOC API Server after updating environment variables**

Environment variables are only loaded at startup. After changing any variable, restart the server process.

**Restarting cloudflared without updating `LOCAL_LLM_ENGINE_BASE_URL`**

The quick tunnel URL (`*.trycloudflare.com`) changes every time you restart cloudflared. Update `LOCAL_LLM_ENGINE_BASE_URL` in the SOC backend's environment and restart the SOC API Server.

**Setting `LOCAL_LLM_API_KEY` in the engine but not `LOCAL_LLM_ENGINE_API_KEY` in the SOC backend**

The engine expects a key, the SOC backend does not send one. The engine returns HTTP 401; the SOC backend surfaces this as `fallback_used: true` with `engine_error` mentioning auth.

**Using `http://` instead of `https://` for the tunnel URL**

Cloudflare Tunnel only serves HTTPS. The URL must start with `https://`.

**Calling the engine's `/analyze-event` endpoint directly instead of going through the SOC backend**

This works for testing, but in normal operation the SOC backend handles auth, rate limiting, request ID management, and contract validation for you.

**Very short descriptions**

A description like `"login failure"` gives the model almost no information. Use at least one sentence that includes what happened, from where, and any relevant numbers or identifiers.

---

## Testing auth end-to-end

If you have set both `SOC_API_KEY` (SOC backend) and `LOCAL_LLM_API_KEY` (engine `.env`):

```bash
# This should return 401 (missing SOC inbound key)
curl -X POST https://your-soc-server.example.com/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"description": "test"}'

# This should return 200 (correct SOC key, engine key sent transparently by SOC backend)
curl -X POST https://your-soc-server.example.com/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-soc-inbound-key" \
  -d '{"description": "SSH brute force from external IP."}'
```
