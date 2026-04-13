# SOC API Server

Express/TypeScript API server for the SOC backend. Accepts normalized security alerts and returns structured threat analysis by delegating to the Local LLM Security Engine — a Python FastAPI service that runs inference via Ollama with no cloud APIs.

---

## End-to-end Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  SOC Consumer  (SIEM, analyst tool, automation pipeline)                │
│                                                                         │
│  POST /api/analyze                  GET /api/provider-health            │
│  X-API-Key: <key>  ─────────────┐  (no auth required)                  │
│  X-Request-ID: <trace>          │                                       │
└─────────────────────────────────┼───────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  SOC API Server  (this service — Express/TypeScript)                    │
│                                                                         │
│  Middleware stack for /api/analyze:                                     │
│    1. apiKeyAuth        — checks X-API-Key header (if SOC_API_KEY set)  │
│    2. analyzeRateLimiter — fixed-window per-IP rate limit               │
│    3. validateRequest   — input size & type checks                      │
│    4. local_security_engine provider — calls engine, validates contract │
│                                                                         │
│  Always returns 200 from /api/analyze (fallback_used: true on failure). │
│  Sets X-Request-ID response header for tracing.                        │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                        POST /analyze-event
                        X-API-Key: <engine key>
                        X-Request-ID: <trace>
                        (real HTTP — no cloud)
                                  │
                                  ▼  (local or via Cloudflare Tunnel)
┌─────────────────────────────────────────────────────────────────────────┐
│  Local LLM Security Engine  (Python FastAPI — llm-security-engine/)     │
│                                                                         │
│  Validates input → builds prompt → calls Ollama → parses JSON output    │
│  Returns structured AnalysisResult with contract_validation_failed flag │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                                  ▼  (localhost only — no network)
┌─────────────────────────────────────────────────────────────────────────┐
│  Ollama  (local model: phi4-mini)                                       │
│  No cloud APIs. Inference is 100% local.                                │
└─────────────────────────────────────────────────────────────────────────┘
```

The SOC backend never calls Ollama directly. The Local LLM Security Engine is the sole inference abstraction layer. The SOC backend only speaks JSON over HTTP.

---

## Provider Modes

| Mode                    | Behaviour                                                                  |
|-------------------------|----------------------------------------------------------------------------|
| `local_security_engine` | Forwards analysis requests to the Local LLM Security Engine via HTTP       |
| `none`                  | No provider configured; `/api/analyze` returns 503                         |

**Auto-detection:** if `LOCAL_LLM_ENGINE_BASE_URL` is set, `local_security_engine` is used automatically. Set `PROVIDER_MODE=none` to force-disable without removing the URL.

---

## Environment Variables

### SOC API Server

| Variable                        | Required | Default  | Description                                                    |
|---------------------------------|----------|----------|----------------------------------------------------------------|
| `PORT`                          | Yes      | —        | Server port (set automatically by Replit)                      |
| `SOC_API_KEY`                   | No       | —        | Inbound auth key. Callers must send `X-API-Key: <value>`. If unset, auth is disabled. |
| `RATE_LIMIT_MAX`                | No       | `60`     | Max requests per IP per window for `/api/analyze`              |
| `RATE_LIMIT_WINDOW_MS`          | No       | `60000`  | Rate limit window duration in milliseconds                     |
| `LOCAL_LLM_ENGINE_BASE_URL`     | Yes*     | —        | Base URL of the Local LLM Security Engine                      |
| `LOCAL_LLM_ENGINE_API_KEY`      | No       | —        | API key for the engine (sent as `X-API-Key` to the engine)     |
| `LOCAL_LLM_ENGINE_TIMEOUT_MS`   | No       | `90000`  | Per-request timeout to the engine in ms (inference is 30–60s)  |
| `PROVIDER_MODE`                 | No       | auto     | Override detection: `local_security_engine` or `none`          |
| `NODE_ENV`                      | No       | —        | `development` or `production`                                  |
| `LOG_LEVEL`                     | No       | `info`   | Pino log level                                                 |

\* Required when `PROVIDER_MODE=local_security_engine`

---

## API Endpoints

### `GET /api/healthz`  *(no auth)*

Lightweight liveness check. Always returns 200.

```json
{"status": "ok"}
```

---

### `GET /api/provider-health`  *(no auth)*

Probes the configured LLM provider and returns connectivity status. Never returns an error HTTP status.

```json
{
  "provider_mode": "local_security_engine",
  "configured_base_url": "https://your-tunnel.trycloudflare.com",
  "engine_reachable": true,
  "engine_status": "ok",
  "model_name": "phi4-mini",
  "auth_configured": true,
  "latency_ms": 48.2,
  "engine_error": null
}
```

When the engine is unreachable:
```json
{
  "provider_mode": "local_security_engine",
  "configured_base_url": "https://your-tunnel.trycloudflare.com",
  "engine_reachable": false,
  "engine_status": null,
  "model_name": null,
  "auth_configured": false,
  "latency_ms": null,
  "engine_error": "connect ECONNREFUSED"
}
```

---

### `POST /api/analyze`  *(auth + rate-limited)*

Analyze a normalized security alert.

**Request headers:**

| Header           | Required*   | Description                          |
|------------------|-------------|--------------------------------------|
| `Content-Type`   | Yes         | Must be `application/json`           |
| `X-API-Key`      | If SOC_API_KEY set | Inbound auth key              |
| `X-Request-ID`   | No          | Trace ID; auto-generated if omitted  |

**Request body:**

```json
{
  "description": "57 failed SSH logins followed by a successful login from an external IP.",
  "source_ip": "185.220.101.1",
  "destination_ip": "10.0.0.5",
  "event_type": "authentication_failure",
  "severity": "high",
  "timestamp": "2024-01-15T10:00:00Z",
  "additional_context": "Source IP is on threat intel blocklist."
}
```

| Field                | Required | Max length | Description                           |
|----------------------|----------|------------|---------------------------------------|
| `description`        | Yes      | 4,000      | Event description or raw log summary  |
| `source_ip`          | No       | 500        | Source IP address                     |
| `destination_ip`     | No       | 500        | Destination IP                        |
| `event_type`         | No       | 500        | Event category                        |
| `severity`           | No       | 500        | Reported severity                     |
| `timestamp`          | No       | 500        | ISO 8601 timestamp                    |
| `additional_context` | No       | 4,000      | Additional SOC context                |

**Response (200):**

```json
{
  "attack_classification": "credential_access",
  "false_positive_likelihood": 0.05,
  "risk_score": 92,
  "reason": "57 failed SSH logins followed by a successful login from a flagged IP.",
  "fallback_used": false,
  "model_used": "phi4-mini",
  "provider": "ollama",
  "raw_parse_success": true,
  "parse_strategy": "direct",
  "ollama_error": null,
  "request_id": "a3f5e91b-0c22-4d1b-8b74-2e5f8c9e1234",
  "engine_reachable": true,
  "engine_error": null,
  "latency_ms": 14320,
  "contract_validation_failed": false,
  "soc_provider_mode": "local_security_engine"
}
```

**Always check `fallback_used` before acting on `attack_classification`.** When `true`, the engine was unreachable or returned invalid output — route for manual review instead of automation.

---

## Fallback Behaviour

`/api/analyze` never returns 5xx for engine failures. Provider errors surface in the 200 body:

| Scenario                                   | HTTP | `engine_reachable` | `fallback_used` | `contract_validation_failed` |
|--------------------------------------------|------|---------------------|-----------------|------------------------------|
| Engine returned valid analysis             | 200  | `true`              | `false`         | `false`                      |
| Engine applied its own fallback            | 200  | `true`              | `true`          | `false`                      |
| Engine returned malformed JSON (HTTP 200)  | 200  | `true`              | `true`          | `true`                       |
| Engine unreachable (network error)         | 200  | `false`             | `true`          | `false`                      |
| Engine timed out                           | 200  | `false`             | `true`          | `false`                      |
| Engine rate limited (HTTP 429)             | 200  | `false`             | `true`          | `false`                      |
| Engine auth rejected (HTTP 401/403)        | 200  | `false`             | `true`          | `false`                      |
| No provider configured                     | 503  | —                   | —               | —                            |
| Invalid request body                       | 422  | —                   | —               | —                            |
| Inbound auth failure (wrong X-API-Key)     | 401  | —                   | —               | —                            |
| Rate limit exceeded                        | 429  | —                   | —               | —                            |

`contract_validation_failed: true` means the engine was reachable (HTTP 200) but returned a body that failed runtime schema validation. This indicates a version mismatch between the SOC backend and the engine.

---

## Request Tracing

Pass `X-Request-ID` to correlate a single event across all three layers:

```bash
curl -X POST http://localhost:$PORT/api/analyze \
  -H "X-API-Key: your-key" \
  -H "X-Request-ID: siem-alert-id-abc" \
  -H "Content-Type: application/json" \
  -d '{"description": "Port scan from 1.2.3.4"}'
```

The same ID flows to:
- The engine's `POST /analyze-event` as `X-Request-ID` request header
- The SOC backend's response as `X-Request-ID` response header
- The response body as `request_id`
- Every structured log line as `request_id`

---

## Inbound Authentication

Set `SOC_API_KEY` in the environment to enable inbound auth on `/api/analyze`:

```bash
export SOC_API_KEY=your-inbound-secret-key
```

Callers must then include the header:

```
X-API-Key: your-inbound-secret-key
```

`/api/healthz` and `/api/provider-health` are intentionally public — they are monitoring endpoints that must be accessible without credentials.

When `SOC_API_KEY` is not set, authentication is disabled and all requests are accepted. This is the expected development mode.

---

## Rate Limiting

`/api/analyze` is rate-limited per client IP using a fixed-window counter:

| Variable            | Default | Description                  |
|---------------------|---------|------------------------------|
| `RATE_LIMIT_MAX`    | `60`    | Max requests per window      |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Window size in milliseconds |

When exceeded, the server returns:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 42
Content-Type: application/json

{
  "error": "rate_limit_exceeded",
  "detail": "Too many requests. Limit is 60 per 60s. Try again in 42s.",
  "retry_after_seconds": 42
}
```

The rate limiter state is in-memory and does not persist across restarts. For multi-instance deployments, replace it with a Redis-backed implementation.

---

## Local Development Setup

### Step 1 — Start Ollama and pull the model

```bash
ollama pull phi4-mini
ollama serve
```

### Step 2 — Start the Local LLM Security Engine

```bash
cd llm-security-engine
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Verify it's up
curl http://localhost:8000/health
```

### Step 3 — (Remote only) Expose via Cloudflare Tunnel

If the SOC API Server runs on a different machine from the engine:

```bash
cloudflared tunnel --url http://localhost:8000
# Prints: https://random-name.trycloudflare.com
```

### Step 4 — Configure the SOC backend

```bash
# Engine on the same machine:
export LOCAL_LLM_ENGINE_BASE_URL=http://localhost:8000

# Engine via tunnel:
export LOCAL_LLM_ENGINE_BASE_URL=https://random-name.trycloudflare.com

# If the engine requires an API key:
export LOCAL_LLM_ENGINE_API_KEY=your-engine-key

# To enable inbound auth on this server:
export SOC_API_KEY=your-inbound-secret-key
```

### Step 5 — Start the SOC backend

```bash
cd soc-backend
pnpm run dev
```

### Step 6 — Send a test alert

```bash
curl -X POST http://localhost:$PORT/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-inbound-secret-key" \
  -d '{
    "description": "57 failed SSH logins then 1 success from a flagged external IP.",
    "source_ip": "185.220.101.1",
    "event_type": "authentication_failure",
    "severity": "high"
  }'
```

---

## Running Tests

```bash
cd soc-backend
pnpm run test
```

The test suite includes:

| File                           | What it covers                                                    |
|--------------------------------|-------------------------------------------------------------------|
| `localSecurityEngine.test.ts`  | Unit tests: client class, `validateEngineResponse`, every HTTP error code, timeouts, auth header |
| `analyzeRoute.test.ts`         | Integration: full HTTP round-trips via real Express server, all status codes, fallback/contract-violation paths |
| `contract.test.ts`             | Contract stability: request body shape, response field set across all paths, UUID generation |
| `e2e.test.ts`                  | End-to-end: real mock Python engine + real SOC backend, auth enforcement, rate limiting |

---

## Adding Another Provider

1. Add the new mode to `ProviderMode` in `src/lib/config.ts`
2. Create `src/providers/yourProvider.ts` with `analyzeEvent()` and `checkHealth()` methods
3. Add env vars to `config.ts` and `.env.example`
4. Add branching in `src/routes/analyze.ts` and `src/routes/health.ts`
5. Document in this README and `lib/api-spec/openapi.yaml`

The middleware stack (`apiKeyAuth`, `analyzeRateLimiter`) applies automatically to the route — no changes needed there.
