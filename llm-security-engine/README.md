# Local LLM Security Engine

A local AI inference service for cybersecurity event analysis. It accepts normalized security events, runs them through a local [Ollama](https://ollama.ai) language model (default: `phi4-mini`), and returns structured JSON threat classifications — with no cloud LLM APIs, no third-party data processing, and no internet required for local inference.

This service is designed to be called by a larger SOC backend. It is an **inference module**, not a SIEM, not a detection pipeline, and not a replacement for a security team. See [docs/using_real_logs.md](docs/using_real_logs.md) for what that means in practice.

---

## Documentation

If you are new to this project, read the docs in this order:

| Step | File | What it covers |
|------|------|----------------|
| 1 | [docs/getting_started.md](docs/getting_started.md) | Prerequisites, installation, first run |
| 2 | [docs/deployment_guide.md](docs/deployment_guide.md) | Run as a persistent service on Linux (systemd) or Windows (NSSM) |
| 3 | [docs/architecture_walkthrough.md](docs/architecture_walkthrough.md) | How all the pieces fit together |
| 4 | [docs/real_usage_guide.md](docs/real_usage_guide.md) | How to send events and read responses |
| 5 | [docs/end_to_end_integration.md](docs/end_to_end_integration.md) | Connecting a SOC backend to this engine |
| 6 | [docs/troubleshooting.md](docs/troubleshooting.md) | Diagnosing errors, fallbacks, and connectivity issues |
| 7 | [docs/using_real_logs.md](docs/using_real_logs.md) | How to use this with real log sources |
| — | [docs/integration_contract.md](docs/integration_contract.md) | Stable API contract for downstream consumers |
| — | [docs/production_gap.md](docs/production_gap.md) | What is missing before production SOC deployment |

---

## Overview

**What it does:**
- Accepts security events or SOC context summaries over HTTP
- Builds a structured cybersecurity prompt with label definitions and disambiguation examples
- Sends it to a local Ollama model (default: `phi4-mini`)
- Parses and validates the JSON output using up to 7 extraction strategies
- Returns a stable `AnalysisResponse` — or a safe fallback if anything fails

**What makes it reliable:**
- The service **never crashes on model failure**. Every code path returns a valid `AnalysisResponse`.
- When Ollama fails, times out, or returns unparseable output, `fallback_used` is set to `true` and defaults are returned.
- All output fields are validated against strict rules before being returned.

**What it is not:**
- Not a production SIEM
- Not a real-time detection system
- Not a replacement for security engineering
- See [docs/using_real_logs.md](docs/using_real_logs.md) for the honest constraints

---

## Quick Start

```bash
# 1. Install Ollama and pull the model (on your local machine)
ollama pull phi4-mini

# 2. Install Python dependencies
cd llm-security-engine
pip install -r requirements.txt

# 3. Copy config
cp .env.example .env

# 4. Start the server
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 5. Check it is running
curl http://localhost:8000/health
```

Full step-by-step instructions: [docs/getting_started.md](docs/getting_started.md)

---

## API Endpoints

### `GET /health`  *(no auth required)*

Liveness check. Reports service status and Ollama connectivity. Always returns HTTP 200.

```json
{
  "status": "ok",
  "service": "Local LLM Security Engine",
  "version": "1.0.0",
  "config": {
    "ollama_base_url": "http://localhost:11434",
    "ollama_model": "phi4-mini",
    "ollama_timeout_seconds": 60,
    "debug": false
  },
  "ollama": {
    "reachable": true,
    "configured_model": "phi4-mini",
    "model_available": true,
    "available_models": ["phi4-mini:latest"],
    "error": null
  }
}
```

If Ollama is down, `status` becomes `"degraded"` but the HTTP status is still 200.

---

### `GET /debug/ping-ollama`  *(no auth required)*

Lightweight Ollama connectivity probe for development. Returns reachability and round-trip latency.

---

### `POST /analyze-event`  *(auth required if `LOCAL_LLM_API_KEY` is set)*

Analyze a normalized security event.

**Minimal request:**
```bash
curl -X POST http://localhost:8000/analyze-event \
  -H "Content-Type: application/json" \
  -d '{"description": "57 failed SSH logins then 1 success from 185.220.101.1."}'
```

**Full request:**
```bash
curl -X POST http://localhost:8000/analyze-event \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key" \
  -H "X-Request-ID: my-trace-id" \
  -d '{
    "description": "57 failed SSH logins then 1 successful login on port 22.",
    "source_ip": "185.220.101.1",
    "destination_ip": "10.0.0.100",
    "event_type": "authentication_failure",
    "severity": "high",
    "timestamp": "2024-01-15T10:00:00Z",
    "additional_context": "Source IP on threat intel blocklist."
  }'
```

**Response:**
```json
{
  "attack_classification": "credential_access",
  "false_positive_likelihood": 0.05,
  "risk_score": 92,
  "reason": "57 failed SSH logins followed by a successful login from a flagged external IP.",
  "fallback_used": false,
  "model_used": "phi4-mini",
  "provider": "ollama",
  "raw_parse_success": true,
  "parse_strategy": "direct",
  "ollama_error": null,
  "request_id": "my-trace-id"
}
```

---

### `POST /analyze-context`  *(auth required if `LOCAL_LLM_API_KEY` is set)*

Analyze a short SOC context summary for an entity or session.

```bash
curl -X POST http://localhost:8000/analyze-context \
  -H "Content-Type: application/json" \
  -d '{
    "entity": "user:john.doe@corp.com",
    "summary": "Accessed 12 servers never visited before, downloaded 4.2GB, VPN from Eastern Europe.",
    "time_window": "2024-01-15 06:00–12:00 UTC",
    "additional_context": "No HR travel record. Mid-level developer account."
  }'
```

Returns the same `AnalysisResponse` schema as `/analyze-event`.

---

### `POST /raw-ollama-test`  *(debug only — auth required if `LOCAL_LLM_API_KEY` is set)*

Sends a raw prompt to Ollama and returns the unprocessed response. Use this to inspect model output and verify Ollama connectivity. Unlike the analysis endpoints, this endpoint intentionally surfaces raw Ollama errors and may return 5xx on Ollama failures.

---

## Response Schema

All analysis endpoints return the same stable schema:

| Field | Type | Always present | Description |
|---|---|---|---|
| `attack_classification` | string | Yes | One of 7 allowed labels (see below) |
| `false_positive_likelihood` | float | Yes | 0.0 = certain real threat · 1.0 = certain false positive |
| `risk_score` | integer | Yes | 0 = no risk · 100 = critical |
| `reason` | string | Yes | Brief explanation from the model |
| `fallback_used` | boolean | Yes | `true` if Ollama failed or returned invalid output |
| `model_used` | string | Yes | Ollama model name |
| `provider` | string | Yes | Always `"ollama"` |
| `raw_parse_success` | boolean | Yes | Whether raw output was valid JSON |
| `parse_strategy` | string | No | Which extraction strategy succeeded (null if none) |
| `ollama_error` | string | No | Error detail if Ollama failed (null on success) |
| `request_id` | string | No | Echoed from `X-Request-ID` header |

**Allowed `attack_classification` values:**

| Value | Meaning |
|---|---|
| `reconnaissance` | Scanning, probing, information gathering before an attack |
| `credential_access` | Stealing or brute-forcing credentials (access not yet gained) |
| `initial_access` | First successful entry into an environment |
| `lateral_movement` | Moving between systems inside a compromised network |
| `command_and_control` | Outbound communication to attacker infrastructure |
| `benign` | Normal, expected activity |
| `unknown` | Cannot classify from available data |

**Always check `fallback_used` before acting on `attack_classification`.** A result with `fallback_used: true` should be routed for manual review, not treated as a real classification.

---

## Configuration

Copy `.env.example` to `.env` and adjust:

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API URL |
| `OLLAMA_MODEL` | `phi4-mini` | Model name for inference |
| `OLLAMA_TIMEOUT` | `60` | Ollama request timeout in seconds |
| `LOCAL_LLM_API_KEY` | *(unset)* | Inbound auth key. If set, all `/analyze-*` and `/raw-ollama-test` endpoints require `X-API-Key: <value>`. Leave unset for local development. |
| `RATE_LIMIT_ENABLED` | `true` | Enable per-IP rate limiting |
| `RATE_LIMIT_REQUESTS` | `60` | Max requests per window |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Window duration in seconds |
| `MAX_DESCRIPTION_LENGTH` | `4000` | Max chars for `description` field in `/analyze-event` |
| `MAX_CONTEXT_LENGTH` | `4000` | Max chars for `summary` and `additional_context` fields (applied in both `/analyze-event` and `/analyze-context`) |
| `MAX_PROMPT_LENGTH` | `8000` | Max chars for `prompt` field in `/raw-ollama-test` |
| `MAX_FIELD_LENGTH` | `500` | Max chars for all other optional string fields |
| `API_HOST` | `0.0.0.0` | Host address the server binds to (used as reference; when running with `uvicorn`, pass `--host` and `--port` flags directly) |
| `API_PORT` | `8000` | Port the server listens on (see note above) |
| `DEBUG` | `false` | Enable debug logging |

---

## Reliability Behavior

| Failure | What happens |
|---|---|
| Ollama not running | Returns fallback with `fallback_used: true` and `ollama_error` set |
| Model not pulled | Returns HTTP 422 with detail: `Model 'phi4-mini' not found on Ollama. Run: ollama pull phi4-mini` |
| Ollama times out | Retries up to 3 times, then returns fallback |
| Model returns invalid JSON | Parser tries up to 7 extraction strategies; fallback if all fail |
| Model returns out-of-range values | Validator rejects and returns fallback with diagnostic reason |

`/analyze-event` and `/analyze-context` **never return a 5xx** while Ollama is running — all failures produce a valid `AnalysisResponse` with `fallback_used: true`. The `/raw-ollama-test` debug endpoint intentionally surfaces raw Ollama errors and may return 5xx.

---

## Authentication

Authentication is optional. To enable it:

```bash
# In .env (or environment):
LOCAL_LLM_API_KEY=your-secret-key
```

When set, every `/analyze-*` and `/raw-ollama-test` request must include:
```
X-API-Key: your-secret-key
```

Missing key → HTTP 401. Wrong key → HTTP 403.

The following endpoints are always public (no auth required):
- `GET /health`
- `GET /debug/ping-ollama`
- `GET /docs`
- `GET /redoc`

---

## Exposing via Cloudflare Tunnel (Development)

To allow a remote SOC backend to reach your local service:

```bash
# Install cloudflared: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
cloudflared tunnel --url http://localhost:8000
# Prints: https://random-name.trycloudflare.com
```

Your SOC backend can then call `https://random-name.trycloudflare.com/analyze-event`.

The tunnel is end-to-end encrypted — no firewall rules or port forwarding needed. This is a development pattern; see [docs/production_gap.md](docs/production_gap.md) for what a production setup requires.

---

## Connecting to a SOC Backend

This service is a stateless inference module. Your SOC backend calls it over HTTP and checks `fallback_used` before routing on the result:

```python
import requests

def analyze_event(event: dict, api_key: str | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    resp = requests.post(
        "http://localhost:8000/analyze-event",
        json=event,
        headers=headers,
        timeout=90,
    )
    resp.raise_for_status()
    result = resp.json()

    if result["fallback_used"]:
        # Ollama failed or returned invalid output — route for manual review
        queue_for_manual_review(result)
        return result

    # Safe to use result["attack_classification"] and result["risk_score"]
    return result
```

Full integration guide: [docs/end_to_end_integration.md](docs/end_to_end_integration.md)

---

## Running Tests

```bash
cd llm-security-engine
python -m pytest tests/ -v
```

126 tests across 8 files covering: JSON parsing (all 7 strategies including combined_fix), field validation, prompt construction, Ollama client retries, auth, rate limiting, input limits, and schema stability. No real Ollama instance required — all tests use mocks.

---

## Project Structure

```
llm-security-engine/
├── app/
│   ├── main.py                    # FastAPI app, middleware registration
│   ├── config.py                  # Settings from environment / .env
│   ├── middleware/
│   │   ├── auth.py                # Optional X-API-Key auth
│   │   ├── rate_limiter.py        # In-memory sliding-window rate limiter
│   │   └── request_id.py          # X-Request-ID propagation
│   ├── models/
│   │   └── schemas.py             # Pydantic models: SecurityEvent, AnalysisResponse, etc.
│   ├── routes/
│   │   ├── health.py              # GET /health, GET /debug/ping-ollama
│   │   └── analyze.py             # POST /analyze-event, /analyze-context, /raw-ollama-test
│   └── services/
│       ├── ollama_client.py       # Async HTTP client with retries and typed errors
│       ├── prompt_builder.py      # Cybersecurity prompt with label definitions
│       ├── parser.py              # 7-strategy JSON extractor
│       └── validator.py           # Per-field validation with fallback reasons
├── docs/
│   ├── getting_started.md         # Step-by-step beginner guide
│   ├── architecture_walkthrough.md# How all layers fit together
│   ├── real_usage_guide.md        # How to send events and read responses
│   ├── end_to_end_integration.md  # Connecting a SOC backend to this engine
│   ├── troubleshooting.md         # Common errors and fixes
│   ├── using_real_logs.md         # Using with Suricata, Zeek, Wazuh, etc.
│   ├── integration_contract.md    # Stable API contract reference
│   └── production_gap.md          # What is missing before production use
├── tests/                         # 125 unit tests (mocked — no Ollama needed)
├── samples/                       # curl and Python request examples
├── test_local.py                  # Quick end-to-end test (requires running server + Ollama)
├── requirements.txt
├── requirements-dev.txt
└── .env.example
```

---

## Limitations

- **Local-only inference**: Ollama must run on the same machine or LAN. This is not a cloud service.
- **Synchronous**: Each request blocks until Ollama finishes (up to 60 seconds). Not designed for high-throughput streaming.
- **Single model**: One model per running instance. Model routing by severity must be implemented by the caller.
- **No audit trail**: Requests and responses are not persisted. Every request is stateless.
- **In-memory rate limiting**: Rate limit state is lost on restart and is not shared across multiple instances.
- **Not a SIEM**: No alert correlation, no detection rules, no case management.

See [docs/production_gap.md](docs/production_gap.md) for the full gap analysis.
