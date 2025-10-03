# Integration Contract — Local LLM Security Engine

**Version**: 1.0.0  
**Service**: Local LLM Security Engine  
**Protocol**: HTTP/1.1, JSON  
**Base URL (local)**: `http://localhost:8000`  
**Base URL (tunnel)**: `https://<tunnel-host>` (Cloudflare Tunnel or equivalent)

---

## Purpose

This document is the stable integration contract for downstream SOC backends consuming this service. It defines the exact request schemas, response schemas, authentication behavior, error handling, and fallback semantics that consumers can depend on.

---

## Authentication

### When auth is disabled (default for local development)

No special headers required. All requests are accepted.

**Configuration**: `LOCAL_LLM_API_KEY` is unset or empty in `.env`.

### When auth is enabled

Every request to a protected endpoint must include:

```
X-API-Key: <your-configured-key>
```

**Configuration**: Set `LOCAL_LLM_API_KEY=your-secret-key` in `.env`.

### Auth error responses

| Condition           | Status | Body                                          |
|---------------------|--------|-----------------------------------------------|
| Header missing      | 401    | `{"detail": "Missing X-API-Key header..."}`   |
| Header wrong value  | 403    | `{"detail": "Invalid API key."}`              |

### Exempt endpoints (never require auth)

- `GET /health`
- `GET /debug/ping-ollama`
- `GET /docs`
- `GET /redoc`

---

## Request ID Tracing

Every request receives a unique trace ID attached to the response as:

```
X-Request-ID: <uuid>
```

To provide your own trace ID (for end-to-end correlation), send:

```
X-Request-ID: <your-trace-id>
```

The service echoes this value in the response header and in the `request_id` field of the response body.

---

## Rate Limiting

Default: 60 requests per 60 seconds per client identity.

Client identity is derived in order:
1. `X-Client-ID` header (if present)
2. `CF-Connecting-IP` header (Cloudflare Tunnel)
3. `X-Forwarded-For` header
4. Direct connection IP

### Rate limit error response

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 42
Content-Type: application/json
```

```json
{
  "error": "rate_limit_exceeded",
  "detail": "Rate limit exceeded: 60 requests per 60 seconds.",
  "retry_after_seconds": 42
}
```

---

## Endpoints

### GET /health

**Auth required**: No  
**Purpose**: Liveness check. Always returns 200.

**Response (200)**:
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

When Ollama is unreachable, `status` becomes `"degraded"` but the HTTP status is still 200. The service is still alive; it just cannot reach Ollama.

---

### POST /analyze-event

**Auth required**: Yes (if configured)  
**Purpose**: Analyze a normalized security event.

**Request body**:

```json
{
  "description": "string (required, 1–4000 chars)",
  "source_ip": "string (optional, max 500 chars)",
  "destination_ip": "string (optional, max 500 chars)",
  "event_type": "string (optional, max 500 chars)",
  "severity": "string (optional, max 500 chars)",
  "timestamp": "string (optional, max 500 chars)",
  "additional_context": "string (optional, max 4000 chars)"
}
```

**Response (200)**:
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
  "request_id": "a3f5e91b-0c22-4d1b-8b74-2e5f8c9e1234"
}
```

---

### POST /analyze-context

**Auth required**: Yes (if configured)  
**Purpose**: Analyze a SOC context summary for an entity or session.

**Request body**:

```json
{
  "summary": "string (required, 1–4000 chars)",
  "entity": "string (optional, max 500 chars)",
  "time_window": "string (optional, max 500 chars)",
  "additional_context": "string (optional, max 4000 chars)"
}
```

**Response (200)**: Same schema as `/analyze-event`.

---

### POST /raw-ollama-test

**Auth required**: Yes (if configured)  
**Purpose**: Debug only. Sends a raw prompt to Ollama and returns the raw response.

**Request body**:

```json
{
  "prompt": "string (required, 1–8000 chars)"
}
```

**Response (200)**:
```json
{
  "prompt": "What is reconnaissance?",
  "raw_response": "Reconnaissance is...",
  "model": "phi4-mini"
}
```

---

## Response Schema — AnalysisResponse

All analysis endpoints return `AnalysisResponse`. This schema is stable.

| Field                       | Type    | Always present | Description                                                           |
|-----------------------------|---------|----------------|-----------------------------------------------------------------------|
| `attack_classification`     | string  | Yes            | One of 7 allowed labels (see below)                                   |
| `false_positive_likelihood` | float   | Yes            | 0.0 = certain real threat · 1.0 = certain false positive             |
| `risk_score`                | integer | Yes            | 0 = no risk · 100 = critical                                          |
| `reason`                    | string  | Yes            | Non-empty explanation; may be a fallback message if `fallback_used`  |
| `fallback_used`             | boolean | Yes            | `true` if model output was invalid or Ollama failed                   |
| `model_used`                | string  | Yes            | Ollama model name                                                     |
| `provider`                  | string  | Yes            | Always `"ollama"`                                                     |
| `raw_parse_success`         | boolean | Yes            | Whether raw model output was parsed as valid JSON                     |
| `parse_strategy`            | string  | No (null)      | Which JSON extraction strategy succeeded; null if parsing failed      |
| `ollama_error`              | string  | No (null)      | Error detail if Ollama failed; null on success                        |
| `request_id`                | string  | No (null)      | Echoed trace ID                                                       |

### Allowed `attack_classification` values

| Value                 | Meaning                                                        |
|-----------------------|----------------------------------------------------------------|
| `reconnaissance`      | Scanning, probing, information gathering before an attack      |
| `credential_access`   | Stealing or brute-forcing credentials (not yet accessing system) |
| `initial_access`      | First successful entry into an environment                     |
| `lateral_movement`    | Moving between systems inside a compromised network            |
| `command_and_control` | Outbound communication to attacker infrastructure              |
| `benign`              | Normal, expected activity                                      |
| `unknown`             | Cannot classify from available data                            |

---

## Fallback Behavior

The service **never returns a 5xx error for analysis endpoints** when Ollama is running. Instead:

| Trigger                     | Behavior                                                             |
|-----------------------------|----------------------------------------------------------------------|
| Ollama not running          | Returns `AnalysisResponse` with `fallback_used: true`, `ollama_error` set |
| Ollama timeout              | Returns `AnalysisResponse` with `fallback_used: true`, `ollama_error` set |
| Model output unparseable    | Returns `AnalysisResponse` with `fallback_used: true`, safe defaults |
| Model output fields invalid | Returns `AnalysisResponse` with `fallback_used: true`, safe defaults |

### Fallback defaults

```json
{
  "attack_classification": "unknown",
  "false_positive_likelihood": 0.5,
  "risk_score": 50,
  "reason": "<diagnostic message>",
  "fallback_used": true
}
```

**Consumers must always check `fallback_used`** before routing on `attack_classification`. A `fallback_used: true` result should be queued for manual review, not treated as a classification.

---

## Error Responses

### HTTP 401 — Missing API key
```json
{"detail": "Missing X-API-Key header. Authentication is required."}
```

### HTTP 403 — Wrong API key
```json
{"detail": "Invalid API key."}
```

### HTTP 422 — Validation error (bad request body or model not found)
Standard FastAPI validation error:
```json
{
  "detail": [
    {
      "loc": ["body", "description"],
      "msg": "String should have at most 4000 characters",
      "type": "string_too_long"
    }
  ]
}
```

Or for model-not-found:
```json
{"detail": "Model 'phi4-mini' not found on Ollama. Run: ollama pull phi4-mini"}
```

### HTTP 429 — Rate limit exceeded
```json
{
  "error": "rate_limit_exceeded",
  "detail": "Rate limit exceeded: 60 requests per 60 seconds.",
  "retry_after_seconds": 42
}
```
Headers: `Retry-After: 42`

---

## Input Size Limits

| Field                    | Default max length | Config var                |
|--------------------------|--------------------|---------------------------|
| `description`            | 4000 chars         | `MAX_DESCRIPTION_LENGTH`  |
| `summary`                | 4000 chars         | `MAX_CONTEXT_LENGTH`      |
| `additional_context`     | 4000 chars         | `MAX_CONTEXT_LENGTH`      |
| `prompt` (raw test)      | 8000 chars         | `MAX_PROMPT_LENGTH`       |
| Optional string fields   | 500 chars          | `MAX_FIELD_LENGTH`        |

Exceeding any limit returns HTTP 422 before the request reaches Ollama.

---

## Recommended Consumer Pattern

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

    if resp.status_code == 429:
        retry_after = resp.json().get("retry_after_seconds", 60)
        raise Exception(f"Rate limited. Retry after {retry_after}s.")

    resp.raise_for_status()
    result = resp.json()

    if result["fallback_used"]:
        # Queue for manual review — do not trust the classification
        pass

    return result
```
