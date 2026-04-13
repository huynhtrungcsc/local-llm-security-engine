# Architecture Walkthrough — Local LLM Security Engine

This document explains how all the pieces of this system fit together: what runs where, what talks to what, and why things are structured the way they are.

---

## The big picture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  CLOUD (your server — VPS, dedicated, or any networked machine)           │
│                                                                           │
│  SOC API Server  (Express / TypeScript)                                   │
│  soc-backend/                                                             │
│                                                                           │
│  Receives alerts from SIEM, analyst tools, or your own automation.       │
│  Applies inbound auth, rate limiting, and input validation.              │
│  Calls the Local LLM Security Engine for inference.                      │
│  Returns structured threat analysis to the caller.                       │
│                                                                           │
└──────────────────────────────────────────┬───────────────────────────────┘
                                           │
                             HTTPS (Cloudflare Tunnel)
                             POST /analyze-event
                             X-API-Key, X-Request-ID
                                           │
                                           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  YOUR LOCAL MACHINE                                                       │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │  Local LLM Security Engine  (Python / FastAPI)                   │     │
│  │  llm-security-engine/   — port 8000                             │     │
│  │                                                                   │     │
│  │  Receives the event from the SOC backend.                        │     │
│  │  Builds a structured security prompt.                            │     │
│  │  Calls Ollama. Parses and validates the response.               │     │
│  │  Returns AnalysisResponse (or safe fallback).                   │     │
│  └──────────────────────┬──────────────────────────────────────────┘     │
│                          │ HTTP (localhost only)                          │
│                          │ POST /api/generate                            │
│                          ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │  Ollama  (local model server)                                    │     │
│  │  port 11434                                                      │     │
│  │                                                                   │     │
│  │  Loads phi4-mini (or another model) into RAM/VRAM.              │     │
│  │  Runs inference. Returns raw text output.                        │     │
│  │  No internet connection used at inference time.                  │     │
│  └─────────────────────────────────────────────────────────────────┘     │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## What runs where

| Component | Where it runs | Who manages it |
|---|---|---|
| SOC API Server | Cloud server or networked machine | System service / process manager |
| Cloudflare Tunnel | Your local machine | You (run `cloudflared`) |
| Local LLM Security Engine | Your local machine | You (run `uvicorn`) |
| Ollama | Your local machine | Ollama (background service) |
| phi4-mini model | Your local machine (file on disk) | Ollama |

The SOC backend is in the cloud. Everything else is on your machine. **No event data is forwarded to third-party cloud APIs** — the SOC backend sends events over the tunnel to your local engine, and the engine sends them to Ollama, which never makes outbound network calls. All inference happens locally.

---

## What Cloudflare Tunnel does

The SOC API Server runs on a networked server (cloud VPS, dedicated server, or any machine the SOC backend is deployed on). Your Local LLM Security Engine runs on your local machine behind a firewall. These two cannot communicate directly.

Cloudflare Tunnel bridges the gap:

```
Cloud server → Cloudflare servers → Cloudflare Tunnel daemon → localhost:8000
```

The tunnel daemon runs on your machine and creates an outbound connection to Cloudflare's servers. When the SOC backend sends a request to the tunnel URL, Cloudflare forwards it through that connection to your local engine. No firewall rules or port forwarding are needed — the connection is initiated from your machine, not from outside.

The tunnel URL looks like: `https://random-name.trycloudflare.com`

This is a development pattern. In production, you would run the engine in a proper server environment accessible to the SOC backend without needing a tunnel.

---

## The data flow, step by step

1. **A security alert arrives** at the SOC API Server (from a SIEM, analyst tool, or your own code).

2. **The SOC backend validates** the request body, checks the inbound API key (if configured), and applies rate limiting.

3. **The SOC backend calls the engine**: it sends a `POST /analyze-event` request to the tunnel URL (or `http://localhost:8000` if both are on the same machine).

4. **The engine receives the event** and builds a structured prompt. The prompt includes:
   - The event fields (description, IPs, severity, etc.)
   - Definitions of all 7 attack classification labels
   - Examples that disambiguate similar labels (e.g. credential access vs. initial access)
   - Instructions to return only JSON, nothing else

5. **The engine calls Ollama** via HTTP on localhost. Ollama loads `phi4-mini` into RAM (or VRAM if a GPU is available) and runs inference. This is the slow step — it takes 10–60 seconds on a CPU.

6. **Ollama returns raw text**. The model almost always returns JSON, but sometimes wraps it in markdown code fences, adds explanatory text, or uses single quotes instead of double quotes. The engine's parser tries 7 different extraction strategies to handle this.

7. **The parser returns a dict** (or `None` if it could not extract valid JSON). The validator checks every field: is the attack classification one of the 7 allowed values? Is the risk score an integer between 0 and 100? Is the reason a non-empty string?

8. **The engine returns an `AnalysisResponse`**. If validation succeeded, `fallback_used` is `false`. If anything failed (Ollama down, timeout, unparseable output, invalid fields), the engine returns a safe fallback with `fallback_used: true`.

9. **The SOC backend receives the response**, adds its own fields (`soc_provider_mode`, `engine_reachable`, `contract_validation_failed`), and returns the final result to the caller.

---

## What the engine does not do

- It does not store requests or responses. Every call is stateless.
- It does not call any external API at inference time. Ollama is local.
- It does not manage alerts, cases, tickets, or workflows.
- It does not run rules or signatures. It only runs model inference.
- It does not decide what to do with the result. That is the SOC backend's job.

---

## Why this separation exists

The Local LLM Security Engine and the SOC API Server are deliberately separate services:

- **Local engine**: runs model inference. Knows nothing about the SOC backend's data model, user management, or alert lifecycle. Can be replaced with a different model or a cloud API without changing the SOC backend.

- **SOC API Server**: handles inbound auth, rate limiting, routing, tracing, and fallback enrichment. Knows nothing about how Ollama works internally. Can switch the inference provider by changing a config variable.

This separation means you can:
- Test the engine standalone with curl — no SOC backend needed
- Swap `phi4-mini` for a larger model by changing one env var
- Replace the engine entirely with a cloud API (OpenAI, Anthropic, etc.) by changing the provider in the SOC backend — without modifying any of the engine code

---

## The internal structure of the engine

```
Request arrives at FastAPI
        │
        ▼
RequestIDMiddleware      — assigns X-Request-ID (or echoes caller-supplied one)
        │
        ▼
RateLimitMiddleware      — rejects with 429 if limit exceeded
        │
        ▼
verify_api_key           — rejects with 401/403 if auth is enabled and key is wrong
        │
        ▼
analyze_event route      — validates input with Pydantic
        │
        ▼
build_event_prompt()     — constructs the structured security prompt
        │
        ▼
query_ollama()           — async HTTP to localhost:11434/api/generate (retries up to 3x)
        │
        ▼
extract_json_from_response()  — tries 7 JSON extraction strategies
        │
        ▼
validate_analysis_result()    — checks every field; returns fallback if any fail
        │
        ▼
AnalysisResponse         — returned to caller
```

Every step that can fail returns a safe fallback instead of an error. The service only raises HTTP errors for: invalid request body (422), missing/wrong API key (401/403), rate limit exceeded (429).

---

## Why local inference

Using a local model means:
- **No event data is sent to cloud LLM providers** during inference. All inference runs on the local machine running Ollama. This matters for security event data, which may contain PII, internal IPs, credentials, or indicators of compromise. Note that when the SOC backend communicates with the engine over a Cloudflare Tunnel, event data travels over that encrypted channel to reach the engine — but it never reaches a third-party LLM API.
- **No per-inference cost**. Cloud APIs charge per token. A local model has a fixed hardware cost.
- **No dependency on external service availability**. The engine works during cloud outages.
- **No rate limits from a third party**. Your throughput is only limited by your hardware.

The tradeoff: local models like `phi4-mini` are less capable than large cloud models. The engine is designed to compensate with a carefully structured prompt, output validation, and reliable fallback behavior.
