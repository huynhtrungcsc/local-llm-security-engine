<div align="center">

# local-llm-security-engine

**Local LLM Inference Service for Cybersecurity Event Analysis**

*FastAPI · Ollama · Express — No cloud APIs, all inference runs locally*

[![Python](https://img.shields.io/badge/Python-3.10%20|%203.11%20|%203.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Ollama](https://img.shields.io/badge/Ollama-local%20inference-black)](https://ollama.ai/)
[![Python Tests](https://img.shields.io/badge/Python%20tests-126%20passing-brightgreen)](llm-security-engine/tests/)
[![TS Tests](https://img.shields.io/badge/TS%20tests-92%20passing-brightgreen)](soc-backend/tests/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Inference](https://img.shields.io/badge/Inference-no%20cloud%20APIs-blueviolet)](llm-security-engine/docs/architecture_walkthrough.md)

</div>

---

## Overview

This repository contains two tightly integrated services for on-premise AI-assisted security operations:

| Component | Path | Language | Purpose |
|-----------|------|----------|---------|
| **LLM Security Engine** | `llm-security-engine/` | Python 3.10+ / FastAPI | Runs local LLM inference via Ollama; classifies security events into structured JSON |
| **SOC Backend** | `soc-backend/` | TypeScript / Express | Receives raw security alerts, calls the engine, returns normalised analysis to downstream consumers |

The `openapi/` directory contains the shared OpenAPI 3.1 contract that both services conform to.

All LLM inference runs locally on your machine via [Ollama](https://ollama.ai). No event data is sent to cloud LLM providers.

---

## Quick Start

**Prerequisites:** Python 3.10+, Node.js 20+, [Ollama](https://ollama.com) running with a model pulled.

```bash
# Pull the default model
ollama pull phi4-mini

# 1. Start the LLM Security Engine
cd llm-security-engine
pip install -r requirements.txt
cp .env.example .env          # edit OLLAMA_MODEL, API key, etc.
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 2. Start the SOC Backend (separate terminal, needs Node.js 20+ and pnpm)
cd soc-backend
pnpm install
cp .env.example .env.local   # PORT=3000 + LOCAL_LLM_ENGINE_BASE_URL already set
pnpm run dev
```

Full setup guide: [`llm-security-engine/docs/getting_started.md`](llm-security-engine/docs/getting_started.md)

---

## Architecture

```
[Security alert source]
         |
         v
+------------------+   POST /api/analyze   +----------------------------+
|   SOC Backend    |---------------------->|   LLM Security Engine      |
|  (TypeScript)    |                       |  (Python / FastAPI)        |
|  soc-backend/    |<----------------------|  llm-security-engine/      |
+------------------+  structured analysis  |  -> Ollama (local model)   |
                                           +----------------------------+
```

The engine exposes a stable REST API. The SOC backend validates every response against the OpenAPI contract before forwarding downstream — any contract violation is flagged as a `fallback_used` event rather than silently accepted.

When the engine is running behind a Cloudflare Tunnel, the SOC backend on a remote machine can reach it over an encrypted HTTPS connection while keeping all LLM inference on the local Ollama host.

---

## API Endpoints

### LLM Security Engine (`http://localhost:8000`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/analyze-event` | Optional | Classify a normalized security event |
| `POST` | `/analyze-context` | Optional | Classify a SOC context summary |
| `POST` | `/raw-ollama-test` | Optional | Debug: send a raw prompt to Ollama |
| `GET` | `/health` | None | Service health check |
| `GET` | `/debug/ping-ollama` | None | Ollama connectivity probe |

All analysis endpoints return the same stable `AnalysisResponse` schema. Ollama failures produce a structured fallback with `fallback_used: true` rather than an HTTP error.

### SOC Backend (`http://localhost:3000`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/analyze` | Optional | Receive a security alert and return engine analysis |
| `GET` | `/api/healthz` | None | Liveness check — always returns `{"status":"ok"}` |
| `GET` | `/api/provider-health` | None | Engine connectivity probe with model and latency info |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Getting started](llm-security-engine/docs/getting_started.md) | Step-by-step local setup for all platforms |
| [Architecture walkthrough](llm-security-engine/docs/architecture_walkthrough.md) | Code paths, data flow, and component roles |
| [Real usage guide](llm-security-engine/docs/real_usage_guide.md) | Annotated request/response examples |
| [End-to-end integration](llm-security-engine/docs/end_to_end_integration.md) | Connecting both services over a Cloudflare Tunnel |
| [Troubleshooting](llm-security-engine/docs/troubleshooting.md) | Common errors and how to fix them |
| [Using real logs](llm-security-engine/docs/using_real_logs.md) | Adapting Suricata / Zeek / Syslog output |
| [Wazuh integration](llm-security-engine/docs/integration_wazuh.md) | Connect Wazuh alerts to the engine; write results back to Elasticsearch |
| [Elastic SIEM integration](llm-security-engine/docs/integration_elk.md) | Connect Elastic SIEM detection alerts; Logstash pipeline option |
| [Splunk integration](llm-security-engine/docs/integration_splunk.md) | Polling script, HEC output, and Splunk Custom Alert Action adapter |
| [Integration contract](llm-security-engine/docs/integration_contract.md) | Field-level API contract between services |
| [Production gap](llm-security-engine/docs/production_gap.md) | What is missing before production SOC deployment |

---

## Testing

```bash
# Python engine — 126 unit tests (no Ollama required)
cd llm-security-engine
pip install -r requirements-dev.txt
python -m pytest tests/ -v

# SOC Backend — 92 unit tests
cd soc-backend
pnpm install
pnpm run test
```

All tests use mocks — no running Ollama instance required.

---

## Configuration

The engine is configured via environment variables (copy `.env.example` to `.env` inside `llm-security-engine/`):

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API URL |
| `OLLAMA_MODEL` | `phi4-mini` | Model name for inference |
| `OLLAMA_TIMEOUT` | `60` | Request timeout in seconds |
| `LOCAL_LLM_API_KEY` | *(unset)* | Optional inbound API key for all engine endpoints |
| `RATE_LIMIT_ENABLED` | `true` | Enable per-IP sliding-window rate limiting |
| `RATE_LIMIT_REQUESTS` | `60` | Max requests per window |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Window size in seconds |

Full configuration reference: [`llm-security-engine/README.md`](llm-security-engine/README.md)

---

## Repository Structure

```
local-llm-security-engine/
├── llm-security-engine/          # Python FastAPI inference service
│   ├── app/
│   │   ├── main.py               # FastAPI app, middleware registration
│   │   ├── config.py             # Pydantic settings from environment
│   │   ├── middleware/           # Auth, rate limiting, request ID
│   │   ├── models/schemas.py     # Request/response Pydantic models
│   │   ├── routes/               # /analyze-event, /analyze-context, /health
│   │   └── services/             # Ollama client, prompt builder, parser, validator
│   ├── docs/                     # Full documentation set (8 guides)
│   ├── tests/                    # 126 unit tests
│   ├── samples/                  # curl and Python examples
│   └── README.md                 # Engine-specific reference
├── soc-backend/                  # TypeScript Express SOC integration layer
│   ├── src/
│   │   ├── routes/analyze.ts     # POST /api/analyze
│   │   ├── providers/            # Local engine client + contract validation
│   │   └── middleware/           # Auth, rate limiting, request ID
│   └── tests/                    # 92 unit tests
├── openapi/                      # OpenAPI 3.1 contract (shared by both services)
└── README.md                     # This file
```

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Security

To report a security vulnerability, please follow the process in [SECURITY.md](SECURITY.md). Do not open a public GitHub issue for security-related findings.
