# local-llm-security-engine

Local LLM inference service for structured cybersecurity log analysis using Ollama.

## Overview

This repository contains two tightly integrated services:

| Component | Path | Language | Purpose |
|-----------|------|----------|---------|
| **LLM Security Engine** | `llm-security-engine/` | Python 3.11 / FastAPI | Runs local LLM inference via Ollama; classifies security events into structured JSON |
| **SOC Backend** | `soc-backend/` | TypeScript / Express | Receives raw security alerts, calls the engine, returns normalised analysis to downstream consumers |

The `openapi/` directory contains the shared OpenAPI 3.1 contract that both services conform to.

## Quick start

**Prerequisites:** Python 3.11+, Node.js 20+, [Ollama](https://ollama.com) with a model pulled (e.g. `ollama pull phi4-mini`).

```bash
# 1. Start the LLM Security Engine
cd llm-security-engine
pip install -r requirements.txt
cp .env.example .env   # edit as needed
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 2. Start the SOC Backend (separate terminal)
cd soc-backend
npm install
LOCAL_LLM_ENGINE_BASE_URL=http://localhost:8000 \
LOCAL_LLM_ENGINE_API_KEY=your-key \
npm run dev
```

Full setup instructions are in [`llm-security-engine/docs/getting_started.md`](llm-security-engine/docs/getting_started.md).

## Architecture

```
[Security alert source]
        │
        ▼
┌─────────────────┐   POST /api/analyze   ┌───────────────────────────┐
│   SOC Backend   │ ─────────────────────▶│   LLM Security Engine     │
│  (TypeScript)   │                        │  (Python / FastAPI)       │
│  soc-backend/   │ ◀─────────────────────│  llm-security-engine/     │
└─────────────────┘  structured analysis  │  → Ollama (local model)   │
                                          └───────────────────────────┘
```

The engine exposes a stable REST API. The SOC backend validates every response against the OpenAPI contract before forwarding it downstream — any contract violation is flagged as a `fallback_used` event rather than silently accepted.

## Documentation

| Document | Description |
|----------|-------------|
| [Getting started](llm-security-engine/docs/getting_started.md) | Step-by-step local setup |
| [Architecture walkthrough](llm-security-engine/docs/architecture_walkthrough.md) | Code paths, data flow, component roles |
| [Real usage guide](llm-security-engine/docs/real_usage_guide.md) | Annotated request/response examples |
| [End-to-end integration](llm-security-engine/docs/end_to_end_integration.md) | Connecting both services over a tunnel |
| [Troubleshooting](llm-security-engine/docs/troubleshooting.md) | Common errors and fixes |
| [Using real logs](llm-security-engine/docs/using_real_logs.md) | Adapting Suricata / Zeek / Syslog output |
| [Integration contract](llm-security-engine/docs/integration_contract.md) | Field-level contract between services |

## Testing

```bash
# Python engine — 125 unit tests
cd llm-security-engine
pip install -r requirements-dev.txt
python -m pytest tests/ -v

# SOC backend — 92 unit + E2E tests
cd soc-backend
npm install
npm test
```

## Configuration

See [`llm-security-engine/.env.example`](llm-security-engine/.env.example) for the full list of engine configuration variables and [`llm-security-engine/README.md`](llm-security-engine/README.md) for detailed descriptions.

## License

MIT
