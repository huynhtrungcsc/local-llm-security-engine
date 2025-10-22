# Getting Started — Local LLM Security Engine

This guide walks you through everything you need to run this service from scratch. It assumes you are working on a Windows, Linux, or macOS machine and have Python installed. It does not assume any prior experience with Ollama or FastAPI.

---

## What you will have at the end of this guide

- Ollama running locally with the `phi4-mini` model
- The Local LLM Security Engine running on port 8000
- A verified working test against the API

The whole process takes about 10–15 minutes, depending on your download speed.

---

## Step 1 — Prerequisites

Before you start, check you have these installed:

### Python 3.10 or newer

```bash
python --version
# or on some systems:
python3 --version
```

If you see `Python 3.10.x` or higher, you are ready. If not, download from [python.org](https://www.python.org/downloads/).

### pip (Python package installer)

```bash
pip --version
```

pip comes with Python. If it is missing, run:
```bash
python -m ensurepip --upgrade
```

---

## Step 2 — Install Ollama

Ollama is the tool that runs language models locally on your machine. Download and install it from:

**https://ollama.ai**

Choose the installer for your operating system:
- **Windows**: Download the `.exe` installer and run it. Ollama installs as a background service.
- **macOS**: Download the `.dmg` file. Ollama runs in the menu bar.
- **Linux**: Run the install script shown on the Ollama website:
  ```bash
  curl -fsSL https://ollama.ai/install.sh | sh
  ```

After installation, Ollama starts automatically and listens on `http://localhost:11434`.

### Verify Ollama is running

```bash
curl http://localhost:11434/api/tags
```

You should see a JSON response (even if empty). If you get `connection refused`, Ollama is not running yet. On Windows, check the system tray. On Linux, you may need to start it manually:

```bash
ollama serve
```

---

## Step 3 — Pull the phi4-mini model

`phi4-mini` is a compact model from Microsoft that fits in 2–4 GB of RAM and runs well on a CPU. It is the default model for this service.

```bash
ollama pull phi4-mini
```

This downloads the model file. It takes 2–5 minutes on a typical connection. You will see a progress bar.

When it finishes, verify the model is available:

```bash
ollama list
```

You should see `phi4-mini` in the output.

> **Using a different model?** You can use any Ollama-compatible model. Just set `OLLAMA_MODEL=your-model-name` in your `.env` file and pull it with `ollama pull your-model-name`. Larger models (like `llama3`, `mistral`, or `phi4`) will give better results but require more RAM and are slower.

---

## Step 4 — Install Python dependencies

Navigate to the `llm-security-engine` directory and install the required packages:

```bash
cd llm-security-engine
pip install -r requirements.txt
```

This installs FastAPI, Uvicorn, httpx, Pydantic, and a few other small libraries. It takes about 30 seconds.

If you want to run the test suite, also install the development dependencies:

```bash
pip install -r requirements-dev.txt
```

> **Note**: If you are on a shared Python environment and do not want to install globally, create a virtual environment first:
> ```bash
> python -m venv venv
> # Windows:
> venv\Scripts\activate
> # Linux/macOS:
> source venv/bin/activate
> ```
> Then run `pip install -r requirements.txt`.

---

## Step 5 — Configure the service

Copy the example configuration file:

```bash
# Windows:
copy .env.example .env

# Linux/macOS:
cp .env.example .env
```

Open `.env` in a text editor. For a basic local setup, the defaults are fine:

```env
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=phi4-mini
OLLAMA_TIMEOUT=60
DEBUG=false
API_HOST=0.0.0.0
API_PORT=8000
```

You do not need to set an API key for local development. Leave `LOCAL_LLM_API_KEY` commented out.

---

## Step 6 — Start the server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

> If you changed `API_PORT` in `.env` to something other than 8000, update the `--port` value in this command to match.

You should see output similar to:

```
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

The `--reload` flag can be added for development (restarts the server when you change a file):

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Leave this terminal open. The server runs until you press `CTRL+C`.

> **Make sure you are in the `llm-security-engine/` directory** before running this command. If you navigated somewhere else since Step 4, run `cd llm-security-engine` again first.

---

## Step 7 — Verify everything is working

Open a new terminal (keep the server running) and run these checks in order:

### Check the service is up

```bash
curl http://localhost:8000/health
```

Expected output:
```json
{
  "status": "ok",
  "service": "Local LLM Security Engine",
  "version": "1.0.0",
  "config": { "ollama_model": "phi4-mini", ... },
  "ollama": { "reachable": true, "model_available": true, ... }
}
```

If `status` is `"ok"` and `ollama.reachable` is `true`, everything is connected correctly.

If `status` is `"degraded"`, Ollama is not reachable. Check Step 2 and restart Ollama.

### Send a test security event

```bash
curl -X POST http://localhost:8000/analyze-event \
  -H "Content-Type: application/json" \
  -d '{
    "description": "57 failed SSH login attempts followed by one successful login from 185.220.101.1.",
    "source_ip": "185.220.101.1",
    "event_type": "authentication_failure",
    "severity": "high"
  }'
```

This will take 10–60 seconds on a CPU, depending on your machine. **The very first request after starting Ollama may take 1–3 minutes** while the model loads into memory — this is a one-time cost per Ollama restart. Subsequent requests in the same session are faster. You will see a response like:

```json
{
  "attack_classification": "credential_access",
  "false_positive_likelihood": 0.05,
  "risk_score": 88,
  "reason": "High volume of failed SSH logins followed by success from a suspicious external IP suggests brute-force credential access.",
  "fallback_used": false,
  "model_used": "phi4-mini",
  "provider": "ollama",
  "raw_parse_success": true,
  "parse_strategy": "direct",
  "ollama_error": null,
  "request_id": null
}
```

If `fallback_used` is `false` and `attack_classification` is a valid label, the service is working correctly.

### Run the quick test script

From the `llm-security-engine/` directory:

```bash
python test_local.py
```

This script sends a few sample events to the running server and prints the results. It requires both the server and Ollama to be running.

---

## Step 8 — Browse the interactive API docs

FastAPI auto-generates interactive documentation. Open in your browser:

```
http://localhost:8000/docs
```

From there you can explore all endpoints, see request/response schemas, and send test requests directly from the browser — no curl required.

---

## Step 9 — Run the unit tests (optional, no Ollama needed)

The test suite runs entirely with mocks — no running server or Ollama instance required. From the `llm-security-engine/` directory:

```bash
python -m pytest tests/ -v
```

You should see 125 tests all pass.

---

## Common issues at this stage

**"Connection refused" when calling the API:**
The server is not running. Go back to Step 6.

**`status: "degraded"` in `/health` response:**
Ollama is not running or not listening on port 11434. Restart Ollama and check with `curl http://localhost:11434/api/tags`.

**`fallback_used: true` in the analysis response:**
The model returned output that could not be parsed or validated. This can happen with small models on short or ambiguous descriptions. Try a longer, more detailed description.

**Very slow response (over 2 minutes):**
`phi4-mini` runs on CPU if you have no GPU. 30–60 seconds is normal on a modern CPU. If it is consistently over 2 minutes, the model may not be fully loaded — try pulling it again with `ollama pull phi4-mini`.

**Model not found error (HTTP 422):**
You did not pull the model. Run `ollama pull phi4-mini`.

---

## What to read next

- [docs/architecture_walkthrough.md](architecture_walkthrough.md) — understand how all the pieces fit together
- [docs/real_usage_guide.md](real_usage_guide.md) — how to send real events and interpret responses
- [docs/end_to_end_integration.md](end_to_end_integration.md) — connect a SOC backend to this service
