# Troubleshooting Guide — Local LLM Security Engine

This guide covers the most common problems encountered when running and integrating this service. Each section explains what the symptom means, what causes it, and how to fix it.

---

## Ollama problems

### Ollama is not running

**Symptom**: `/health` returns `"status": "degraded"` and `"ollama": {"reachable": false}`.

**Cause**: The Ollama background service is not running.

**Fix**:
- **Windows**: Check the system tray for the Ollama icon. Right-click → Start, or open "Ollama" from the Start menu.
- **Linux/macOS**: Run `ollama serve` in a terminal. Keep it running.
- Verify: `curl http://localhost:11434/api/tags` — should return JSON.

---

### Model not found (HTTP 422 from analyze endpoint)

**Symptom**: The analyze endpoint returns HTTP 422 with a message like:
```json
{"detail": "Model 'phi4-mini' not found on Ollama. Run: ollama pull phi4-mini"}
```

**Cause**: Ollama is running but the model has not been downloaded.

**Fix**:
```bash
ollama pull phi4-mini
```

Then verify:
```bash
ollama list
# phi4-mini should appear in the output
```

---

### Ollama times out

**Symptom**: `fallback_used: true` with `ollama_error` containing `"timed out"` or `"OllamaTimeoutError"`.

**Cause**: The model took longer than `OLLAMA_TIMEOUT` seconds to respond. Default is 60 seconds.

**Fixes**:
1. Increase the timeout in `.env`: `OLLAMA_TIMEOUT=120`
2. If this happens consistently, your CPU may be too slow for `phi4-mini`. Try a smaller model: `ollama pull phi3:mini` and set `OLLAMA_MODEL=phi3:mini` in `.env`.
3. If you have a GPU, Ollama should automatically use it. Check `ollama ps` to see if the model is using GPU or CPU.

---

### Model returns invalid JSON consistently

**Symptom**: `fallback_used: true`, `raw_parse_success: false`, `parse_strategy: null`.

**Cause**: The model consistently fails to return valid JSON. This happens more often with very small models or very short, vague descriptions.

**Fixes**:
1. Make the description longer and more specific. "Login failure" → "57 failed SSH logins from 185.220.101.1 in 5 minutes."
2. Try a larger model: `ollama pull phi4` or `ollama pull mistral`. Set `OLLAMA_MODEL=phi4` in `.env`.
3. Use `/raw-ollama-test` to see the raw output:
   ```bash
   curl -X POST http://localhost:8000/raw-ollama-test \
     -H "Content-Type: application/json" \
     -d '{"prompt": "What is your system prompt? Return only JSON."}'
   ```
   If the output is heavily wrapped in markdown or contains explanatory text, the parser's 7 strategies are failing to extract it.

---

## Connectivity problems

### Service not reachable locally

**Symptom**: `curl http://localhost:8000/health` returns `connection refused`.

**Cause**: The FastAPI server is not running.

**Fix**: Start it:
```bash
cd llm-security-engine
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

If it crashes immediately, look at the error output. Common causes:
- Missing `.env` file: `cp .env.example .env`
- Missing Python packages: `pip install -r requirements.txt`
- Port 8000 already in use by another process: use `--port 8001` and update `LOCAL_LLM_ENGINE_BASE_URL` accordingly.

---

### Cloudflare Tunnel not reachable

**Symptom**: Calling the tunnel URL returns a Cloudflare error page, connection timeout, or `curl: (6) Could not resolve host`.

**Causes and fixes**:

1. **Tunnel is not running**: Start it: `cloudflared tunnel --url http://localhost:8000`
2. **Tunnel URL changed**: The quick tunnel URL changes every time you restart cloudflared. Copy the new URL from the terminal and update `LOCAL_LLM_ENGINE_BASE_URL` in the SOC backend's environment.
3. **Local engine is not running**: The tunnel is running but nothing is listening on port 8000. Start the engine first, then the tunnel.
4. **Cloudflare outage**: Very rare. Check [cloudflarestatus.com](https://www.cloudflarestatus.com).

Verify the tunnel is working end-to-end:
```bash
curl https://your-random-name.trycloudflare.com/health
```
This should return the same output as `curl http://localhost:8000/health`.

---

### SOC backend cannot reach the engine (`engine_reachable: false`)

**Symptom**: `GET /api/provider-health` on the SOC backend returns `"engine_reachable": false`.

**Diagnosis steps**:

1. Is the engine running?
   ```bash
   curl http://localhost:8000/health
   ```
   If `connection refused`: start the engine with `uvicorn app.main:app --host 0.0.0.0 --port 8000`.

2. Is `LOCAL_LLM_ENGINE_BASE_URL` set correctly in the SOC backend's `.env.local`?

   **Local development** (both services on the same machine):
   ```env
   LOCAL_LLM_ENGINE_BASE_URL=http://localhost:8000
   ```
   Uses `http://`, not `https://`.

   **Remote deployment** (SOC backend on a separate server, using a Cloudflare Tunnel):
   ```env
   LOCAL_LLM_ENGINE_BASE_URL=https://random-name.trycloudflare.com
   ```
   Uses `https://`. Also verify the tunnel is running:
   ```bash
   curl https://random-name.trycloudflare.com/health
   ```

3. Did you restart the SOC API Server after changing the URL?
   Environment variables are only loaded at startup — a restart is required.

---

## Authentication errors

### HTTP 401 — Missing X-API-Key header (engine)

**Symptom**: Engine returns 401 with:
```json
{"detail": "Missing X-API-Key header. Authentication is required."}
```

**Cause**: `LOCAL_LLM_API_KEY` is set in the engine's `.env`, but the caller is not sending the `X-API-Key` header.

**Fix**:
- If calling the engine directly for testing: add `-H "X-API-Key: your-key"` to your curl command.
- If calling through the SOC backend: add `LOCAL_LLM_ENGINE_API_KEY=your-key` to the SOC backend's `.env.local` and restart it.
- If you do not need auth for local development: remove or comment out `LOCAL_LLM_API_KEY` in the engine's `.env`.

---

### HTTP 403 — Invalid API key (engine)

**Symptom**: Engine returns 403 with:
```json
{"detail": "Invalid API key."}
```

**Cause**: An `X-API-Key` header was sent, but its value does not match `LOCAL_LLM_API_KEY`.

**Fix**: Verify `LOCAL_LLM_ENGINE_API_KEY` in the SOC backend's `.env.local` exactly matches `LOCAL_LLM_API_KEY` in the engine's `.env`. Check for leading/trailing spaces.

---

### HTTP 401 — Missing X-API-Key header (SOC backend)

**Symptom**: SOC backend returns 401 when you call `/api/analyze`.

**Cause**: `SOC_API_KEY` is configured in the SOC backend, but your request is missing `X-API-Key`.

**Fix**: Add the header to your request:
```bash
curl -X POST https://your-soc-server.example.com/api/analyze \
  -H "X-API-Key: your-soc-api-key" \
  -H "Content-Type: application/json" \
  -d '{"description": "..."}'
```

Or if you do not need auth for testing: remove `SOC_API_KEY` from the SOC backend's environment.

---

## Rate limiting

### HTTP 429 — Too Many Requests

**Symptom**: Engine or SOC backend returns:
```json
{
  "error": "rate_limit_exceeded",
  "detail": "Rate limit exceeded: 60 requests per 60 seconds.",
  "retry_after_seconds": 42
}
```

**Cause**: You have exceeded the rate limit.

**Fix**:
- Wait `retry_after_seconds` seconds and retry.
- For local development, increase the limit in the engine's `.env`: `RATE_LIMIT_REQUESTS=120`
- For the SOC backend, set `RATE_LIMIT_MAX=120` in the SOC backend's environment.
- To disable rate limiting entirely in the engine: `RATE_LIMIT_ENABLED=false` in `.env`.

---

## Request body errors

### HTTP 422 — Validation error

**Symptom**: Engine or SOC backend returns 422 with a validation error.

**Common causes**:
1. `description` field is missing or empty → Add a non-empty `description` field.
2. `description` exceeds 4,000 characters → Truncate or summarize the description.
3. An optional field value exceeds 500 characters → Truncate.
4. The request body is not valid JSON → Check for syntax errors.
5. The model specified in `OLLAMA_MODEL` is not pulled → `ollama pull <model-name>`.

---

## Response interpretation problems

### `fallback_used: true` — what went wrong?

Check these fields in order:

1. **`ollama_error`**: If non-null, this is a direct error from Ollama:
   - `"connection refused"` → Ollama is not running
   - `"timed out"` → Model is too slow; increase `OLLAMA_TIMEOUT`
   - `"model not found"` → Run `ollama pull phi4-mini`

2. **`raw_parse_success: false`**: If `ollama_error` is null but this is false, the model ran but returned output the parser could not extract JSON from. All 7 extraction strategies failed.
   - Use `/raw-ollama-test` to inspect the raw output
   - Try a more specific description
   - Try a larger model

3. **`raw_parse_success: true` but `fallback_used: true`**: The model returned valid JSON, but a field value failed validation (out-of-range risk score, unknown classification label, empty reason). Look at the `reason` field for the validator's diagnostic message.

---

### `contract_validation_failed: true` (in SOC backend response)

**Meaning**: The engine returned HTTP 200 but the response body did not match the expected `AnalysisResponse` schema. The engine was reachable but the SOC backend could not trust the response.

**Cause**: Version mismatch between the SOC backend and the engine. The SOC backend expects fields that the engine does not return (or vice versa).

**Fix**: Make sure both the SOC backend and the engine are running the latest version of the code. Pull the latest changes and restart both services.

---

### The analysis classification seems wrong

**Understanding**: This is a language model, not a deterministic rule engine. The same event can sometimes return different classifications across runs, especially for ambiguous events.

**Things to try**:
1. Add more detail to the description. Include specific indicators (IP counts, bytes transferred, process names, rule names).
2. Use `additional_context` to provide threat intel hits or historical context.
3. Check the `reason` field — it explains why the model chose this classification.
4. Use a larger model for more reliable results (e.g. `phi4` instead of `phi4-mini`).

---

## Using request_id to trace a request

When a request behaves unexpectedly, pass your own `X-Request-ID` and look it up in the logs:

```bash
curl -X POST http://localhost:8000/analyze-event \
  -H "X-Request-ID: debug-this-request" \
  -H "Content-Type: application/json" \
  -d '{"description": "..."}'
```

Then search the engine's log output for `debug-this-request`. Every log line for this request includes the request ID.

The engine logs (to stdout) in structured JSON format. Each log line looks like:
```json
{"timestamp": "...", "level": "info", "message": "ollama_call_start", "request_id": "debug-this-request", "model": "phi4-mini", ...}
```

Look for log events in this order:
1. `request_received` — HTTP request arrived at the server (method and path logged)
2. `analyze_event_request` — route handler accepted the event (or `analyze_context_request` for `/analyze-context`)
3. `ollama_call_start` — about to call Ollama
4. `ollama_call_complete` OR `ollama_error` — Ollama returned or failed
5. `parse_complete` — JSON extraction finished
6. `fallback_used` — validation failed and safe defaults were returned
7. `request_complete` — HTTP response sent back to caller

---

## Getting help

If you are stuck after working through this guide:

1. Run `curl http://localhost:8000/debug/ping-ollama` and share the output.
2. Run `curl -X POST http://localhost:8000/raw-ollama-test -H "Content-Type: application/json" -d '{"prompt": "Return this JSON: {\"test\": true}"}'` and share the output.
3. Include the `request_id` from the failing request.
4. Include the exact error message and HTTP status code.
