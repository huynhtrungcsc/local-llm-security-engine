# Splunk Integration Guide

This guide explains two ways to connect Splunk to the Local LLM Security Engine: a polling script that queries Splunk's REST API, and a webhook-based approach using Splunk Custom Alert Actions.

---

## Architecture

### Option A — Polling script (recommended for getting started)

```
Splunk Indexers
        │ logs indexed
        ▼
Splunk Correlation Searches → Notable Events (in itsi_notable_events or similar)
        │
┌───────┘  poll via Splunk REST API
▼
Integration script (Python + splunklib)
        │ POST /api/analyze
        ▼
SOC Backend (soc-backend/)
        │ POST /analyze-event
        ▼
LLM Security Engine (llm-security-engine/)
        │ Ollama inference (local)
        ▼
AnalysisResult
        │ write back via HEC
        ▼
Splunk index: soc_enrichments
        │
        ▼
Splunk dashboard / Enterprise Security (ES) case enrichment
```

### Option B — Custom Alert Action (webhook)

```
Splunk alert fires
        │ POST (custom alert action)
        ▼
SOC Backend → Engine → Analysis result → HEC back to Splunk
```

---

## Prerequisites

- Splunk Enterprise 8.x or 9.x (or Splunk Cloud)
- Splunk Enterprise Security (optional, for notable events)
- SOC backend running: `pnpm run dev` (port 3000)
- LLM Security Engine running: `uvicorn app.main:app --port 8000`
- Python 3.10+ with packages: `pip install splunk-sdk requests`
- Splunk HTTP Event Collector (HEC) enabled (to write results back)
- Splunk user with `search` capability and access to relevant indexes

---

## Step 1 — Enable Splunk HTTP Event Collector (HEC)

HEC lets the integration script write analysis results back to Splunk.

1. Splunk Web → Settings → Data inputs → HTTP Event Collector → Add new
2. Name: `soc-enrichments`, Source type: `_json`
3. Copy the generated **HEC token**
4. Settings → HTTP Event Collector → Global Settings → set port to `8088` (default)

Note the HEC token — you will need it in the integration script.

---

## Step 2 — Understand Splunk notable events / search results

Splunk notable events (from Splunk ES correlation searches) are stored in `notable` index. A typical search result:

```
rule_name=Brute Force Access Behavior Detected
src=192.168.1.100
dest=10.0.0.5
user=jdoe
urgency=high
event_category=Authentication
count=147
first_time=2024-01-15T14:00:00.000Z
last_time=2024-01-15T14:23:00.000Z
event_id=abc123def456
```

If you are not using Splunk ES, you can query any Splunk search that produces structured events.

---

## Step 3 — Map Splunk fields to the SOC backend input

| SOC backend field    | Required | Splunk ES notable event source              |
|----------------------|----------|---------------------------------------------|
| `description`        | Yes      | Build from `rule_name` + key details        |
| `source_ip`          | No       | `src`                                       |
| `destination_ip`     | No       | `dest`                                      |
| `event_type`         | No       | `event_category` or `type`                  |
| `severity`           | No       | `urgency` (low/medium/high/critical)        |
| `timestamp`          | No       | `last_time` (ISO 8601)                      |
| `additional_context` | No       | `user`, `count`, `first_time`, `src_zone`   |

**Building a good `description`:**

```python
# Weak:
"Brute Force Access Behavior Detected"

# Better:
"Brute force attack detected: 147 failed login attempts for user jdoe "
"from source IP 192.168.1.100 to 10.0.0.5 over a 23-minute window. "
"Splunk ES rule: Brute Force Access Behavior Detected (urgency: high)"
```

---

## Step 4 — Option A: Polling script

Save as `splunk_integration.py`:

```python
"""
Splunk Enterprise Security → SOC Backend integration script.

Searches for notable events above a threshold urgency, sends each to the
SOC backend for LLM analysis, and writes results back to Splunk via HEC.

Usage:
    pip install splunk-sdk requests
    python splunk_integration.py

Environment variables:
    SPLUNK_HOST           Splunk host (default: localhost)
    SPLUNK_PORT           Splunk management port (default: 8089)
    SPLUNK_USER           Splunk username
    SPLUNK_PASS           Splunk password
    SPLUNK_TOKEN          Splunk session token (alternative to user/pass)
    HEC_URL               HEC endpoint (default: http://localhost:8088)
    HEC_TOKEN             HEC authentication token
    SOC_BACKEND_URL       SOC backend URL (default: http://localhost:3000)
    SOC_API_KEY           SOC backend API key (optional)
    MIN_URGENCY           Minimum urgency: low|medium|high|critical (default: medium)
    POLL_INTERVAL_SEC     Seconds between polls (default: 60)
"""

import os
import time
import datetime
import requests
import splunklib.client as splunk_client
import splunklib.results as splunk_results

# ── Configuration ─────────────────────────────────────────────────────────────

SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.environ.get("SPLUNK_PORT", "8089"))
SPLUNK_USER = os.environ.get("SPLUNK_USER", "admin")
SPLUNK_PASS = os.environ.get("SPLUNK_PASS", "")
HEC_URL     = os.environ.get("HEC_URL",     "http://localhost:8088/services/collector/event")
HEC_TOKEN   = os.environ.get("HEC_TOKEN",   "")
SOC_URL     = os.environ.get("SOC_BACKEND_URL", "http://localhost:3000")
SOC_KEY     = os.environ.get("SOC_API_KEY",     "")
POLL_SEC    = int(os.environ.get("POLL_INTERVAL_SEC", "60"))

URGENCY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
MIN_URGENCY  = os.environ.get("MIN_URGENCY", "medium")
MIN_RANK     = URGENCY_RANK.get(MIN_URGENCY, 1)

# ── Splunk client ─────────────────────────────────────────────────────────────

service = splunk_client.connect(
    host=SPLUNK_HOST,
    port=SPLUNK_PORT,
    username=SPLUNK_USER,
    password=SPLUNK_PASS,
)

# ── Helpers ────────────────────────────────────────────────────────────────────

def build_description(event: dict) -> str:
    rule_name  = event.get("rule_name")   or event.get("search_name", "Unknown Splunk alert")
    urgency    = event.get("urgency",     "")
    src        = event.get("src",         "")
    dest       = event.get("dest",        "")
    user       = event.get("user",        "")
    count      = event.get("count",       "")
    first_time = event.get("first_time",  "")
    last_time  = event.get("last_time",   "")

    parts = [f"Splunk ES notable event: {rule_name}"]
    if user:       parts.append(f"for user {user}")
    if src:        parts.append(f"from source IP {src}")
    if dest:       parts.append(f"to destination {dest}")
    if count:      parts.append(f"occurred {count} times")
    if first_time and last_time:
        parts.append(f"between {first_time} and {last_time}")
    if urgency:    parts.append(f"Urgency: {urgency}")

    return ". ".join(parts)

def build_additional_context(event: dict) -> str | None:
    ctx = []
    if event.get("user"):       ctx.append(f"User: {event['user']}")
    if event.get("src_zone"):   ctx.append(f"Source zone: {event['src_zone']}")
    if event.get("dest_zone"):  ctx.append(f"Dest zone: {event['dest_zone']}")
    if event.get("signature"):  ctx.append(f"Signature: {event['signature']}")
    return ". ".join(ctx) if ctx else None

def build_soc_alert(event: dict) -> dict:
    return {
        "description":        build_description(event),
        "source_ip":          event.get("src")           or None,
        "destination_ip":     event.get("dest")          or None,
        "event_type":         event.get("event_category") or event.get("type") or None,
        "severity":           event.get("urgency")        or None,
        "timestamp":          event.get("last_time")      or None,
        "additional_context": build_additional_context(event),
    }

def call_soc_backend(body: dict, event_id: str) -> dict | None:
    headers = {"Content-Type": "application/json", "X-Request-ID": event_id}
    if SOC_KEY:
        headers["X-API-Key"] = SOC_KEY
    try:
        resp = requests.post(f"{SOC_URL}/api/analyze", json=body,
                             headers=headers, timeout=120)
        if resp.status_code == 429:
            retry = resp.json().get("retry_after_seconds", 60)
            print(f"[WARN] Rate limited — sleeping {retry}s")
            time.sleep(retry)
            return None
        if resp.status_code in (422, 503):
            print(f"[WARN] {resp.status_code} for event {event_id}: {resp.text[:200]}")
            return None
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[ERROR] SOC backend error for {event_id}: {e}")
        return None

def write_to_hec(event_id: str, splunk_event: dict, analysis: dict) -> None:
    if not HEC_TOKEN:
        print(f"[SKIP] HEC_TOKEN not set — not writing result for {event_id}")
        return
    payload = {
        "time":       time.time(),
        "sourcetype": "soc_enrichment",
        "index":      "soc_enrichments",
        "event": {
            "splunk_event_id":           event_id,
            "splunk_rule_name":          splunk_event.get("rule_name") or splunk_event.get("search_name"),
            "splunk_urgency":            splunk_event.get("urgency"),
            "attack_classification":     analysis["attack_classification"],
            "risk_score":                analysis["risk_score"],
            "false_positive_likelihood": analysis["false_positive_likelihood"],
            "reason":                    analysis["reason"],
            "fallback_used":             analysis["fallback_used"],
            "model_used":                analysis.get("model_used"),
            "latency_ms":                analysis.get("latency_ms"),
            "ts":                        datetime.datetime.utcnow().isoformat() + "Z",
        }
    }
    try:
        resp = requests.post(
            HEC_URL, json=payload,
            headers={"Authorization": f"Splunk {HEC_TOKEN}"},
            timeout=10,
        )
        resp.raise_for_status()
        print(f"[OK] {event_id[:12]}… → {analysis['attack_classification']} "
              f"(risk={analysis['risk_score']}, fallback={analysis['fallback_used']})")
    except Exception as e:
        print(f"[ERROR] HEC write failed for {event_id}: {e}")

def search_notable_events(earliest: str) -> list[dict]:
    """Search for Splunk ES notable events above MIN_URGENCY since `earliest`."""
    spl = (
        f"search index=notable earliest={earliest} latest=now "
        f"| eval urgency_rank=case(urgency=\"low\",0, urgency=\"medium\",1, "
        f"urgency=\"high\",2, urgency=\"critical\",3, true(),0) "
        f"| where urgency_rank>={MIN_RANK} "
        f"| fields rule_name,search_name,src,dest,user,urgency,event_category,"
        f"type,count,first_time,last_time,event_id,src_zone,dest_zone,signature "
        f"| sort +_time | head 50"
    )
    job = service.jobs.create(spl, exec_mode="blocking")
    results = []
    for result in splunk_results.JSONResultsReader(job.results(output_mode="json")):
        if isinstance(result, dict):
            results.append(result)
    return results

# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    print(f"Starting Splunk integration: polling every {POLL_SEC}s, min urgency: {MIN_URGENCY}")
    print(f"Splunk: {SPLUNK_HOST}:{SPLUNK_PORT}  |  SOC backend: {SOC_URL}")

    earliest = "-5m"  # Start from 5 minutes ago on first run

    while True:
        events = search_notable_events(earliest)
        print(f"Found {len(events)} notable events (urgency >= {MIN_URGENCY})")

        for event in events:
            event_id  = event.get("event_id") or event.get("rule_name", "unknown")
            soc_alert = build_soc_alert(event)
            analysis  = call_soc_backend(soc_alert, str(event_id))
            if analysis:
                write_to_hec(str(event_id), event, analysis)
            time.sleep(2)  # pace requests — Ollama inference takes 15-60s on CPU

        earliest = "-1m"  # Switch to 1-minute window after first poll
        time.sleep(POLL_SEC)

if __name__ == "__main__":
    main()
```

---

## Step 5 — Option B: Splunk Custom Alert Action (webhook)

Instead of polling, configure Splunk to call the SOC backend directly when a correlation search fires.

1. **Create a Splunk alert** from any search:
   - Search → Save as Alert → Trigger Actions → Add Actions → Webhook
   - Webhook URL: `http://localhost:3000/api/analyze`
   - Note: the webhook body format doesn't match the SOC backend's schema directly

2. **The problem**: Splunk's built-in webhook sends a different JSON structure. You need a thin adapter. Save as `splunk_webhook_adapter.py` and run it on port 5000:

```python
"""
Thin adapter that receives Splunk webhook payloads and reformats them
for the SOC backend. Run on port 5000.

Usage:
    pip install flask requests
    python splunk_webhook_adapter.py
"""

from flask import Flask, request, jsonify
import requests, os

app = Flask(__name__)
SOC_URL = os.environ.get("SOC_BACKEND_URL", "http://localhost:3000")
SOC_KEY = os.environ.get("SOC_API_KEY", "")

@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_json(force=True) or {}
    results = payload.get("result", {})

    # Build description from Splunk's search result fields
    search_name = payload.get("search_name", "Splunk alert")
    src   = results.get("src", "")
    dest  = results.get("dest", "")
    user  = results.get("user", "")
    count = results.get("count", "")

    desc_parts = [f"Splunk alert: {search_name}"]
    if user:  desc_parts.append(f"for user {user}")
    if src:   desc_parts.append(f"from {src}")
    if dest:  desc_parts.append(f"to {dest}")
    if count: desc_parts.append(f"({count} occurrences)")

    soc_alert = {
        "description":    ". ".join(desc_parts),
        "source_ip":      src  or None,
        "destination_ip": dest or None,
        "severity":       results.get("urgency") or None,
        "timestamp":      results.get("_time")   or None,
    }

    headers = {"Content-Type": "application/json"}
    if SOC_KEY:
        headers["X-API-Key"] = SOC_KEY

    resp = requests.post(f"{SOC_URL}/api/analyze", json=soc_alert,
                         headers=headers, timeout=120)
    return jsonify(resp.json()), resp.status_code

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

Then set the Splunk webhook URL to `http://localhost:5000/webhook`.

---

## Step 6 — View results in Splunk

After results are written via HEC to the `soc_enrichments` index:

```spl
index=soc_enrichments
| table ts, splunk_rule_name, attack_classification, risk_score, false_positive_likelihood, reason, fallback_used
| sort -risk_score
```

**Dashboard panel — attack classification breakdown:**
```spl
index=soc_enrichments
| stats count by attack_classification
| sort -count
```

**Find likely false positives to tune your correlation searches:**
```spl
index=soc_enrichments false_positive_likelihood>0.6
| table ts, splunk_rule_name, reason
```

**Correlate enrichment with notable event by `event_id`:**
```spl
index=notable OR index=soc_enrichments
| eval join_key=coalesce(event_id, splunk_event_id)
| stats values(*) as * by join_key
```

---

## Common issues

**`HTTPError: 401` from Splunk REST API:**
- Check `SPLUNK_USER` and `SPLUNK_PASS`
- The user needs the `search` role and access to the `notable` index

**HEC writes fail with `400 Invalid token`:**
- The HEC token is wrong or HEC is not enabled
- Verify: Splunk Web → Settings → Data inputs → HTTP Event Collector

**No notable events returned:**
- Splunk ES must have correlation searches enabled and firing
- Try changing `earliest=-24h` to search a wider window for testing
- Confirm there are events in: `index=notable | head 5`

**`fallback_used: true` on all results:**
- LLM engine unreachable: `curl http://localhost:8000/health`
- SOC backend not configured: `curl http://localhost:3000/api/provider-health`
- Ollama inference timeout: increase `LOCAL_LLM_ENGINE_TIMEOUT_MS=120000` in `soc-backend/.env.local`
