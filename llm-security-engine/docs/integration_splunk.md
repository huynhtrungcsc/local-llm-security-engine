# Splunk Integration Guide

This guide explains two ways to connect Splunk to the Local LLM Security Engine: a polling script that queries Splunk's REST API, and a webhook-based approach using Splunk Custom Alert Actions.

---

## Architecture

### Option A — Polling script (recommended for getting started)

```
Splunk Indexers
        │ logs indexed
        ▼
Splunk Correlation Searches → Notable Events (index=notable)
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
Webhook adapter (Flask) → SOC Backend → Engine → Analysis result → HEC back to Splunk
```

---

## Prerequisites

- Splunk Enterprise 8.x or 9.x (or Splunk Cloud)
- Splunk Enterprise Security (recommended, for notable events)
- SOC backend running: `pnpm run dev` (port 3000)
- LLM Security Engine running: `uvicorn app.main:app --port 8000`
- Python 3.10+ with packages (Option A):
  ```bash
  pip install splunk-sdk requests
  ```
- Python packages (Option B adds Flask):
  ```bash
  pip install splunk-sdk requests flask
  ```
- Splunk HTTP Event Collector (HEC) enabled (to write results back)
- Splunk user with `search` capability and access to relevant indexes

---

## Step 1 — Enable Splunk HTTP Event Collector (HEC)

HEC lets the integration script write analysis results back to Splunk.

1. Splunk Web → Settings → Data inputs → HTTP Event Collector → Add new
2. Name: `soc-enrichments`, Source type: `_json`
3. Copy the generated **HEC token**
4. Settings → HTTP Event Collector → Global Settings → Default index: `soc_enrichments` (create this index first if it doesn't exist)

Default HEC port is `8088`. Note the HEC token — you will need it in the integration script.

---

## Step 2 — Understand Splunk notable events

Splunk notable events (from Splunk ES correlation searches) are stored in the `notable` index. When searched via the REST API, a typical result looks like:

```
rule_name         = Brute Force Access Behavior Detected
src               = 192.168.1.100
dest              = 10.0.0.5
user              = jdoe
urgency           = high
event_category    = Authentication
count             = 147
first_time        = 2024-01-15T14:00:00.000Z
last_time         = 2024-01-15T14:23:00.000Z
_time             = 2024-01-15T14:23:00.000Z
event_hash        = abc123def456
```

The field `event_hash` is the unique identifier for Splunk ES notable events. `_time` is the standard Splunk event timestamp.

If you are not using Splunk ES, adapt the SPL search in the script to match your data.

---

## Step 3 — Map Splunk fields to the SOC backend input

| SOC backend field    | Required | Splunk ES notable event source              |
|----------------------|----------|---------------------------------------------|
| `description`        | Yes      | Build from `rule_name` + key details        |
| `source_ip`          | No       | `src`                                       |
| `destination_ip`     | No       | `dest`                                      |
| `event_type`         | No       | `event_category` or `type`                  |
| `severity`           | No       | `urgency` (low/medium/high/critical)        |
| `timestamp`          | No       | `_time` or `last_time` (ISO 8601)           |
| `additional_context` | No       | `user`, `count`, `first_time`, `src_zone`   |

**Building a good `description`:**

```python
# Weak:
"Brute Force Access Behavior Detected"

# Better:
"Brute force attack detected: 147 failed login attempts for user jdoe "
"from source IP 192.168.1.100 to destination 10.0.0.5 over a 23-minute window. "
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
    SPLUNK_HOST           Splunk management host (default: localhost)
    SPLUNK_PORT           Splunk management port (default: 8089)
    SPLUNK_USER           Splunk username
    SPLUNK_PASS           Splunk password
    SPLUNK_HEC_URL        HEC endpoint (default: http://localhost:8088/services/collector)
    SPLUNK_HEC_TOKEN      HEC token (from Step 1)
    SOC_BACKEND_URL       SOC backend URL (default: http://localhost:3000)
    SOC_API_KEY           SOC backend API key (optional)
    URGENCY_MIN           Minimum urgency to process: low/medium/high/critical (default: high)
    POLL_INTERVAL_SEC     Seconds between polls (default: 60)
"""

import os
import time
import json
import datetime
import requests
import splunklib.client as client
import splunklib.results as results

# ── Configuration ─────────────────────────────────────────────────────────────

SPLUNK_HOST  = os.environ.get("SPLUNK_HOST",      "localhost")
SPLUNK_PORT  = int(os.environ.get("SPLUNK_PORT",  "8089"))
SPLUNK_USER  = os.environ.get("SPLUNK_USER",      "admin")
SPLUNK_PASS  = os.environ.get("SPLUNK_PASS",      "changeme")
HEC_URL      = os.environ.get("SPLUNK_HEC_URL",   "http://localhost:8088/services/collector")
HEC_TOKEN    = os.environ.get("SPLUNK_HEC_TOKEN",  "")
SOC_URL      = os.environ.get("SOC_BACKEND_URL",   "http://localhost:3000")
SOC_KEY      = os.environ.get("SOC_API_KEY",        "")
URGENCY_MIN  = os.environ.get("URGENCY_MIN",        "high")
POLL_SEC     = int(os.environ.get("POLL_INTERVAL_SEC", "60"))

# Urgency ranking for filtering — only process events at or above URGENCY_MIN
URGENCY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MIN_RANK     = URGENCY_RANK.get(URGENCY_MIN.lower(), 3)

# ── Splunk client ─────────────────────────────────────────────────────────────

service = client.connect(
    host=SPLUNK_HOST,
    port=SPLUNK_PORT,
    username=SPLUNK_USER,
    password=SPLUNK_PASS,
)

# ── Helper functions ──────────────────────────────────────────────────────────

def urgency_to_soc(urgency: str) -> str:
    return {"low": "low", "medium": "medium", "high": "high",
            "critical": "critical"}.get(urgency.lower(), "medium")

def build_description(event: dict) -> str:
    rule_name = event.get("rule_name", "Unknown Splunk rule")
    urgency   = event.get("urgency",  "unknown")
    src       = event.get("src",      "")
    dest      = event.get("dest",     "")
    user      = event.get("user",     "")
    count     = event.get("count",    "")

    parts = [f"Splunk ES alert: {rule_name}"]
    if src:   parts.append(f"from source IP {src}")
    if dest:  parts.append(f"to destination {dest}")
    if user:  parts.append(f"involving user {user}")
    if count: parts.append(f"event count: {count}")
    parts.append(f"urgency: {urgency}")
    return ". ".join(parts)

def build_soc_alert(event: dict) -> dict:
    ctx_parts = []
    for field in ("user", "count", "first_time", "src_zone", "dest_zone", "category"):
        val = event.get(field)
        if val:
            ctx_parts.append(f"{field}: {val}")

    return {
        "description":        build_description(event),
        "source_ip":          event.get("src")   or None,
        "destination_ip":     event.get("dest")  or None,
        "event_type":         event.get("event_category") or event.get("type") or None,
        "severity":           urgency_to_soc(event.get("urgency", "medium")),
        "timestamp":          event.get("_time") or event.get("last_time") or None,
        "additional_context": ". ".join(ctx_parts) or None,
    }

def call_soc_backend(body: dict, event_hash: str) -> dict | None:
    headers = {"Content-Type": "application/json", "X-Request-ID": event_hash}
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
            print(f"[WARN] {resp.status_code} for event {event_hash}: {resp.text[:200]}")
            return None
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[ERROR] SOC backend error for {event_hash}: {e}")
        return None

def write_to_hec(event: dict, analysis: dict) -> None:
    payload = {
        "time":       datetime.datetime.now(datetime.timezone.utc).timestamp(),
        "sourcetype": "_json",
        "index":      "soc_enrichments",
        "event": {
            "ts":                        datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "splunk_rule_name":          event.get("rule_name"),
            "splunk_event_hash":         event.get("event_hash"),
            "splunk_urgency":            event.get("urgency"),
            "splunk_src":                event.get("src"),
            "attack_classification":     analysis["attack_classification"],
            "risk_score":                analysis["risk_score"],
            "false_positive_likelihood": analysis["false_positive_likelihood"],
            "reason":                    analysis["reason"],
            "fallback_used":             analysis["fallback_used"],
            "model_used":                analysis.get("model_used"),
            "latency_ms":                analysis.get("latency_ms"),
        },
    }
    resp = requests.post(
        HEC_URL,
        headers={"Authorization": f"Splunk {HEC_TOKEN}"},
        json=payload,
        timeout=10,
    )
    resp.raise_for_status()
    rule = event.get("rule_name", "?")[:40]
    print(f"[OK] {rule!r} → {analysis['attack_classification']} "
          f"(risk={analysis['risk_score']}, fallback={analysis['fallback_used']})")

def search_notable_events(earliest_epoch: int) -> list[dict]:
    """
    Search Splunk for notable events since `earliest_epoch` (Unix timestamp).

    Using an absolute epoch timestamp — not a relative modifier like "-1m" —
    ensures no events are missed even if a poll cycle takes a long time.
    """
    spl = (
        f"search index=notable earliest={earliest_epoch} latest=now "
        f"| where urgency IN (\"high\", \"critical\") "
        f"| fields rule_name, src, dest, user, urgency, event_category, "
        f"         count, first_time, last_time, _time, event_hash"
    )

    job = service.jobs.create(spl, exec_mode="blocking")
    reader = results.JSONResultsReader(job.results(output_mode="json"))

    events = []
    for item in reader:
        if isinstance(item, dict):
            urgency = item.get("urgency", "").lower()
            if URGENCY_RANK.get(urgency, 0) >= MIN_RANK:
                events.append(item)
    return events

# ── Main polling loop ─────────────────────────────────────────────────────────

def main():
    print(f"Splunk integration: polling every {POLL_SEC}s, urgency >= {URGENCY_MIN}")
    print(f"Splunk: {SPLUNK_HOST}:{SPLUNK_PORT}  |  SOC backend: {SOC_URL}")

    # Track absolute epoch timestamp. Using relative modifiers ("-1m", "-5m")
    # would miss events if a poll cycle takes longer than the modifier window.
    last_poll_epoch = int(
        (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)).timestamp()
    )

    while True:
        poll_start_epoch = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        try:
            events = search_notable_events(last_poll_epoch)
            print(f"Found {len(events)} notable events (urgency >= {URGENCY_MIN})")

            for event in events:
                event_hash = event.get("event_hash") or str(hash(str(event)))
                soc_alert  = build_soc_alert(event)
                analysis   = call_soc_backend(soc_alert, event_hash)
                if analysis and HEC_TOKEN:
                    write_to_hec(event, analysis)
                time.sleep(2)  # pace requests

        except Exception as e:
            print(f"[ERROR] Poll cycle failed: {e}")

        # Advance window. Subtract 10 seconds overlap to avoid missing events at
        # the boundary caused by clock skew or Splunk indexing lag.
        last_poll_epoch = poll_start_epoch - 10
        time.sleep(POLL_SEC)

if __name__ == "__main__":
    main()
```

---

## Step 5 — Option B: Webhook adapter (Custom Alert Action)

This approach lets Splunk push alerts to your engine immediately when a correlation search fires, without polling.

Save as `splunk_webhook.py`:

```python
"""
Splunk Custom Alert Action webhook adapter.

Receives POST from Splunk, calls the SOC backend, and writes the result
back to Splunk via HEC.

Usage:
    pip install flask requests
    python splunk_webhook.py
    # Runs on port 5000

Configure in Splunk:
    Alert action → Webhook → URL: http://localhost:5000/webhook
"""

import os
import json
import datetime
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

SOC_URL   = os.environ.get("SOC_BACKEND_URL",  "http://localhost:3000")
SOC_KEY   = os.environ.get("SOC_API_KEY",       "")
HEC_URL   = os.environ.get("SPLUNK_HEC_URL",   "http://localhost:8088/services/collector")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN",  "")

@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_json(force=True, silent=True) or {}
    result  = payload.get("result", {})

    rule_name = result.get("source", "Unknown Splunk alert")
    src_ip    = result.get("src")  or result.get("src_ip")
    dest_ip   = result.get("dest") or result.get("dest_ip")
    urgency   = result.get("urgency", "medium")

    soc_alert = {
        "description": (
            f"Splunk alert: {rule_name}. "
            f"Source IP: {src_ip}. Urgency: {urgency}."
        ),
        "source_ip":      src_ip,
        "destination_ip": dest_ip,
        "severity":       urgency,
    }

    headers = {"Content-Type": "application/json"}
    if SOC_KEY:
        headers["X-API-Key"] = SOC_KEY

    try:
        resp = requests.post(f"{SOC_URL}/api/analyze", json=soc_alert,
                             headers=headers, timeout=120)
        resp.raise_for_status()
        analysis = resp.json()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if HEC_TOKEN:
        hec_payload = {
            "time":  datetime.datetime.now(datetime.timezone.utc).timestamp(),
            "index": "soc_enrichments",
            "event": {**analysis, "splunk_rule_name": rule_name, "splunk_src": src_ip},
        }
        requests.post(HEC_URL,
                      headers={"Authorization": f"Splunk {HEC_TOKEN}"},
                      json=hec_payload, timeout=10)

    return jsonify({"status": "ok", "classification": analysis.get("attack_classification")}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

In Splunk: Alerts → Edit → Add actions → Webhook → URL: `http://localhost:5000/webhook`.

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
| sort -ts
```

**Correlate enrichment with the original notable event by `event_hash`:**

```spl
index=notable OR index=soc_enrichments
| eval join_key=coalesce(event_hash, splunk_event_hash)
| stats values(*) as * by join_key
| where isnotnull(attack_classification)
```

---

## Common issues

**`HTTPError: 401` from Splunk REST API:**
- Check `SPLUNK_USER` and `SPLUNK_PASS`
- The user needs the `search` role and read access to the `notable` index

**HEC writes fail with `400 Invalid token`:**
- The HEC token is wrong or HEC is not enabled
- Verify: Splunk Web → Settings → Data inputs → HTTP Event Collector
- Test manually: `curl -k http://localhost:8088/services/collector -H "Authorization: Splunk YOUR_TOKEN" -d '{"event": "test"}'`

**No notable events returned:**
- Splunk ES must have correlation searches enabled and generating alerts
- Confirm events exist: run `index=notable | head 5` directly in Splunk Search
- Try widening the search window: temporarily change `last_poll_epoch` to 24 hours ago

**`fallback_used: true` on all results:**
- LLM engine unreachable: `curl http://localhost:8000/health`
- SOC backend not configured: `curl http://localhost:3000/api/provider-health`
- Ollama inference timeout: increase `LOCAL_LLM_ENGINE_TIMEOUT_MS=120000` in `soc-backend/.env.local`
