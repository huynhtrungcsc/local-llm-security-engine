# Wazuh Integration Guide

This guide explains how to connect Wazuh to the Local LLM Security Engine. The integration works in both directions: Wazuh alerts flow into the engine for AI-powered classification, and the results flow back into Elasticsearch where Wazuh stores its data.

---

## Architecture

```
Wazuh Agents (endpoints)
        │ raw events
        ▼
Wazuh Manager  ─── applies detection rules ───►  Elasticsearch
                                                  wazuh-alerts-4.x-* index
                                                        │
                                          ┌─────────────┘ poll new alerts
                                          ▼
                                  Integration script (Python)
                                          │ POST /api/analyze
                                          ▼
                                  SOC Backend (soc-backend/)
                                          │ POST /analyze-event
                                          ▼
                                  LLM Security Engine (llm-security-engine/)
                                          │ Ollama inference (local)
                                          ▼
                                  AnalysisResult
                                          │ write back
                                          ▼
                                  Elasticsearch
                                  soc-enrichments-* index
                                          │
                                          ▼
                                  Wazuh Dashboard (Kibana)
                                  custom dashboard or discover view
```

The integration script runs on the same machine (or network) as both Wazuh's Elasticsearch and the SOC backend. It polls for new Wazuh alerts, normalizes them, calls the engine, and writes the enriched result back to Elasticsearch.

---

## Prerequisites

- Wazuh 4.x with Elasticsearch or OpenSearch backend
- SOC backend running: `pnpm run dev` (port 3000)
- LLM Security Engine running: `uvicorn app.main:app --port 8000`
- Python 3.10+ with packages:
  ```bash
  pip install "elasticsearch>=8.0" requests
  ```
- Network access from the integration script to:
  - Elasticsearch (default port 9200)
  - SOC backend (default port 3000)

---

## Step 1 — Understand the Wazuh alert format

Wazuh stores alerts as JSON documents in Elasticsearch. A typical alert `_source` looks like:

```json
{
  "@timestamp": "2024-01-15T14:23:01.000Z",
  "agent": {
    "id": "001",
    "name": "ubuntu-endpoint",
    "ip": "10.0.1.50"
  },
  "rule": {
    "id": "5710",
    "level": 10,
    "description": "sshd: attempt to login using a non-existent user",
    "groups": ["syslog", "sshd", "authentication_failures"]
  },
  "data": {
    "srcip": "185.234.219.44",
    "srcport": "52341"
  },
  "full_log": "sshd[1234]: Invalid user admin from 185.234.219.44 port 52341"
}
```

To verify your Wazuh index name (it may differ by installation):

```bash
curl http://localhost:9200/_cat/indices | grep wazuh
# Example output: wazuh-alerts-4.x-2024.01.15
```

---

## Step 2 — Map Wazuh fields to the SOC backend input

The SOC backend accepts this JSON schema (see `openapi/openapi.yaml`):

| SOC backend field    | Required | Wazuh source                                      |
|----------------------|----------|---------------------------------------------------|
| `description`        | Yes      | Build from `rule.description` + key details       |
| `source_ip`          | No       | `data.srcip` or `agent.ip`                        |
| `destination_ip`     | No       | `data.dstip` (if present)                         |
| `event_type`         | No       | `rule.groups` joined with comma                   |
| `severity`           | No       | Mapped from `rule.level` (see table below)        |
| `timestamp`          | No       | `@timestamp` (ISO 8601)                           |
| `additional_context` | No       | `agent.name`, `rule.id`, `full_log`               |

**Severity mapping (Wazuh rule level → SOC severity):**

| Wazuh rule level | SOC severity |
|------------------|--------------|
| 0–3              | `low`        |
| 4–7              | `medium`     |
| 8–11             | `high`       |
| 12–15            | `critical`   |

**Building a good `description`:**

The `description` field is the primary input to the LLM. Include specifics:

```python
# Weak — Wazuh rule description alone:
"sshd: attempt to login using a non-existent user"

# Better — add agent name, source IP, log line:
"SSH login attempt for non-existent user on host ubuntu-endpoint from external IP 185.234.219.44. "
"Rule: sshd authentication failure (level 10). Log: Invalid user admin from 185.234.219.44 port 52341"
```

---

## Step 3 — Integration script

Save as `wazuh_integration.py` and run it periodically (cron, systemd timer, or loop):

```python
"""
Wazuh → SOC Backend integration script.

Polls Elasticsearch for new Wazuh alerts, sends each to the SOC backend
for LLM analysis, and writes the enriched result back to Elasticsearch.

Usage:
    pip install "elasticsearch>=8.0" requests
    python wazuh_integration.py

Environment variables:
    ELASTICSEARCH_URL     Elasticsearch base URL (default: http://localhost:9200)
    ELASTICSEARCH_USER    Username (optional, for secured Elasticsearch)
    ELASTICSEARCH_PASS    Password (optional)
    SOC_BACKEND_URL       SOC backend URL (default: http://localhost:3000)
    SOC_API_KEY           SOC backend API key (optional, matches SOC_API_KEY in .env.local)
    MIN_RULE_LEVEL        Minimum Wazuh rule level to analyze (default: 7)
    POLL_INTERVAL_SEC     Seconds between polls (default: 60)
    WAZUH_INDEX           Elasticsearch index pattern (default: wazuh-alerts-4.x-*)
"""

import os
import time
import json
import datetime
import requests
from elasticsearch import Elasticsearch

# ── Configuration ─────────────────────────────────────────────────────────────

ES_URL       = os.environ.get("ELASTICSEARCH_URL",  "http://localhost:9200")
ES_USER      = os.environ.get("ELASTICSEARCH_USER", "")
ES_PASS      = os.environ.get("ELASTICSEARCH_PASS", "")
SOC_URL      = os.environ.get("SOC_BACKEND_URL",    "http://localhost:3000")
SOC_API_KEY  = os.environ.get("SOC_API_KEY",        "")
MIN_LEVEL    = int(os.environ.get("MIN_RULE_LEVEL",    "7"))
POLL_SEC     = int(os.environ.get("POLL_INTERVAL_SEC", "60"))
WAZUH_INDEX  = os.environ.get("WAZUH_INDEX", "wazuh-alerts-4.x-*")
RESULT_INDEX = "soc-enrichments"

# ── Elasticsearch client ─────────────────────────────────────────────────────
# elasticsearch-py 8.x: use basic_auth= instead of http_auth=

if ES_USER and ES_PASS:
    es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS))
else:
    es = Elasticsearch(ES_URL)

# ── Helper functions ──────────────────────────────────────────────────────────

def safe_get(doc: dict, *keys, default=None):
    """Safely navigate a nested dict. Example: safe_get(alert, 'rule', 'level')"""
    val = doc
    for k in keys:
        if not isinstance(val, dict):
            return default
        val = val.get(k)
        if val is None:
            return default
    return val if val is not None else default

def wazuh_level_to_severity(level: int) -> str:
    if level >= 12: return "critical"
    if level >= 8:  return "high"
    if level >= 4:  return "medium"
    return "low"

def build_description(alert: dict) -> str:
    rule       = alert.get("rule", {})
    agent      = alert.get("agent", {})
    data       = alert.get("data", {})
    base       = rule.get("description", "Unknown Wazuh alert")
    agent_name = agent.get("name", "unknown-host")
    src_ip     = data.get("srcip") or agent.get("ip", "")
    full_log   = alert.get("full_log", "")

    parts = [f"{base} on host {agent_name}"]
    if src_ip:   parts.append(f"from source IP {src_ip}")
    if full_log: parts.append(f"Log: {full_log[:300]}")
    return ". ".join(parts)

def build_soc_alert(alert: dict) -> dict:
    rule   = alert.get("rule", {})
    agent  = alert.get("agent", {})
    data   = alert.get("data", {})
    groups = rule.get("groups", [])

    ctx_parts = [
        f"Agent: {agent.get('name', 'unknown')} (ID: {agent.get('id', '?')})",
        f"Rule ID: {rule.get('id', '?')}, Level: {rule.get('level', '?')}",
    ]
    if groups:
        ctx_parts.append(f"Groups: {', '.join(groups)}")

    return {
        "description":        build_description(alert),
        "source_ip":          data.get("srcip") or agent.get("ip") or None,
        "destination_ip":     data.get("dstip") or None,
        "event_type":         ", ".join(groups) if groups else None,
        "severity":           wazuh_level_to_severity(rule.get("level", 0)),
        "timestamp":          alert.get("@timestamp"),
        "additional_context": ". ".join(ctx_parts),
    }

def call_soc_backend(alert_body: dict, alert_id: str) -> dict | None:
    headers = {
        "Content-Type": "application/json",
        "X-Request-ID": alert_id,
    }
    if SOC_API_KEY:
        headers["X-API-Key"] = SOC_API_KEY

    try:
        resp = requests.post(
            f"{SOC_URL}/api/analyze",
            json=alert_body,
            headers=headers,
            timeout=120,  # Ollama inference can take up to 90s on CPU
        )
        if resp.status_code == 429:
            retry = resp.json().get("retry_after_seconds", 60)
            print(f"[WARN] Rate limited — waiting {retry}s")
            time.sleep(retry)
            return None
        if resp.status_code == 422:
            print(f"[WARN] Validation error for alert {alert_id}: {resp.text[:200]}")
            return None
        if resp.status_code == 503:
            print("[ERROR] SOC backend has no LLM provider configured. "
                  "Check LOCAL_LLM_ENGINE_BASE_URL in soc-backend/.env.local")
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.Timeout:
        print(f"[WARN] Request timed out for alert {alert_id}")
        return None
    except requests.RequestException as e:
        print(f"[ERROR] Failed to reach SOC backend: {e}")
        return None

def write_enrichment(alert_id: str, wazuh_alert: dict, analysis: dict) -> None:
    rule = wazuh_alert.get("rule", {})
    doc = {
        "@timestamp":                datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "wazuh_alert_id":            alert_id,
        "wazuh_rule_id":             rule.get("id"),
        "wazuh_rule_description":    rule.get("description"),
        "wazuh_rule_level":          rule.get("level"),
        "wazuh_agent_name":          wazuh_alert.get("agent", {}).get("name"),
        "attack_classification":     analysis["attack_classification"],
        "risk_score":                analysis["risk_score"],
        "false_positive_likelihood": analysis["false_positive_likelihood"],
        "reason":                    analysis["reason"],
        "fallback_used":             analysis["fallback_used"],
        "model_used":                analysis.get("model_used"),
        "latency_ms":                analysis.get("latency_ms"),
    }
    es.index(index=RESULT_INDEX, document=doc)
    print(f"[OK] {alert_id} → {analysis['attack_classification']} "
          f"(risk={analysis['risk_score']}, fallback={analysis['fallback_used']})")

def get_alerts_since(since_iso: str) -> list[dict]:
    """Query Elasticsearch for Wazuh alerts above minimum level since `since_iso`."""
    resp = es.search(
        index=WAZUH_INDEX,
        query={
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": since_iso}}},
                    {"range": {"rule.level": {"gte": MIN_LEVEL}}},
                ]
            }
        },
        sort=[{"@timestamp": "asc"}],
        size=50,
    )
    return resp["hits"]["hits"]

# ── Main polling loop ─────────────────────────────────────────────────────────

def main():
    print(f"Starting Wazuh integration: polling every {POLL_SEC}s, min rule level {MIN_LEVEL}")
    print(f"Elasticsearch: {ES_URL}  |  SOC backend: {SOC_URL}")
    print(f"Index: {WAZUH_INDEX}")

    # Track the actual wall-clock time of the last successful poll start.
    # This avoids the bug of using a relative modifier like "-1m" which can
    # miss events if a poll cycle takes longer than 1 minute.
    last_poll_start = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    )

    while True:
        poll_start = datetime.datetime.now(datetime.timezone.utc)
        since_iso  = last_poll_start.isoformat()

        try:
            hits = get_alerts_since(since_iso)
            print(f"[{poll_start.strftime('%H:%M:%S')}] Found {len(hits)} alerts (level >= {MIN_LEVEL})")

            for hit in hits:
                alert_id  = hit["_id"]
                alert     = hit["_source"]
                soc_alert = build_soc_alert(alert)
                analysis  = call_soc_backend(soc_alert, alert_id)
                if analysis:
                    write_enrichment(alert_id, alert, analysis)
                # Pace requests — 1 analysis per 2 seconds minimum
                time.sleep(2)

        except Exception as e:
            print(f"[ERROR] Poll cycle failed: {e}")

        # Advance the window: next poll queries from when this poll started,
        # minus a 10-second overlap to avoid missing alerts at the boundary.
        last_poll_start = poll_start - datetime.timedelta(seconds=10)
        time.sleep(POLL_SEC)

if __name__ == "__main__":
    main()
```

---

## Step 4 — Understanding the response

The SOC backend returns:

```json
{
  "attack_classification": "credential_access",
  "risk_score": 78,
  "false_positive_likelihood": 0.15,
  "reason": "Repeated SSH login failures for non-existent users from an external IP suggest automated credential stuffing or brute-force attack.",
  "fallback_used": false,
  "model_used": "phi4-mini",
  "engine_reachable": true,
  "latency_ms": 22400
}
```

**Key fields:**

| Field | What to do with it |
|---|---|
| `fallback_used: true` | Engine was unreachable or model output was invalid. Do not auto-escalate — flag for manual review. |
| `attack_classification` | One of: `reconnaissance`, `credential_access`, `initial_access`, `lateral_movement`, `command_and_control`, `benign`, `unknown` |
| `risk_score` | 0–100. Use alongside Wazuh rule level as a secondary triage signal. |
| `false_positive_likelihood` | 0–1. High value (> 0.6) = strong signal this is benign noise. |
| `reason` | Plain-language explanation — most useful for analyst notes and ticket descriptions. |

---

## Step 5 — View results in Kibana

After the script writes to the `soc-enrichments` index, create a Kibana index pattern:

1. **Kibana → Stack Management → Index Patterns → Create index pattern**
2. Pattern: `soc-enrichments*`
3. Time field: `@timestamp`

Then use **Discover** to search by `attack_classification`, `risk_score`, or `wazuh_agent_name`. Create a dashboard with a data table grouped by `attack_classification` and `wazuh_agent_name`.

---

## Pre-filtering recommendations

**Do not send every Wazuh alert to the engine.** Ollama inference takes 15–60 seconds per request on CPU. Pre-filter to only high-value alerts:

| Wazuh rule level | Recommendation |
|---|---|
| 1–6 (low) | Skip — informational only |
| 7–11 (medium/high) | Selective — send only if from external IPs or unknown agents |
| 12–15 (critical) | Always send |

Set `MIN_RULE_LEVEL=7` to start. Adjust after seeing what volume your environment produces.

---

## Common issues

**`Connection refused` to SOC backend:**
- SOC backend is not running: `cd soc-backend && pnpm run dev`
- Wrong port: check `PORT` in `soc-backend/.env.local`

**`503 no_provider_configured`:**
- `LOCAL_LLM_ENGINE_BASE_URL` is not set in `soc-backend/.env.local`
- Should be `http://localhost:8000` for local development

**`fallback_used: true` on every result:**
- LLM engine is not running: `cd llm-security-engine && uvicorn app.main:app --port 8000`
- Ollama is not running or model not pulled: `ollama pull phi4-mini`
- Timeout too short: increase `LOCAL_LLM_ENGINE_TIMEOUT_MS=120000` in `soc-backend/.env.local`

**`elasticsearch.exceptions.NotFoundError` (index not found):**
- Check your actual index name: `curl http://localhost:9200/_cat/indices | grep wazuh`
- Set `WAZUH_INDEX=your-actual-index-name-*` in the environment

**`elasticsearch.AuthenticationException`:**
- Set `ELASTICSEARCH_USER` and `ELASTICSEARCH_PASS`
- Or configure Elasticsearch without authentication for local development
