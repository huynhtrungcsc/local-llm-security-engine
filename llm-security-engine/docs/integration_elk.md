# ELK Stack / Elastic SIEM Integration Guide

This guide explains how to connect an Elastic SIEM deployment to the Local LLM Security Engine. Detection rule alerts from Elastic SIEM flow into the engine for AI-powered classification, and results are written back to Elasticsearch as an enrichment index.

---

## Architecture

```
Beats / Logstash / Elastic Agent
        │ raw events
        ▼
Elasticsearch (logs)
        │
  Elastic SIEM detection rules fire
        │
        ▼
.alerts-security.alerts-default  ← Elastic SIEM alert documents
        │
┌───────┘  poll new alerts
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
Elasticsearch: soc-enrichments-* index
        │
        ▼
Kibana dashboard / SIEM case enrichment
```

---

## Prerequisites

- Elastic Stack 8.x (Elasticsearch + Kibana + Elastic Security/SIEM)
- SOC backend running: `pnpm run dev` (port 3000)
- LLM Security Engine running: `uvicorn app.main:app --port 8000`
- Python 3.10+ with packages:
  ```bash
  pip install "elasticsearch>=8.0" requests
  ```
- Elasticsearch API key or username/password for the integration script

---

## Step 1 — Understand the Elastic SIEM alert format

Elastic SIEM stores detection rule alerts in a hidden index: `.alerts-security.alerts-default`.

**Important**: When you query this index via the Elasticsearch API, the `_source` uses **nested objects** — not flat dot-notation keys. The path `kibana.alert.rule.name` is stored as `{"kibana": {"alert": {"rule": {"name": "..."}}}}`:

```json
{
  "@timestamp": "2024-01-15T14:23:01.000Z",
  "kibana": {
    "alert": {
      "rule": {
        "name": "Suspicious PowerShell Execution",
        "category": "Custom Query Rule",
        "description": "Detects encoded PowerShell with outbound connections"
      },
      "severity": "high",
      "risk_score": 73,
      "status": "open",
      "uuid": "abc123-def456"
    }
  },
  "source": { "ip": "192.168.1.100" },
  "destination": { "ip": "203.0.113.5", "port": 443 },
  "process": {
    "name": "powershell.exe",
    "command_line": "powershell.exe -enc JABjAG0AZAA..."
  },
  "host": { "hostname": "WORKSTATION-01" },
  "user": { "name": "jdoe" }
}
```

Verify that your Elastic Security has alerts:

```bash
# Check that the index exists and has documents
curl -u elastic:yourpassword \
  "http://localhost:9200/.alerts-security.alerts-default/_count"
# { "count": 42, ... }
```

---

## Step 2 — Map Elastic SIEM fields to the SOC backend input

| SOC backend field    | Required | Elastic SIEM source                                         |
|----------------------|----------|-------------------------------------------------------------|
| `description`        | Yes      | Build from rule name + key event details                    |
| `source_ip`          | No       | `source → ip`                                               |
| `destination_ip`     | No       | `destination → ip`                                          |
| `event_type`         | No       | `kibana → alert → rule → category`                          |
| `severity`           | No       | `kibana → alert → severity`                                 |
| `timestamp`          | No       | `@timestamp`                                                |
| `additional_context` | No       | `host → hostname`, `user → name`, `process → command_line` |

**Building a good `description`:**

```python
# Weak — rule name alone:
"Suspicious PowerShell Execution"

# Better — include host, user, and what was observed:
"Suspicious PowerShell execution on WORKSTATION-01 by user jdoe. "
"Encoded command line detected. Connection to external IP 203.0.113.5:443. "
"Elastic SIEM rule: Suspicious PowerShell Execution (severity: high, risk_score: 73)"
```

---

## Step 3 — Create an Elasticsearch API key

In Kibana → Stack Management → Security → API Keys → Create API key.

Minimum required privileges:

```json
{
  "cluster": ["monitor"],
  "indices": [
    {
      "names": [".alerts-security.alerts-*", "soc-enrichments-*"],
      "privileges": ["read", "create_index", "index", "view_index_metadata"]
    }
  ]
}
```

Kibana will show the API key as a **base64 string** — use that directly as `ELASTICSEARCH_API_KEY`.

---

## Step 4 — Integration script

Save as `elk_integration.py`:

```python
"""
Elastic SIEM → SOC Backend integration script.

Polls .alerts-security.alerts-default for open Elastic SIEM alerts,
sends each to the SOC backend for LLM analysis, and writes enriched
results back to Elasticsearch.

Usage:
    pip install "elasticsearch>=8.0" requests
    python elk_integration.py

Environment variables:
    ELASTICSEARCH_URL      Elasticsearch base URL (default: http://localhost:9200)
    ELASTICSEARCH_API_KEY  Base64 API key from Kibana (preferred)
    ELASTICSEARCH_USER     Username (alternative to API key)
    ELASTICSEARCH_PASS     Password
    SOC_BACKEND_URL        SOC backend URL (default: http://localhost:3000)
    SOC_API_KEY            SOC backend API key (optional)
    MIN_RISK_SCORE         Minimum Elastic SIEM risk_score to analyze (default: 40)
    POLL_INTERVAL_SEC      Seconds between polls (default: 60)
"""

import os
import time
import datetime
import requests
from elasticsearch import Elasticsearch

# ── Configuration ─────────────────────────────────────────────────────────────

ES_URL     = os.environ.get("ELASTICSEARCH_URL",      "http://localhost:9200")
ES_API_KEY = os.environ.get("ELASTICSEARCH_API_KEY",  "")
ES_USER    = os.environ.get("ELASTICSEARCH_USER",     "")
ES_PASS    = os.environ.get("ELASTICSEARCH_PASS",     "")
SOC_URL    = os.environ.get("SOC_BACKEND_URL",        "http://localhost:3000")
SOC_KEY    = os.environ.get("SOC_API_KEY",            "")
MIN_RISK   = int(os.environ.get("MIN_RISK_SCORE",     "40"))
POLL_SEC   = int(os.environ.get("POLL_INTERVAL_SEC",  "60"))
RESULT_INDEX = "soc-enrichments"
ALERT_INDEX  = ".alerts-security.alerts-default"

# ── Elasticsearch client ─────────────────────────────────────────────────────
# elasticsearch-py 8.x: use api_key= or basic_auth= (not the deprecated http_auth=)

if ES_API_KEY:
    es = Elasticsearch(ES_URL, api_key=ES_API_KEY)
elif ES_USER and ES_PASS:
    es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS))
else:
    es = Elasticsearch(ES_URL)

# ── Field access helper ───────────────────────────────────────────────────────

def get(doc: dict, path: str, default=None):
    """
    Navigate a nested dict using a dot-notation path string.

    Elastic SIEM alert _source uses nested objects — access them with dots:
      get(alert, "kibana.alert.rule.name")   → alert["kibana"]["alert"]["rule"]["name"]
      get(alert, "source.ip")                → alert["source"]["ip"]
      get(alert, "host.hostname")            → alert["host"]["hostname"]

    Returns `default` if any key along the path is missing or not a dict.
    """
    val = doc
    for key in path.split("."):
        if not isinstance(val, dict):
            return default
        val = val.get(key)
        if val is None:
            return default
    return val if val is not None else default

# ── Alert normalization ───────────────────────────────────────────────────────

def build_description(alert: dict) -> str:
    rule_name = get(alert, "kibana.alert.rule.name",  default="Unknown detection rule")
    severity  = get(alert, "kibana.alert.severity",   default="")
    risk      = get(alert, "kibana.alert.risk_score", default="")
    hostname  = get(alert, "host.hostname",           default="")
    username  = get(alert, "user.name",               default="")
    cmd_line  = get(alert, "process.command_line",    default="")
    src_ip    = get(alert, "source.ip",               default="")

    parts = [f"Elastic SIEM alert: {rule_name}"]
    if hostname: parts.append(f"on host {hostname}")
    if username: parts.append(f"by user {username}")
    if src_ip:   parts.append(f"from source IP {src_ip}")
    if cmd_line: parts.append(f"Process: {cmd_line[:200]}")
    if severity or risk:
        parts.append(f"Elastic severity: {severity}, risk_score: {risk}")

    return ". ".join(parts)

def build_soc_alert(alert: dict) -> dict:
    hostname  = get(alert, "host.hostname",                    default="")
    username  = get(alert, "user.name",                        default="")
    rule_cat  = get(alert, "kibana.alert.rule.category",       default="")
    dest_port = get(alert, "destination.port",                 default="")
    rule_desc = get(alert, "kibana.alert.rule.description",    default="")

    ctx_parts = []
    if hostname:  ctx_parts.append(f"Host: {hostname}")
    if username:  ctx_parts.append(f"User: {username}")
    if dest_port: ctx_parts.append(f"Destination port: {dest_port}")
    if rule_desc: ctx_parts.append(f"Rule description: {rule_desc[:200]}")

    return {
        "description":        build_description(alert),
        "source_ip":          get(alert, "source.ip"),
        "destination_ip":     get(alert, "destination.ip"),
        "event_type":         rule_cat or None,
        "severity":           get(alert, "kibana.alert.severity"),
        "timestamp":          alert.get("@timestamp"),
        "additional_context": ". ".join(ctx_parts) or None,
    }

def call_soc_backend(body: dict, alert_uuid: str) -> dict | None:
    headers = {"Content-Type": "application/json", "X-Request-ID": alert_uuid}
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
            print(f"[WARN] {resp.status_code} for alert {alert_uuid}: {resp.text[:200]}")
            return None
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[ERROR] SOC backend error for {alert_uuid}: {e}")
        return None

def write_enrichment(alert_uuid: str, alert: dict, analysis: dict) -> None:
    doc = {
        "@timestamp":                datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "elastic_alert_uuid":        alert_uuid,
        "elastic_rule_name":         get(alert, "kibana.alert.rule.name"),
        "elastic_rule_category":     get(alert, "kibana.alert.rule.category"),
        "elastic_severity":          get(alert, "kibana.alert.severity"),
        "elastic_risk_score":        get(alert, "kibana.alert.risk_score"),
        "attack_classification":     analysis["attack_classification"],
        "risk_score":                analysis["risk_score"],
        "false_positive_likelihood": analysis["false_positive_likelihood"],
        "reason":                    analysis["reason"],
        "fallback_used":             analysis["fallback_used"],
        "model_used":                analysis.get("model_used"),
        "latency_ms":                analysis.get("latency_ms"),
    }
    es.index(index=RESULT_INDEX, document=doc)
    print(f"[OK] {alert_uuid[:16]}… → {analysis['attack_classification']} "
          f"(risk={analysis['risk_score']}, fallback={analysis['fallback_used']})")

def get_open_alerts(since_iso: str) -> list[dict]:
    """Query Elasticsearch for open Elastic SIEM alerts above min risk since `since_iso`."""
    resp = es.search(
        index=ALERT_INDEX,
        query={
            "bool": {
                "must": [
                    {"range": {"@timestamp":                {"gte": since_iso}}},
                    {"range": {"kibana.alert.risk_score":   {"gte": MIN_RISK}}},
                    {"term":  {"kibana.alert.status":       "open"}},
                ]
            }
        },
        sort=[{"@timestamp": "asc"}],
        size=50,
    )
    return resp["hits"]["hits"]

# ── Main polling loop ─────────────────────────────────────────────────────────

def main():
    print(f"Elastic SIEM integration: polling every {POLL_SEC}s, min risk {MIN_RISK}")
    print(f"Elasticsearch: {ES_URL}  |  SOC backend: {SOC_URL}")

    # Track actual wall-clock time to avoid missing events if a poll cycle
    # takes longer than POLL_SEC. Never use relative modifiers like "-1m" here.
    last_poll_start = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    )

    while True:
        poll_start = datetime.datetime.now(datetime.timezone.utc)
        try:
            hits = get_open_alerts(last_poll_start.isoformat())
            print(f"[{poll_start.strftime('%H:%M:%S')}] Found {len(hits)} open alerts (risk >= {MIN_RISK})")

            for hit in hits:
                alert_uuid = get(hit["_source"], "kibana.alert.uuid") or hit["_id"]
                alert      = hit["_source"]
                soc_alert  = build_soc_alert(alert)
                analysis   = call_soc_backend(soc_alert, str(alert_uuid))
                if analysis:
                    write_enrichment(str(alert_uuid), alert, analysis)
                time.sleep(2)  # pace requests — Ollama inference is not instant

        except Exception as e:
            print(f"[ERROR] Poll cycle failed: {e}")

        # Advance window with a 10-second overlap to avoid missing alerts at the boundary
        last_poll_start = poll_start - datetime.timedelta(seconds=10)
        time.sleep(POLL_SEC)

if __name__ == "__main__":
    main()
```

---

## Step 5 — Viewing results in Kibana

**Create an index pattern** for `soc-enrichments*` (time field: `@timestamp`).

In Kibana Discover, useful filters:

```
attack_classification : "lateral_movement"     → high-priority findings
false_positive_likelihood > 0.7                → tune your detection rules
fallback_used : true                            → engine was unreachable, review manually
```

**Correlate with the original Elastic SIEM alert:**

Both the enrichment document and the original alert carry `elastic_alert_uuid` / `kibana.alert.uuid`. In Kibana Lens, use a top-level Join on this field to view the enrichment alongside the original alert.

---

## Alternative approach — Logstash HTTP filter

If you prefer a pipeline-based approach rather than a polling script:

```ruby
# logstash.conf (filter section)
# Requires logstash-filter-http plugin: bin/logstash-plugin install logstash-filter-http
filter {
  if [type] == "elastic_siem_alert" {
    http {
      url  => "http://localhost:3000/api/analyze"
      verb => "POST"
      body => {
        "description" => "%{[kibana][alert][rule][name]}: %{[host][hostname]}"
        "source_ip"   => "%{[source][ip]}"
        "severity"    => "%{[kibana][alert][severity]}"
        "timestamp"   => "%{@timestamp}"
      }
      body_format => "json"
      target_body => "soc_analysis"
    }
  }
}
output {
  if [soc_analysis] {
    elasticsearch {
      hosts => ["http://localhost:9200"]
      index => "soc-enrichments-%{+YYYY.MM}"
    }
  }
}
```

This is simpler but gives you less control over rate limiting and timeout handling.

---

## Common issues

**`AuthorizationException` from Elasticsearch:**
- The API key or user lacks permissions on `.alerts-security.alerts-*`
- Add `read` and `view_index_metadata` privileges for that index pattern

**Empty results (no alerts returned):**
- Elastic Security must have detection rules enabled and firing
- Check Kibana → Security → Alerts — if empty, the index has no documents
- Lower `MIN_RISK_SCORE` to `1` to verify connectivity, then raise it

**`NotFoundError` for the alerts index:**
- The `.alerts-security.alerts-default` index only exists after the first alert fires
- Run a detection rule manually in Kibana to create the index
- Or check with: `curl http://localhost:9200/_cat/indices | grep alerts-security`

**`fallback_used: true` on all results:**
- LLM engine unreachable: `curl http://localhost:8000/health`
- SOC backend not configured: `curl http://localhost:3000/api/provider-health`
