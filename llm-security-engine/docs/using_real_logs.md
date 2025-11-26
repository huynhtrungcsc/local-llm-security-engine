# Using This Service with Real Logs

This guide explains how this service fits into a real security monitoring workflow, what log sources it can work with, what preprocessing is required, and what it cannot do.

---

## What role this service plays

This service is an **inference layer**. It sits between your log sources (Suricata, Zeek, Wazuh, SIEM, etc.) and whatever decision-making system you are building.

```
Log sources (Suricata, Zeek, Wazuh, SIEM)
         │
         ▼
Your SOC backend  ←── normalizes, deduplicates, enriches
         │
         ▼
Local LLM Security Engine  ←── adds LLM-based threat classification
         │
         ▼
Your alert routing / ticketing / analyst workflow
```

The engine does not replace any of these steps. It adds one thing: a structured threat classification and risk estimate, produced by a local language model, for normalized events that your backend sends to it.

---

## What this service is not

Be clear about these limitations before integrating with real log data:

- **Not a SIEM**: It has no alert correlation, no detection rules, no event deduplication, no case management, and no dashboards.
- **Not a real-time detection pipeline**: It is synchronous — each request blocks until Ollama finishes (up to 60 seconds). It cannot process thousands of events per minute.
- **Not a replacement for detection engineers**: The model does not know your environment, your baselines, or what is normal for your organization.
- **Not a compliance tool**: No audit trail, no data retention, no chain of custody.
- **Not production-hardened**: See [production_gap.md](production_gap.md) for what is missing.

---

## What kinds of log data work well

### Good inputs

The model performs best on events that have:
- A clear human-readable description of what happened
- Specific indicators (IPs, counts, process names, file paths, protocol details)
- Enough context to distinguish threat from benign (e.g. "from an external IP never seen before")

**Well-suited event types:**
- Failed/successful authentication events with counts and source IPs
- Network connections to unusual destinations, especially with beaconing patterns
- Process execution events involving known-suspicious tools (mimikatz, psexec, certutil)
- Lateral movement indicators (admin share access, pass-the-hash patterns)
- Data exfiltration indicators (large outbound transfers to external hosts)
- DNS requests to newly-registered or suspicious domains

---

### What does not work well

- **Raw log lines**: A Suricata JSON alert or a Zeek conn.log row should not be sent directly. The model is not a log parser.
- **Volume metrics without context**: "100 connection attempts" is weak. "100 connection attempts to 100 different internal hosts from one external IP in 30 seconds" is much better.
- **Repeated routine events**: If your SIEM generates 10,000 "successful VPN login" events per day, the model will classify each one individually and expensively. Pre-filter these at the SIEM layer.
- **Raw binary or encoded data**: Base64 strings, hex dumps, binary payloads — the model cannot reason about encoded data without decoding context.
- **Events with no description**: The `description` field is the primary input. If you send only metadata (IP, port, timestamp) with no human-readable description, results will be unreliable.

---

## Preprocessing requirements

Your SOC backend is responsible for preprocessing before calling this engine. This service expects **normalized, human-readable event summaries** — not raw log data.

### What preprocessing looks like

For a Suricata alert:

**Raw Suricata JSON** (do not send this directly):
```json
{
  "timestamp": "2024-01-15T10:00:00.123456+0000",
  "flow_id": 123456789,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "185.220.101.1",
  "src_port": 54321,
  "dest_ip": "10.0.0.100",
  "dest_port": 22,
  "proto": "TCP",
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 2001219,
    "rev": 7,
    "signature": "ET SCAN Potential SSH Scan",
    "category": "Attempted Information Leak",
    "severity": 2
  }
}
```

**Normalized description for this engine**:
```
"Suricata blocked potential SSH scan from 185.220.101.1:54321 to 10.0.0.100:22. Rule: ET SCAN Potential SSH Scan (SID 2001219, severity 2). Action: blocked."
```

The normalization step is yours to build. This engine only sees the description and optional structured fields.

---

### Preprocessing checklist

Before sending an event to this engine, your SOC backend should:

1. **Convert the log format to a human-readable summary**: Join the key fields into a sentence that describes what happened.

2. **Add counts and context**: "57 failed logins" is more useful than "failed login" repeated 57 times.

3. **Deduplicate and aggregate**: If the same event type fires 100 times from the same source in 5 minutes, send one summary ("100 failed SSH logins from 1.2.3.4 in 5 minutes") rather than 100 individual events.

4. **Enrich with threat intel**: If you have a blocklist, check the source IP. If it is on the list, include that in `additional_context`: `"Source IP is on Spamhaus DROP list."` This significantly improves classification quality.

5. **Remove PII that is not necessary**: Keep the IP addresses, event types, and counts. Remove user full names, email addresses, or other PII if it is not needed for the classification.

6. **Truncate to 4,000 characters**: The `description` field is capped. Summarize, do not dump.

---

## Working with specific log sources

### Suricata

Suricata produces alert events with rule signatures, source/destination IPs, and protocol details. Good fit for:
- Alert-level events (not connection-level noise)
- Blocked actions (these are higher-priority)
- High-severity signatures

**Preprocessing approach**:
1. Filter for `event_type == "alert"` and Suricata severity 1–2 (Suricata uses 1 = most severe, 4 = least severe, so 1–2 means high-priority only)
2. Format: `"Suricata {action} {signature} from {src_ip} to {dest_ip}:{dest_port}. Category: {category}."` (replace `{placeholders}` with actual field values)
3. If the source IP has a threat intel hit, add it to `additional_context`

---

### Zeek

Zeek produces rich connection logs, DNS logs, HTTP logs, and more. The volume is very high — do not send all connections.

**Preprocessing approach**:
- Focus on `weird.log` (protocol anomalies) and `notice.log` (analyst-relevant events)
- For `conn.log`: only process connections with unusually high byte counts, unusual duration patterns, or connections to rare external hosts
- For `dns.log`: focus on queries to newly-registered domains or known DGA patterns

---

### Wazuh

Wazuh generates alerts from its OSSEC-based rule engine. Alerts have a severity level and a description already.

**Preprocessing approach**:
- Filter for alerts at level 10+ (or whatever your threshold is)
- Use the Wazuh alert `description` field as your starting point
- Include the rule ID and agent name in `additional_context`

---

### Generic SIEM

If you are using Splunk, Elastic SIEM, Microsoft Sentinel, or similar:
- Use the SIEM's existing alert/notable event output rather than raw logs
- The SIEM has already applied detection rules and produced structured alerts
- Take the alert's title, description, source/destination, and severity and format them into this engine's input format
- Let the SIEM handle volume and rule-based detection; let this engine add LLM-based reasoning for high-priority alerts

---

## How many events should you send?

**This engine is not designed for high volume.** Each request takes 10–60 seconds of Ollama inference time on a CPU. On a mid-range CPU:

- 1 request → 10–60 seconds
- 10 requests in sequence → 2–10 minutes
- 100 requests → not practical without queuing

**Practical recommendation for development use:**
- Use this engine for your highest-priority alerts — the ones that would go to a Tier 1 analyst
- Pre-filter with SIEM rules to reduce the volume to the 5–50 most interesting events per hour
- Do not pipe raw log streams into this engine

For higher volume, you would need: async job queues (Celery/RQ), multiple Ollama instances, and possibly GPU acceleration. These are production-grade requirements — see [production_gap.md](production_gap.md).

---

## How to think about the output

The engine's output is an LLM-generated classification, not a rule-based detection. This has implications:

**It can reason about context that rules cannot**: A rule says "more than 50 failed logins = suspicious." The model can say "50 failed logins + 1 success from a flagged IP + after-hours timestamp = likely credential_access leading to initial_access."

**It is not deterministic**: The same event with the same description can produce slightly different results across runs, especially for ambiguous events. Do not treat the output as ground truth.

**It is only as good as your description**: The model has no access to your environment, your baselines, or your asset inventory. It only sees what you send it. A vague description produces a vague classification.

**Treat it as one signal, not the final word**: Use it alongside SIEM scores, threat intel, and analyst judgment — not instead of them. It is especially useful for explaining *why* an event might be suspicious, which is what the `reason` field captures.

---

## Honest summary

This service can add value to a SOC workflow, but it requires:
- A working SIEM or log aggregation layer to handle volume and initial filtering
- A SOC backend to normalize events before sending them
- A human analyst (or automated routing system) to review and act on the output
- Understanding that `fallback_used: true` results need manual review

It is genuinely useful for: enriching high-priority alerts with an LLM-generated threat classification and explanation, especially when you want to understand *why* an event is suspicious before escalating it.

It is not useful for: replacing any existing part of your detection pipeline, processing raw log streams, or running without human oversight.
