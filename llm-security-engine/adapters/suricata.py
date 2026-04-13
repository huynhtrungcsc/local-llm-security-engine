"""
Suricata EVE JSON adapter for the Local LLM Security Engine.

Converts Suricata EVE JSON log records into ``SecurityEventRequest`` objects
suitable for the engine's ``/analyze-event`` endpoint.

Suricata EVE JSON reference:
    https://docs.suricata.io/en/latest/output/eve/eve-json-format.html

Supported event types
---------------------
- ``alert``   — IDS/IPS rule matches (highest priority)
- ``dns``     — DNS queries and responses
- ``http``    — HTTP request/response metadata
- ``tls``     — TLS handshake metadata
- ``flow``    — Connection flow records
- ``ssh``     — SSH handshake metadata
- ``smb``     — SMB session metadata

Unsupported event types (``stats``, ``fileinfo``, ``anomaly``, etc.) are
silently skipped — ``parse_line`` returns ``None`` for those.

Usage::

    from adapters.suricata import SuricataAdapter
    from sdk import EngineClient, SecurityEventRequest

    adapter = SuricataAdapter(min_severity="medium")

    with EngineClient(base_url="http://localhost:8000") as client:
        with open("/var/log/suricata/eve.json") as fh:
            for line in fh:
                request = adapter.parse_line(line)
                if request is None:
                    continue          # unsupported or below min_severity
                result = client.analyze_event(request)
                if result.is_threat:
                    print(f"[{result.attack_classification}] {result.reason}")
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from sdk.models import SecurityEventRequest

logger = logging.getLogger(__name__)

# Suricata severity levels (alert.severity field: 1=high, 2=medium, 3=low, 4=info)
_SEVERITY_MAP = {1: "critical", 2: "high", 3: "medium", 4: "low"}

# Minimum Suricata severity to process (1=critical only, 4=all)
_SEVERITY_THRESHOLD_MAP = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 4}

_SUPPORTED_EVENT_TYPES = frozenset({
    "alert", "dns", "http", "tls", "flow", "ssh", "smb",
})


class SuricataAdapter:
    """
    Converts Suricata EVE JSON log lines into SecurityEventRequest objects.

    Parameters
    ----------
    min_severity:
        Minimum Suricata severity level to process. For alert events, records
        below this threshold are skipped. Non-alert events are always included
        when their event_type is supported.
        Choices: ``"critical"``, ``"high"``, ``"medium"``, ``"low"``, ``"info"``.
    include_flow_context:
        When True, appends flow bytes/packets to additional_context for
        alert and flow events. Adds useful volume context for anomaly detection.
    """

    def __init__(
        self,
        min_severity: str = "low",
        include_flow_context: bool = True,
    ) -> None:
        if min_severity not in _SEVERITY_THRESHOLD_MAP:
            raise ValueError(
                f"Invalid min_severity '{min_severity}'. "
                f"Choose from: {sorted(_SEVERITY_THRESHOLD_MAP)}"
            )
        self._severity_threshold = _SEVERITY_THRESHOLD_MAP[min_severity]
        self._include_flow = include_flow_context

    def parse_line(self, line: str) -> Optional[SecurityEventRequest]:
        """
        Parse one line of Suricata EVE JSON output.

        Returns a SecurityEventRequest, or None if the line should be skipped
        (unsupported event type, below severity threshold, or parse error).
        """
        line = line.strip()
        if not line:
            return None
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("Skipping non-JSON line: %s", line[:80])
            return None

        event_type = record.get("event_type", "")
        if event_type not in _SUPPORTED_EVENT_TYPES:
            return None

        try:
            return self._build_request(record, event_type)
        except Exception:
            logger.warning("Failed to parse Suricata record: %s", line[:120], exc_info=True)
            return None

    def parse_file(self, path: str) -> list[SecurityEventRequest]:
        """
        Parse all supported records from a Suricata EVE JSON file.

        Skips unsupported event types and malformed lines without raising.
        Returns a list (may be empty if the file has no supported events).
        """
        results: list[SecurityEventRequest] = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                req = self.parse_line(line)
                if req is not None:
                    results.append(req)
        return results

    # ── Private builders ──────────────────────────────────────────────────────

    def _build_request(self, r: dict, event_type: str) -> Optional[SecurityEventRequest]:
        src_ip = r.get("src_ip")
        dst_ip = r.get("dest_ip")
        timestamp = r.get("timestamp")

        if event_type == "alert":
            return self._build_alert(r, src_ip, dst_ip, timestamp)
        elif event_type == "dns":
            return self._build_dns(r, src_ip, dst_ip, timestamp)
        elif event_type == "http":
            return self._build_http(r, src_ip, dst_ip, timestamp)
        elif event_type == "tls":
            return self._build_tls(r, src_ip, dst_ip, timestamp)
        elif event_type == "flow":
            return self._build_flow(r, src_ip, dst_ip, timestamp)
        elif event_type == "ssh":
            return self._build_ssh(r, src_ip, dst_ip, timestamp)
        elif event_type == "smb":
            return self._build_smb(r, src_ip, dst_ip, timestamp)
        return None

    def _build_alert(self, r, src_ip, dst_ip, ts) -> Optional[SecurityEventRequest]:
        alert = r.get("alert", {})
        sev_int = alert.get("severity", 3)
        if sev_int < self._severity_threshold:
            return None

        severity_label = _SEVERITY_MAP.get(sev_int, "medium")
        signature = alert.get("signature", "Unknown Suricata alert")
        category = alert.get("category", "")
        action = alert.get("action", "")

        parts = [f"Suricata alert: {signature}"]
        if category:
            parts.append(f"Category: {category}")
        if action:
            parts.append(f"Action: {action}")
        if r.get("proto"):
            parts.append(f"Protocol: {r['proto']}")
        dst_port = r.get("dest_port")
        if dst_port:
            parts.append(f"Destination port: {dst_port}")

        context_parts = []
        if self._include_flow and "flow" in r:
            flow = r["flow"]
            pkts = flow.get("pkts_toserver", 0) + flow.get("pkts_toclient", 0)
            byts = flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
            context_parts.append(f"Flow: {pkts} packets, {byts} bytes")

        return SecurityEventRequest(
            description=". ".join(parts) + ".",
            source_ip=src_ip,
            destination_ip=dst_ip,
            event_type="suricata_alert",
            severity=severity_label,
            timestamp=ts,
            additional_context="; ".join(context_parts) if context_parts else None,
        )

    def _build_dns(self, r, src_ip, dst_ip, ts) -> SecurityEventRequest:
        dns = r.get("dns", {})
        qtype = dns.get("type", "query")
        rrtype = dns.get("rrtype", "A")
        rrname = dns.get("rrname", "unknown")
        rcode = dns.get("rcode", "")

        if qtype == "query":
            description = f"DNS {rrtype} query for {rrname} from {src_ip or 'unknown'}."
        else:
            description = (
                f"DNS {rrtype} response for {rrname} "
                f"(rcode={rcode}) to {dst_ip or 'unknown'}."
            )
            answers = dns.get("answers", [])
            if answers:
                rdata_list = [a.get("rdata", "") for a in answers[:3] if a.get("rdata")]
                if rdata_list:
                    description += f" Resolved: {', '.join(rdata_list)}."

        return SecurityEventRequest(
            description=description,
            source_ip=src_ip,
            destination_ip=dst_ip,
            event_type="dns",
            timestamp=ts,
        )

    def _build_http(self, r, src_ip, dst_ip, ts) -> SecurityEventRequest:
        http = r.get("http", {})
        method = http.get("http_method", "GET")
        hostname = http.get("hostname", dst_ip or "unknown")
        url = http.get("url", "/")
        status = http.get("status", "")
        ua = http.get("http_user_agent", "")

        description = f"HTTP {method} {hostname}{url}"
        if status:
            description += f" → {status}"
        description += "."

        ctx_parts = []
        if ua:
            ctx_parts.append(f"User-Agent: {ua}")
        content_type = http.get("http_content_type", "")
        if content_type:
            ctx_parts.append(f"Content-Type: {content_type}")
        length = http.get("length", 0)
        if length:
            ctx_parts.append(f"Response length: {length} bytes")

        return SecurityEventRequest(
            description=description,
            source_ip=src_ip,
            destination_ip=dst_ip,
            event_type="http",
            timestamp=ts,
            additional_context="; ".join(ctx_parts) if ctx_parts else None,
        )

    def _build_tls(self, r, src_ip, dst_ip, ts) -> SecurityEventRequest:
        tls = r.get("tls", {})
        sni = tls.get("sni", "unknown")
        version = tls.get("version", "")
        issuer = tls.get("issuerdn", "")
        subject = tls.get("subject", "")

        description = f"TLS handshake to {sni} (version: {version or 'unknown'})."
        ctx_parts = []
        if issuer:
            ctx_parts.append(f"Issuer: {issuer}")
        if subject:
            ctx_parts.append(f"Subject: {subject}")
        fingerprint = tls.get("fingerprint", "")
        if fingerprint:
            ctx_parts.append(f"Fingerprint: {fingerprint}")

        return SecurityEventRequest(
            description=description,
            source_ip=src_ip,
            destination_ip=dst_ip,
            event_type="tls",
            timestamp=ts,
            additional_context="; ".join(ctx_parts) if ctx_parts else None,
        )

    def _build_flow(self, r, src_ip, dst_ip, ts) -> Optional[SecurityEventRequest]:
        flow = r.get("flow", {})
        proto = r.get("proto", "unknown")
        dst_port = r.get("dest_port", "")
        state = flow.get("state", "")
        reason = flow.get("reason", "")

        pkts = flow.get("pkts_toserver", 0) + flow.get("pkts_toclient", 0)
        byts = flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)

        description = (
            f"{proto} flow from {src_ip or 'unknown'} to {dst_ip or 'unknown'}"
            + (f":{dst_port}" if dst_port else "")
            + f". Packets: {pkts}, bytes: {byts}"
            + (f", state: {state}" if state else "")
            + "."
        )

        ctx_parts = []
        if reason:
            ctx_parts.append(f"Close reason: {reason}")
        duration = flow.get("age", "")
        if duration:
            ctx_parts.append(f"Duration: {duration}s")

        return SecurityEventRequest(
            description=description,
            source_ip=src_ip,
            destination_ip=dst_ip,
            event_type="flow",
            timestamp=ts,
            additional_context="; ".join(ctx_parts) if ctx_parts else None,
        )

    def _build_ssh(self, r, src_ip, dst_ip, ts) -> SecurityEventRequest:
        ssh = r.get("ssh", {})
        client_sw = ssh.get("client", {}).get("software_version", "unknown")
        server_sw = ssh.get("server", {}).get("software_version", "unknown")

        description = (
            f"SSH handshake: client={client_sw}, server={server_sw}. "
            f"Connection from {src_ip or 'unknown'} to {dst_ip or 'unknown'}."
        )
        return SecurityEventRequest(
            description=description,
            source_ip=src_ip,
            destination_ip=dst_ip,
            event_type="ssh",
            timestamp=ts,
        )

    def _build_smb(self, r, src_ip, dst_ip, ts) -> SecurityEventRequest:
        smb = r.get("smb", {})
        command = smb.get("command", "unknown")
        status = smb.get("status", "")
        filename = smb.get("filename", "")

        description = f"SMB command {command}"
        if filename:
            description += f" on file '{filename}'"
        if status:
            description += f" (status: {status})"
        description += f". From {src_ip or 'unknown'} to {dst_ip or 'unknown'}."

        return SecurityEventRequest(
            description=description,
            source_ip=src_ip,
            destination_ip=dst_ip,
            event_type="smb",
            timestamp=ts,
        )
