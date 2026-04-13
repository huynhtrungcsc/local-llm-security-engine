"""
Zeek (formerly Bro) log adapter for the Local LLM Security Engine.

Converts Zeek tab-separated log records into ``SecurityEventRequest`` objects
suitable for the engine's ``/analyze-event`` endpoint.

Zeek log reference:
    https://docs.zeek.org/en/master/log-formats.html

Supported log files
-------------------
- ``conn.log``    — Connection records (all protocols)
- ``dns.log``     — DNS queries and responses
- ``http.log``    — HTTP request/response metadata
- ``ssl.log``     — SSL/TLS handshake metadata
- ``notice.log``  — Zeek notice framework alerts (highest priority)
- ``weird.log``   — Unexpected protocol behavior

The adapter auto-detects the log type from the ``#path`` directive in the
file header. You can also specify it explicitly when calling ``parse_file``.

Usage::

    from adapters.zeek import ZeekAdapter
    from sdk import EngineClient

    adapter = ZeekAdapter()

    with EngineClient(base_url="http://localhost:8000") as client:
        events = adapter.parse_file("/opt/zeek/logs/current/notice.log")
        for req in events:
            result = client.analyze_event(req)
            print(result.risk_score, req.description[:60])
"""

from __future__ import annotations

import logging
from typing import Optional

from sdk.models import SecurityEventRequest

logger = logging.getLogger(__name__)

_SUPPORTED_PATHS = frozenset({
    "conn", "dns", "http", "ssl", "notice", "weird",
})

_UNSET = "-"     # Zeek's placeholder for missing/unset fields


def _field(value: str) -> Optional[str]:
    """Return None for Zeek's unset sentinel '-', otherwise the raw value."""
    return None if value == _UNSET else value


def _bytes_label(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f} MB"
    if n >= 1_000:
        return f"{n / 1_000:.1f} KB"
    return f"{n} B"


class ZeekAdapter:
    """
    Converts Zeek tab-separated log files into SecurityEventRequest objects.

    Parameters
    ----------
    min_notice_action:
        For notice.log records, only process entries whose ``actions`` field
        includes at least one of the given action strings.
        Default: ``None`` (process all notice records).
    skip_local_to_local:
        When True, skip conn/flow records where both source and destination
        IPs are in RFC-1918 private ranges (10/8, 172.16/12, 192.168/16).
        Default: ``False`` (process all records).
    """

    def __init__(
        self,
        min_notice_action: Optional[list[str]] = None,
        skip_local_to_local: bool = False,
    ) -> None:
        self._min_notice_action = set(min_notice_action or [])
        self._skip_l2l = skip_local_to_local

    # ── Public API ────────────────────────────────────────────────────────────

    def parse_line(
        self,
        line: str,
        fields: list[str],
        log_type: str,
    ) -> Optional[SecurityEventRequest]:
        """
        Parse a single Zeek data line (not a header line).

        Parameters
        ----------
        line:
            Raw tab-separated data line from a Zeek log file.
        fields:
            Ordered list of field names from the ``#fields`` header directive.
        log_type:
            Zeek path name (e.g. ``"conn"``, ``"dns"``). Determines the
            description builder used.
        """
        if line.startswith("#"):
            return None
        parts = line.rstrip("\n").split("\t")
        if len(parts) != len(fields):
            logger.debug("Field count mismatch (%d vs %d), skipping", len(parts), len(fields))
            return None

        record = dict(zip(fields, parts))
        try:
            return self._dispatch(record, log_type)
        except Exception:
            logger.warning("Failed to convert Zeek record: %s", line[:120], exc_info=True)
            return None

    def parse_file(
        self,
        path: str,
        log_type: Optional[str] = None,
    ) -> list[SecurityEventRequest]:
        """
        Parse a complete Zeek log file.

        Auto-detects the log type from the ``#path`` header unless ``log_type``
        is specified. Lines with parse errors are silently skipped.

        Returns a list of SecurityEventRequest objects (may be empty).
        """
        results: list[SecurityEventRequest] = []
        detected_type = log_type
        fields: list[str] = []

        with open(path, encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                elif line.startswith("#path") and not detected_type:
                    detected_type = line.split("\t")[1] if "\t" in line else None
                elif line.startswith("#"):
                    continue
                else:
                    if not fields or not detected_type:
                        logger.warning("Skipping data line — no fields or path header yet")
                        continue
                    if detected_type not in _SUPPORTED_PATHS:
                        break
                    req = self.parse_line(line, fields, detected_type)
                    if req is not None:
                        results.append(req)
        return results

    # ── Dispatcher ────────────────────────────────────────────────────────────

    def _dispatch(self, r: dict, log_type: str) -> Optional[SecurityEventRequest]:
        if log_type == "conn":
            return self._build_conn(r)
        elif log_type == "dns":
            return self._build_dns(r)
        elif log_type == "http":
            return self._build_http(r)
        elif log_type == "ssl":
            return self._build_ssl(r)
        elif log_type == "notice":
            return self._build_notice(r)
        elif log_type == "weird":
            return self._build_weird(r)
        return None

    # ── Builders ──────────────────────────────────────────────────────────────

    def _build_conn(self, r: dict) -> Optional[SecurityEventRequest]:
        src_ip = _field(r.get("id.orig_h", _UNSET))
        dst_ip = _field(r.get("id.resp_h", _UNSET))

        if self._skip_l2l and src_ip and dst_ip:
            if _is_private(src_ip) and _is_private(dst_ip):
                return None

        proto = _field(r.get("proto", _UNSET)) or "unknown"
        service = _field(r.get("service", _UNSET))
        dst_port = _field(r.get("id.resp_p", _UNSET))
        state = _field(r.get("conn_state", _UNSET))
        duration = _field(r.get("duration", _UNSET))

        orig_bytes = r.get("orig_bytes", _UNSET)
        resp_bytes = r.get("resp_bytes", _UNSET)
        total_bytes = 0
        try:
            if orig_bytes != _UNSET:
                total_bytes += int(orig_bytes)
            if resp_bytes != _UNSET:
                total_bytes += int(resp_bytes)
        except ValueError:
            pass

        description = (
            f"{proto.upper()} connection from {src_ip or 'unknown'} "
            f"to {dst_ip or 'unknown'}"
        )
        if dst_port:
            description += f":{dst_port}"
        if service:
            description += f" ({service})"
        if state:
            description += f", state: {state}"
        if total_bytes > 0:
            description += f", {_bytes_label(total_bytes)} transferred"
        if duration and duration != _UNSET:
            try:
                description += f", duration: {float(duration):.1f}s"
            except ValueError:
                pass
        description += "."

        return SecurityEventRequest(
            description=description,
            source_ip=src_ip,
            destination_ip=dst_ip,
            event_type="network_connection",
            timestamp=_field(r.get("ts", _UNSET)),
        )

    def _build_dns(self, r: dict) -> SecurityEventRequest:
        src_ip = _field(r.get("id.orig_h", _UNSET))
        dst_ip = _field(r.get("id.resp_h", _UNSET))
        query = _field(r.get("query", _UNSET)) or "unknown"
        qtype = _field(r.get("qtype_name", _UNSET)) or "A"
        rcode = _field(r.get("rcode_name", _UNSET)) or "NOERROR"
        answers = _field(r.get("answers", _UNSET))

        description = f"DNS {qtype} query for '{query}' (rcode: {rcode})."
        ctx_parts: list[str] = []
        if answers:
            ctx_parts.append(f"Answers: {answers[:200]}")
        ttls = _field(r.get("TTLs", _UNSET))
        if ttls:
            ctx_parts.append(f"TTLs: {ttls}")

        return SecurityEventRequest(
            description=description,
            source_ip=src_ip,
            destination_ip=dst_ip,
            event_type="dns",
            timestamp=_field(r.get("ts", _UNSET)),
            additional_context="; ".join(ctx_parts) if ctx_parts else None,
        )

    def _build_http(self, r: dict) -> SecurityEventRequest:
        src_ip = _field(r.get("id.orig_h", _UNSET))
        dst_ip = _field(r.get("id.resp_h", _UNSET))
        method = _field(r.get("method", _UNSET)) or "GET"
        host = _field(r.get("host", _UNSET)) or dst_ip or "unknown"
        uri = _field(r.get("uri", _UNSET)) or "/"
        status = _field(r.get("status_code", _UNSET))

        description = f"HTTP {method} {host}{uri}"
        if status:
            description += f" → {status}"
        description += "."

        ctx_parts: list[str] = []
        ua = _field(r.get("user_agent", _UNSET))
        if ua:
            ctx_parts.append(f"User-Agent: {ua[:120]}")
        mime = _field(r.get("resp_mime_types", _UNSET))
        if mime:
            ctx_parts.append(f"MIME: {mime}")

        return SecurityEventRequest(
            description=description,
            source_ip=src_ip,
            destination_ip=dst_ip,
            event_type="http",
            timestamp=_field(r.get("ts", _UNSET)),
            additional_context="; ".join(ctx_parts) if ctx_parts else None,
        )

    def _build_ssl(self, r: dict) -> SecurityEventRequest:
        src_ip = _field(r.get("id.orig_h", _UNSET))
        dst_ip = _field(r.get("id.resp_h", _UNSET))
        server_name = _field(r.get("server_name", _UNSET)) or dst_ip or "unknown"
        version = _field(r.get("version", _UNSET)) or "unknown"
        established = _field(r.get("established", _UNSET))

        status = "established" if established == "T" else "failed"
        description = (
            f"TLS {status}: {server_name} "
            f"(version: {version}) "
            f"from {src_ip or 'unknown'}."
        )

        ctx_parts: list[str] = []
        cipher = _field(r.get("cipher", _UNSET))
        if cipher:
            ctx_parts.append(f"Cipher: {cipher}")
        issuer = _field(r.get("issuer", _UNSET))
        if issuer:
            ctx_parts.append(f"Issuer: {issuer[:80]}")
        validation_status = _field(r.get("validation_status", _UNSET))
        if validation_status and validation_status != "ok":
            ctx_parts.append(f"Cert validation: {validation_status}")

        return SecurityEventRequest(
            description=description,
            source_ip=src_ip,
            destination_ip=dst_ip,
            event_type="tls",
            timestamp=_field(r.get("ts", _UNSET)),
            additional_context="; ".join(ctx_parts) if ctx_parts else None,
        )

    def _build_notice(self, r: dict) -> Optional[SecurityEventRequest]:
        actions = _field(r.get("actions", _UNSET)) or ""
        if self._min_notice_action:
            if not any(a in actions for a in self._min_notice_action):
                return None

        src_ip = _field(r.get("id.orig_h", _UNSET)) or _field(r.get("src", _UNSET))
        dst_ip = _field(r.get("id.resp_h", _UNSET)) or _field(r.get("dst", _UNSET))
        note = _field(r.get("note", _UNSET)) or "Unknown notice"
        msg = _field(r.get("msg", _UNSET)) or ""
        sub = _field(r.get("sub", _UNSET)) or ""

        description = f"Zeek notice: {note}."
        if msg:
            description += f" {msg}"

        ctx_parts: list[str] = []
        if sub:
            ctx_parts.append(f"Sub: {sub[:120]}")
        if actions:
            ctx_parts.append(f"Actions: {actions}")

        return SecurityEventRequest(
            description=description.strip(),
            source_ip=src_ip,
            destination_ip=dst_ip,
            event_type="zeek_notice",
            severity="high",
            timestamp=_field(r.get("ts", _UNSET)),
            additional_context="; ".join(ctx_parts) if ctx_parts else None,
        )

    def _build_weird(self, r: dict) -> SecurityEventRequest:
        src_ip = _field(r.get("id.orig_h", _UNSET))
        dst_ip = _field(r.get("id.resp_h", _UNSET))
        name = _field(r.get("name", _UNSET)) or "unknown_weird"
        addl = _field(r.get("addl", _UNSET)) or ""

        description = f"Zeek weird: unexpected protocol behavior '{name}'"
        if addl:
            description += f" ({addl})"
        description += f". From {src_ip or 'unknown'} to {dst_ip or 'unknown'}."

        return SecurityEventRequest(
            description=description,
            source_ip=src_ip,
            destination_ip=dst_ip,
            event_type="protocol_anomaly",
            timestamp=_field(r.get("ts", _UNSET)),
        )


# ── Private helpers ───────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    """Return True if the IP is in an RFC-1918 private range (IPv4 only)."""
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return False
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
    except (ValueError, AttributeError):
        pass
    return False
