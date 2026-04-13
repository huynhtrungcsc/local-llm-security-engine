"""
Log format adapters for the Local LLM Security Engine.

Each adapter converts native log records from a specific security tool into
``SecurityEventRequest`` objects that can be passed directly to the engine SDK.

Available adapters
------------------
- ``suricata`` — Suricata EVE JSON (alert, dns, http, tls event types)
- ``zeek`` — Zeek tab-separated logs (conn.log, dns.log, http.log, notice.log)

Example::

    from adapters.suricata import SuricataAdapter
    from sdk import EngineClient

    adapter = SuricataAdapter()
    with EngineClient(base_url="http://localhost:8000") as client:
        for line in open("/var/log/suricata/eve.json"):
            event = adapter.parse_line(line)
            if event:
                result = client.analyze_event(event)
                print(result.attack_classification, result.risk_score)
"""

from adapters.suricata import SuricataAdapter
from adapters.zeek import ZeekAdapter

__all__ = ["SuricataAdapter", "ZeekAdapter"]
