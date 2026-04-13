#!/usr/bin/env python3
"""
Batch analysis CLI for the Local LLM Security Engine.

Reads a JSONL or CSV file of security events, sends each one to the engine,
and writes structured results to an output file.

Usage
-----
Analyze a JSONL file (one SecurityEvent JSON per line)::

    python scripts/batch_analyze.py \\
        --input events.jsonl \\
        --output results.jsonl \\
        --engine-url http://localhost:8000 \\
        --api-key your-secret-key

Analyze a Suricata EVE JSON log directly::

    python scripts/batch_analyze.py \\
        --input /var/log/suricata/eve.json \\
        --format suricata \\
        --output results.jsonl \\
        --engine-url https://your-tunnel.trycloudflare.com

Analyze a Zeek notice.log::

    python scripts/batch_analyze.py \\
        --input /opt/zeek/logs/current/notice.log \\
        --format zeek \\
        --output results.jsonl

Output format
-------------
Each output line is a JSON object containing the original event fields plus
the full AnalysisResponse from the engine::

    {
      "input_description": "...",
      "attack_classification": "credential_access",
      "risk_score": 88,
      "false_positive_likelihood": 0.05,
      "reason": "...",
      "fallback_used": false,
      "model_used": "phi4-mini",
      "raw_parse_success": true,
      "parse_strategy": "direct",
      "ollama_error": null,
      "request_id": "sdk-..."
    }

Options
-------
--concurrency N     Number of concurrent engine requests (default: 4).
                    Increase for faster throughput; decrease if you hit rate limits.
--timeout N         Per-request timeout in seconds (default: 120).
--skip-fallbacks    Exclude results where fallback_used=true from the output.
--min-risk N        Only write results with risk_score >= N (0–100, default: 0).
--summary           Print a classification summary table when finished.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Batch-analyze security events using the Local LLM Security Engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="Input file path. JSONL (one SecurityEvent JSON per line), "
             "Suricata EVE JSON, or Zeek log depending on --format.",
    )
    parser.add_argument(
        "--output", "-o", required=True,
        help="Output JSONL file path (created or overwritten).",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["jsonl", "suricata", "zeek"],
        default="jsonl",
        help="Input file format (default: jsonl).",
    )
    parser.add_argument(
        "--engine-url",
        default="http://localhost:8000",
        help="Engine base URL (default: http://localhost:8000).",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="X-API-Key for the engine (optional; required if LOCAL_LLM_API_KEY is set).",
    )
    parser.add_argument(
        "--concurrency", "-c",
        type=int, default=4,
        help="Number of concurrent engine requests (default: 4).",
    )
    parser.add_argument(
        "--timeout",
        type=float, default=120.0,
        help="Per-request timeout in seconds (default: 120).",
    )
    parser.add_argument(
        "--skip-fallbacks",
        action="store_true",
        help="Exclude results where fallback_used=true.",
    )
    parser.add_argument(
        "--min-risk",
        type=int, default=0,
        help="Only include results with risk_score >= N (default: 0).",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a classification summary table after processing.",
    )
    return parser.parse_args()


def _load_jsonl_events(path: str) -> list[dict]:
    """Load SecurityEvent dicts from a JSONL file."""
    events: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "description" not in obj:
                    logger.warning("Line %d: missing 'description' field, skipping.", i)
                    continue
                events.append(obj)
            except json.JSONDecodeError:
                logger.warning("Line %d: JSON parse error, skipping.", i)
    return events


def _load_suricata_events(path: str) -> list[dict]:
    """Load events from a Suricata EVE JSON log via the SuricataAdapter."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from adapters.suricata import SuricataAdapter
    adapter = SuricataAdapter()
    requests = adapter.parse_file(path)
    return [r.to_dict() for r in requests]


def _load_zeek_events(path: str) -> list[dict]:
    """Load events from a Zeek log file via the ZeekAdapter."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from adapters.zeek import ZeekAdapter
    adapter = ZeekAdapter()
    requests = adapter.parse_file(path)
    return [r.to_dict() for r in requests]


async def _analyze_batch(
    events: list[dict],
    engine_url: str,
    api_key: Optional[str],
    timeout: float,
    concurrency: int,
    skip_fallbacks: bool,
    min_risk: int,
    output_path: str,
) -> dict[str, int]:
    """Run concurrent analysis and stream results to the output file."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from sdk.client import AsyncEngineClient
    from sdk.models import SecurityEventRequest
    from sdk.exceptions import EngineError

    semaphore = asyncio.Semaphore(concurrency)
    counters: dict[str, int] = {
        "total": len(events),
        "processed": 0,
        "written": 0,
        "skipped_fallback": 0,
        "skipped_min_risk": 0,
        "errors": 0,
    }

    async def analyze_one(client, event_dict: dict) -> Optional[dict]:
        request = SecurityEventRequest(
            description=event_dict["description"],
            source_ip=event_dict.get("source_ip"),
            destination_ip=event_dict.get("destination_ip"),
            event_type=event_dict.get("event_type"),
            severity=event_dict.get("severity"),
            timestamp=event_dict.get("timestamp"),
            additional_context=event_dict.get("additional_context"),
        )
        async with semaphore:
            try:
                result = await client.analyze_event(request)
                counters["processed"] += 1
                return {
                    "input_description": event_dict["description"],
                    "input_source_ip": event_dict.get("source_ip"),
                    "input_event_type": event_dict.get("event_type"),
                    "attack_classification": result.attack_classification,
                    "risk_score": result.risk_score,
                    "false_positive_likelihood": result.false_positive_likelihood,
                    "reason": result.reason,
                    "fallback_used": result.fallback_used,
                    "model_used": result.model_used,
                    "raw_parse_success": result.raw_parse_success,
                    "parse_strategy": result.parse_strategy,
                    "ollama_error": result.ollama_error,
                    "request_id": result.request_id,
                }
            except EngineError as exc:
                counters["errors"] += 1
                logger.error("Engine error for event '%s...': %s",
                             event_dict["description"][:40], exc)
                return None

    async with AsyncEngineClient(
        base_url=engine_url, api_key=api_key, timeout=timeout
    ) as client:
        tasks = [analyze_one(client, ev) for ev in events]
        with open(output_path, "w", encoding="utf-8") as out_fh:
            for coro in asyncio.as_completed(tasks):
                result_dict = await coro
                if result_dict is None:
                    continue
                if skip_fallbacks and result_dict["fallback_used"]:
                    counters["skipped_fallback"] += 1
                    continue
                if result_dict["risk_score"] < min_risk:
                    counters["skipped_min_risk"] += 1
                    continue
                out_fh.write(json.dumps(result_dict, ensure_ascii=False) + "\n")
                counters["written"] += 1

                if counters["processed"] % 10 == 0:
                    logger.info(
                        "Progress: %d/%d processed, %d written",
                        counters["processed"], counters["total"], counters["written"],
                    )

    return counters


def _print_summary(output_path: str) -> None:
    """Read the output file and print a classification breakdown."""
    classification_counts: dict[str, int] = {}
    total = 0
    fallbacks = 0
    high_risk = 0

    with open(output_path, encoding="utf-8") as fh:
        for line in fh:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            label = row.get("attack_classification", "unknown")
            classification_counts[label] = classification_counts.get(label, 0) + 1
            total += 1
            if row.get("fallback_used"):
                fallbacks += 1
            if row.get("risk_score", 0) >= 70:
                high_risk += 1

    if total == 0:
        print("\nNo results to summarize.")
        return

    print(f"\n{'─' * 50}")
    print(f"{'Classification Summary':^50}")
    print(f"{'─' * 50}")
    for label, count in sorted(classification_counts.items(), key=lambda x: -x[1]):
        bar = "█" * int(count / total * 30)
        print(f"  {label:<22} {count:>4}  {bar}")
    print(f"{'─' * 50}")
    print(f"  Total results:    {total}")
    print(f"  Fallbacks:        {fallbacks}")
    print(f"  High-risk (≥70):  {high_risk}")
    print(f"{'─' * 50}\n")


def main() -> int:
    args = _parse_args()

    logger.info("Loading events from %s (format: %s)...", args.input, args.format)
    if args.format == "jsonl":
        events = _load_jsonl_events(args.input)
    elif args.format == "suricata":
        events = _load_suricata_events(args.input)
    else:
        events = _load_zeek_events(args.input)

    if not events:
        logger.error("No events found in %s. Exiting.", args.input)
        return 1

    logger.info("Loaded %d events. Starting analysis (concurrency=%d)...",
                len(events), args.concurrency)

    t0 = time.monotonic()
    counters = asyncio.run(_analyze_batch(
        events=events,
        engine_url=args.engine_url,
        api_key=args.api_key,
        timeout=args.timeout,
        concurrency=args.concurrency,
        skip_fallbacks=args.skip_fallbacks,
        min_risk=args.min_risk,
        output_path=args.output,
    ))
    elapsed = time.monotonic() - t0

    logger.info(
        "Done in %.1fs — %d processed, %d written, %d errors, "
        "%d skipped (fallback), %d skipped (min-risk).",
        elapsed,
        counters["processed"],
        counters["written"],
        counters["errors"],
        counters["skipped_fallback"],
        counters["skipped_min_risk"],
    )

    if args.summary:
        _print_summary(args.output)

    return 0 if counters["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
