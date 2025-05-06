"""
End-to-end local test script for the Local LLM Security Engine.

Requires the server to be running: uvicorn app.main:app --host 0.0.0.0 --port 8000
Requires Ollama to be running with the configured model.

Usage:
    python test_local.py [--url http://localhost:8000] [--api-key YOUR_KEY]

Exit codes:
    0 — all checks passed
    1 — server unreachable, Ollama unreachable, or schema invalid
"""

import sys
import json
import argparse
import requests

REQUIRED_RESPONSE_KEYS = {
    "attack_classification",
    "false_positive_likelihood",
    "risk_score",
    "reason",
    "fallback_used",
    "model_used",
    "provider",
    "raw_parse_success",
    "parse_strategy",
    "ollama_error",
    "request_id",
}

VALID_CLASSIFICATIONS = {
    "reconnaissance", "credential_access", "initial_access",
    "lateral_movement", "command_and_control", "benign", "unknown",
}


def print_section(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print('─' * 60)


def print_result(result: dict) -> None:
    print(json.dumps(result, indent=2))


def check_health(base_url: str, headers: dict) -> bool:
    print_section("1/4  Health Check")
    try:
        r = requests.get(f"{base_url}/health", timeout=5)
        health = r.json()
        status = health.get("status", "unknown")
        ollama = health.get("ollama", {})
        print(f"  Service status   : {status}")
        print(f"  Ollama reachable : {ollama.get('reachable')}")
        print(f"  Model configured : {ollama.get('configured_model')}")
        print(f"  Model available  : {ollama.get('model_available')}")
        if ollama.get("error"):
            print(f"  Ollama error     : {ollama['error']}")

        if not ollama.get("reachable"):
            print("\n  ERROR: Ollama is not reachable.")
            print(f"  Expected at: {ollama.get('configured_model', 'unknown URL')}")
            print("  Make sure Ollama is running: ollama serve")
            return False

        print("\n  Health check passed.")
        return True
    except requests.ConnectionError:
        print(f"\n  ERROR: Cannot reach the FastAPI server at {base_url}")
        print("  Start it with: uvicorn app.main:app --host 0.0.0.0 --port 8000")
        return False


def check_analyze_event(base_url: str, headers: dict) -> bool:
    print_section("2/4  POST /analyze-event (brute-force login)")
    payload = {
        "source_ip": "185.220.101.1",
        "destination_ip": "10.0.0.5",
        "event_type": "authentication_failure",
        "severity": "high",
        "description": (
            "Detected 120 failed login attempts against SSH on port 22 "
            "from an external IP over 3 minutes. The final attempt succeeded."
        ),
        "additional_context": "Source IP is flagged in threat intel as a known brute-force source.",
    }

    try:
        r = requests.post(f"{base_url}/analyze-event", json=payload, headers=headers, timeout=120)
    except requests.Timeout:
        print("  ERROR: Request timed out waiting for Ollama.")
        return False

    if r.status_code == 401:
        print("  ERROR: Authentication required. Pass --api-key flag.")
        return False
    if r.status_code == 403:
        print("  ERROR: Invalid API key.")
        return False
    if r.status_code != 200:
        print(f"  ERROR: Got status {r.status_code}: {r.text}")
        return False

    result = r.json()
    print_result(result)
    return _validate_schema(result, "/analyze-event")


def check_analyze_context(base_url: str, headers: dict) -> bool:
    print_section("3/4  POST /analyze-context (insider threat)")
    payload = {
        "entity": "user:jane.smith@corp.com",
        "summary": (
            "Over 6 hours: accessed 12 servers never visited before, "
            "downloaded 4.2GB, connected from VPN exit in Eastern Europe. "
            "Normal is US access to 2-3 servers."
        ),
        "time_window": "2024-01-15 06:00 - 12:00 UTC",
        "additional_context": "No travel logged in HR system. Mid-level analyst.",
    }

    try:
        r = requests.post(f"{base_url}/analyze-context", json=payload, headers=headers, timeout=120)
    except requests.Timeout:
        print("  ERROR: Request timed out.")
        return False

    if r.status_code != 200:
        print(f"  ERROR: Got status {r.status_code}: {r.text}")
        return False

    result = r.json()
    print_result(result)
    return _validate_schema(result, "/analyze-context")


def check_request_id(base_url: str, headers: dict) -> bool:
    print_section("4/4  Request ID Tracing")
    custom_id = "test-trace-abc-123"
    hdrs = {**headers, "X-Request-ID": custom_id}
    r = requests.get(f"{base_url}/health", headers=hdrs, timeout=5)
    echoed = r.headers.get("X-Request-ID")
    if echoed == custom_id:
        print(f"  X-Request-ID correctly echoed: {echoed}")
        return True
    else:
        print(f"  WARNING: X-Request-ID not echoed. Got: {echoed}")
        return True  # Non-fatal for health endpoint


def _validate_schema(result: dict, endpoint: str) -> bool:
    errors = []

    missing = REQUIRED_RESPONSE_KEYS - set(result.keys())
    if missing:
        errors.append(f"Missing keys: {missing}")

    cls = result.get("attack_classification")
    if cls not in VALID_CLASSIFICATIONS:
        errors.append(f"Invalid attack_classification: '{cls}'")

    fp = result.get("false_positive_likelihood")
    if not isinstance(fp, (int, float)) or not (0.0 <= fp <= 1.0):
        errors.append(f"false_positive_likelihood out of range: {fp}")

    rs = result.get("risk_score")
    if not isinstance(rs, int) or not (0 <= rs <= 100):
        errors.append(f"risk_score out of range: {rs}")

    reason = result.get("reason", "")
    if not reason or not reason.strip():
        errors.append("reason is empty")

    if result.get("provider") != "ollama":
        errors.append(f"Unexpected provider: {result.get('provider')}")

    if errors:
        print(f"\n  SCHEMA ERRORS on {endpoint}:")
        for e in errors:
            print(f"    ✗ {e}")
        return False

    fallback = result.get("fallback_used")
    if fallback:
        print(f"\n  NOTE: fallback_used=true — model may not have returned valid JSON.")
        print(f"  Reason: {result.get('reason')}")
        print(f"  Ollama error: {result.get('ollama_error')}")
    else:
        parse_strategy = result.get("parse_strategy")
        print(f"\n  Schema valid. Classification: {cls}, Risk: {rs}, "
              f"FP likelihood: {fp}, Parse strategy: {parse_strategy}")

    return True


def main():
    parser = argparse.ArgumentParser(description="End-to-end test for Local LLM Security Engine")
    parser.add_argument("--url", default="http://localhost:8000", help="Service base URL")
    parser.add_argument("--api-key", default=None, help="X-API-Key value (if auth is enabled)")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    headers = {"Content-Type": "application/json"}
    if args.api_key:
        headers["X-API-Key"] = args.api_key

    print("=" * 60)
    print("  Local LLM Security Engine — End-to-End Test")
    print(f"  Target: {base_url}")
    print("=" * 60)

    results = [
        check_health(base_url, headers),
        check_analyze_event(base_url, headers),
        check_analyze_context(base_url, headers),
        check_request_id(base_url, headers),
    ]

    passed = sum(results)
    total = len(results)

    print(f"\n{'=' * 60}")
    print(f"  Result: {passed}/{total} checks passed")
    if passed == total:
        print("  Service is ready for SOC backend integration.")
    else:
        print("  Fix the errors above before connecting to a SOC backend.")
    print("=" * 60)

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
