"""
Sample Python requests for the Local LLM Security Engine.
Run the server first: uvicorn app.main:app --host 0.0.0.0 --port 8000

Usage:
    python samples/sample_requests.py
"""

import requests
import json

BASE_URL = "http://localhost:8000"


def print_response(endpoint: str, response: requests.Response):
    print(f"\n{'='*60}")
    print(f"Endpoint: {endpoint}")
    print(f"Status:   {response.status_code}")
    print(f"Response:")
    try:
        print(json.dumps(response.json(), indent=2))
    except Exception:
        print(response.text)
    print("="*60)


def test_health():
    r = requests.get(f"{BASE_URL}/health")
    print_response("GET /health", r)


def test_analyze_event_port_scan():
    payload = {
        "source_ip": "203.0.113.42",
        "destination_ip": "10.0.0.100",
        "event_type": "network_scan",
        "severity": "medium",
        "description": "Nmap SYN scan detected targeting 1000+ ports on internal host.",
        "timestamp": "2024-01-15T10:30:00Z",
        "additional_context": "Source IP is external. No prior activity from this IP."
    }
    r = requests.post(f"{BASE_URL}/analyze-event", json=payload)
    print_response("POST /analyze-event (port scan)", r)


def test_analyze_event_failed_logins():
    payload = {
        "source_ip": "192.168.1.50",
        "event_type": "authentication_failure",
        "severity": "high",
        "description": "57 failed SSH login attempts to admin account within 5 minutes. Followed by one successful login.",
        "timestamp": "2024-01-15T14:22:00Z"
    }
    r = requests.post(f"{BASE_URL}/analyze-event", json=payload)
    print_response("POST /analyze-event (brute force)", r)


def test_analyze_context():
    payload = {
        "entity": "user:john.doe@corp.com",
        "summary": (
            "Over the past 6 hours, this user accessed 12 internal servers they have never visited before, "
            "downloaded 4.2GB of data, and connected from a VPN exit node in Eastern Europe. "
            "Normal pattern is US-based access to 2-3 servers."
        ),
        "time_window": "2024-01-15 06:00 - 12:00 UTC",
        "additional_context": "User is a mid-level developer. No travel logged in HR system."
    }
    r = requests.post(f"{BASE_URL}/analyze-context", json=payload)
    print_response("POST /analyze-context (insider threat)", r)


def test_raw_ollama():
    payload = {
        "prompt": "What is the most common first stage of a cyberattack? Respond in one sentence."
    }
    r = requests.post(f"{BASE_URL}/raw-ollama-test", json=payload)
    print_response("POST /raw-ollama-test", r)


if __name__ == "__main__":
    print("Local LLM Security Engine - Sample Requests")
    print("Make sure the server is running: uvicorn app.main:app --host 0.0.0.0 --port 8000")

    test_health()
    test_analyze_event_port_scan()
    test_analyze_event_failed_logins()
    test_analyze_context()
    test_raw_ollama()
