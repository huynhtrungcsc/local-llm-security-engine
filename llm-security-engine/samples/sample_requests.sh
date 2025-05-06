#!/bin/bash
# Sample curl requests for the Local LLM Security Engine
# Run the server first: uvicorn app.main:app --host 0.0.0.0 --port 8000

BASE_URL="http://localhost:8000"

echo ""
echo "=============================="
echo "GET /health"
echo "=============================="
curl -s -X GET "$BASE_URL/health" | python3 -m json.tool

echo ""
echo "=============================="
echo "POST /analyze-event (port scan)"
echo "=============================="
curl -s -X POST "$BASE_URL/analyze-event" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "203.0.113.42",
    "destination_ip": "10.0.0.100",
    "event_type": "network_scan",
    "severity": "medium",
    "description": "Nmap SYN scan detected targeting 1000+ ports on internal host.",
    "timestamp": "2024-01-15T10:30:00Z",
    "additional_context": "Source IP is external. No prior activity from this IP."
  }' | python3 -m json.tool

echo ""
echo "=============================="
echo "POST /analyze-event (brute force)"
echo "=============================="
curl -s -X POST "$BASE_URL/analyze-event" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.50",
    "event_type": "authentication_failure",
    "severity": "high",
    "description": "57 failed SSH login attempts to admin account within 5 minutes. Followed by one successful login."
  }' | python3 -m json.tool

echo ""
echo "=============================="
echo "POST /analyze-context (insider threat)"
echo "=============================="
curl -s -X POST "$BASE_URL/analyze-context" \
  -H "Content-Type: application/json" \
  -d '{
    "entity": "user:john.doe@corp.com",
    "summary": "Over 6 hours: accessed 12 internal servers never visited before, downloaded 4.2GB, connected from VPN exit in Eastern Europe. Normal is US access to 2-3 servers.",
    "time_window": "2024-01-15 06:00 - 12:00 UTC",
    "additional_context": "Mid-level developer. No travel in HR system."
  }' | python3 -m json.tool

echo ""
echo "=============================="
echo "POST /raw-ollama-test"
echo "=============================="
curl -s -X POST "$BASE_URL/raw-ollama-test" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "What is the most common first stage of a cyberattack? One sentence only."
  }' | python3 -m json.tool
