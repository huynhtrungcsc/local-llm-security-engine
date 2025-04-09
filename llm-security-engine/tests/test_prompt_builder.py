import pytest
from app.models.schemas import SecurityEvent, ContextSummary
from app.services.prompt_builder import build_event_prompt, build_context_prompt


# ─── Event prompt ─────────────────────────────────────────────────────────────

def test_event_prompt_contains_description():
    event = SecurityEvent(description="Multiple failed SSH logins from 192.168.1.1")
    prompt = build_event_prompt(event)
    assert "Multiple failed SSH logins from 192.168.1.1" in prompt


def test_event_prompt_contains_system_instruction():
    event = SecurityEvent(description="Port scan detected")
    prompt = build_event_prompt(event)
    assert "cybersecurity" in prompt.lower()
    assert "JSON" in prompt


def test_event_prompt_contains_label_definitions():
    event = SecurityEvent(description="Suspicious activity")
    prompt = build_event_prompt(event)
    for label in ["reconnaissance", "credential_access", "initial_access",
                  "lateral_movement", "command_and_control", "benign", "unknown"]:
        assert label in prompt, f"Label '{label}' missing from prompt"


def test_event_prompt_includes_distinguishing_examples():
    event = SecurityEvent(description="Brute force followed by login")
    prompt = build_event_prompt(event)
    assert "initial_access" in prompt
    assert "credential_access" in prompt
    assert "failed login" in prompt.lower() or "failed" in prompt.lower()


def test_event_prompt_with_all_optional_fields():
    event = SecurityEvent(
        source_ip="10.0.0.5",
        destination_ip="192.168.1.100",
        event_type="network_scan",
        severity="high",
        description="Nmap scan from internal subnet.",
        timestamp="2024-01-15T10:30:00Z",
        additional_context="Asset is a production database server.",
    )
    prompt = build_event_prompt(event)
    assert "10.0.0.5" in prompt
    assert "192.168.1.100" in prompt
    assert "network_scan" in prompt
    assert "high" in prompt
    assert "Nmap scan" in prompt
    assert "2024-01-15T10:30:00Z" in prompt
    assert "production database" in prompt


def test_event_prompt_omits_missing_optional_fields():
    event = SecurityEvent(description="Anomalous outbound traffic detected.")
    prompt = build_event_prompt(event)
    assert "Anomalous outbound traffic" in prompt
    assert "Source IP" not in prompt
    assert "Destination IP" not in prompt
    assert "Event Type" not in prompt


def test_event_prompt_enforces_json_only_output():
    event = SecurityEvent(description="Test event.")
    prompt = build_event_prompt(event)
    assert "no markdown" in prompt.lower() or "markdown" in prompt.lower()
    assert "Return only" in prompt or "return only" in prompt.lower()


# ─── Context prompt ───────────────────────────────────────────────────────────

def test_context_prompt_contains_summary():
    ctx = ContextSummary(summary="User admin performed 5 failed logins and one successful from a new country.")
    prompt = build_context_prompt(ctx)
    assert "failed logins" in prompt
    assert "new country" in prompt


def test_context_prompt_with_all_fields():
    ctx = ContextSummary(
        entity="user:admin@corp.com",
        summary="Unusual behavior including off-hours access and bulk data download.",
        time_window="2024-01-15 08:00 - 10:00 UTC",
        additional_context="User is on leave per HR system.",
    )
    prompt = build_context_prompt(ctx)
    assert "admin@corp.com" in prompt
    assert "bulk data download" in prompt
    assert "2024-01-15" in prompt
    assert "on leave" in prompt


def test_context_prompt_contains_all_labels():
    ctx = ContextSummary(summary="Lateral movement suspected.")
    prompt = build_context_prompt(ctx)
    for label in ["reconnaissance", "credential_access", "initial_access",
                  "lateral_movement", "command_and_control", "benign", "unknown"]:
        assert label in prompt


def test_context_prompt_enforces_no_markdown():
    ctx = ContextSummary(summary="Test context.")
    prompt = build_context_prompt(ctx)
    assert "markdown" in prompt.lower()


# ─── Edge cases ───────────────────────────────────────────────────────────────

def test_event_prompt_with_very_long_description():
    long_desc = "Suspicious " * 200
    event = SecurityEvent(description=long_desc)
    prompt = build_event_prompt(event)
    assert long_desc.strip() in prompt


def test_event_prompt_with_special_characters_in_description():
    desc = 'Login attempt with payload: \'{"user":"admin","pass":"\\' + "' or '1'='1"
    event = SecurityEvent(description=desc)
    prompt = build_event_prompt(event)
    assert desc in prompt
