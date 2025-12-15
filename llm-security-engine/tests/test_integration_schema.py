"""
Tests for the stable AnalysisResponse schema and end-to-end pipeline
(without calling a real Ollama instance).
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.models.schemas import AnalysisResponse, AnalysisResult, SecurityEvent, ContextSummary
from app.services.parser import extract_json_from_response
from app.services.validator import validate_analysis_result


# ─── Schema stability ─────────────────────────────────────────────────────────

def test_analysis_response_has_all_required_fields():
    response = AnalysisResponse(
        attack_classification="reconnaissance",
        false_positive_likelihood=0.2,
        risk_score=75,
        reason="Port scan detected.",
        fallback_used=False,
        model_used="phi4-mini",
        provider="ollama",
        raw_parse_success=True,
        parse_strategy="direct",
        ollama_error=None,
    )
    assert response.attack_classification == "reconnaissance"
    assert response.model_used == "phi4-mini"
    assert response.provider == "ollama"
    assert response.raw_parse_success is True
    assert response.parse_strategy == "direct"
    assert response.ollama_error is None


def test_analysis_response_provider_is_always_ollama():
    response = AnalysisResponse(
        attack_classification="benign",
        false_positive_likelihood=0.9,
        risk_score=5,
        reason="Normal.",
        fallback_used=False,
        model_used="phi4-mini",
        provider="ollama",
        raw_parse_success=True,
        parse_strategy="direct",
        ollama_error=None,
    )
    assert response.provider == "ollama"


def test_analysis_response_fallback_with_ollama_error():
    response = AnalysisResponse(
        attack_classification="unknown",
        false_positive_likelihood=0.5,
        risk_score=50,
        reason="Analysis failed. Manual review required.",
        fallback_used=True,
        model_used="phi4-mini",
        provider="ollama",
        raw_parse_success=False,
        parse_strategy=None,
        ollama_error="Cannot connect to Ollama at http://localhost:11434",
    )
    assert response.fallback_used is True
    assert response.raw_parse_success is False
    assert response.ollama_error is not None
    assert response.parse_strategy is None


def test_analysis_response_serializes_to_dict():
    response = AnalysisResponse(
        attack_classification="lateral_movement",
        false_positive_likelihood=0.1,
        risk_score=88,
        reason="SMB lateral spread observed.",
        fallback_used=False,
        model_used="phi4-mini",
        provider="ollama",
        raw_parse_success=True,
        parse_strategy="brace_extract",
        ollama_error=None,
    )
    d = response.model_dump()
    assert set(d.keys()) == {
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


# ─── Pipeline: parse → validate ───────────────────────────────────────────────

def test_pipeline_valid_output():
    raw = '{"attack_classification": "credential_access", "false_positive_likelihood": 0.05, "risk_score": 92, "reason": "Brute force login."}'
    parse_result = extract_json_from_response(raw)
    validated = validate_analysis_result(parse_result.data)
    assert validated.fallback_used is False
    assert validated.attack_classification == "credential_access"
    assert parse_result.success is True


def test_pipeline_invalid_model_output_triggers_fallback():
    raw = "I cannot determine the classification from this event."
    parse_result = extract_json_from_response(raw)
    validated = validate_analysis_result(parse_result.data)
    assert validated.fallback_used is True
    assert validated.attack_classification == "unknown"
    assert parse_result.success is False


def test_pipeline_partial_json_triggers_fallback():
    raw = '{"attack_classification": "bad_label", "false_positive_likelihood": 2.5}'
    parse_result = extract_json_from_response(raw)
    validated = validate_analysis_result(parse_result.data)
    assert validated.fallback_used is True


def test_pipeline_empty_response_triggers_fallback():
    parse_result = extract_json_from_response("")
    validated = validate_analysis_result(parse_result.data)
    assert validated.fallback_used is True
    assert parse_result.success is False


# ─── Edge-case event inputs ───────────────────────────────────────────────────

def test_security_event_description_only():
    event = SecurityEvent(description="Outbound connection to known C2 IP.")
    assert event.source_ip is None
    assert event.destination_ip is None
    assert event.description == "Outbound connection to known C2 IP."


def test_security_event_all_fields():
    event = SecurityEvent(
        source_ip="10.10.10.5",
        destination_ip="185.220.101.1",
        event_type="dns_query",
        severity="critical",
        description="DNS query to known C2 domain.",
        timestamp="2024-01-20T03:14:15Z",
        additional_context="Host is a jump server.",
    )
    assert event.event_type == "dns_query"
    assert event.severity == "critical"


def test_context_summary_minimal():
    ctx = ContextSummary(summary="High outbound traffic from workstation.")
    assert ctx.entity is None
    assert ctx.time_window is None


def test_context_summary_full():
    ctx = ContextSummary(
        entity="host:ws-001",
        summary="12 failed logins then successful login at 3am.",
        time_window="2024-01-20 01:00 - 04:00 UTC",
        additional_context="Outside business hours.",
    )
    assert ctx.entity == "host:ws-001"
    assert ctx.time_window == "2024-01-20 01:00 - 04:00 UTC"
