"""
Tests for input size validation on all request models.
Ensures oversized inputs are rejected with HTTP 422 before reaching Ollama.
"""
import pytest
from pydantic import ValidationError
from app.models.schemas import SecurityEvent, ContextSummary, RawPromptRequest
from app.config import get_settings

settings = get_settings()


# ─── SecurityEvent ────────────────────────────────────────────────────────────

def test_event_description_at_max_length_is_valid():
    desc = "A" * settings.MAX_DESCRIPTION_LENGTH
    event = SecurityEvent(description=desc)
    assert len(event.description) == settings.MAX_DESCRIPTION_LENGTH


def test_event_description_exceeds_max_length_raises():
    desc = "A" * (settings.MAX_DESCRIPTION_LENGTH + 1)
    with pytest.raises(ValidationError) as exc_info:
        SecurityEvent(description=desc)
    errors = exc_info.value.errors()
    assert any(e["loc"] == ("description",) for e in errors)


def test_event_description_empty_raises():
    with pytest.raises(ValidationError):
        SecurityEvent(description="")


def test_event_additional_context_at_max_length_is_valid():
    ctx = "B" * settings.MAX_CONTEXT_LENGTH
    event = SecurityEvent(description="Test.", additional_context=ctx)
    assert event.additional_context is not None
    assert len(event.additional_context) == settings.MAX_CONTEXT_LENGTH


def test_event_additional_context_exceeds_max_length_raises():
    ctx = "B" * (settings.MAX_CONTEXT_LENGTH + 1)
    with pytest.raises(ValidationError) as exc_info:
        SecurityEvent(description="Test.", additional_context=ctx)
    errors = exc_info.value.errors()
    assert any(e["loc"] == ("additional_context",) for e in errors)


def test_event_source_ip_exceeds_max_field_length_raises():
    bad_ip = "1" * (settings.MAX_FIELD_LENGTH + 1)
    with pytest.raises(ValidationError) as exc_info:
        SecurityEvent(description="Test.", source_ip=bad_ip)
    errors = exc_info.value.errors()
    assert any(e["loc"] == ("source_ip",) for e in errors)


def test_event_optional_fields_at_max_are_valid():
    event = SecurityEvent(
        description="Test.",
        source_ip="1" * settings.MAX_FIELD_LENGTH,
        destination_ip="2" * settings.MAX_FIELD_LENGTH,
        event_type="3" * settings.MAX_FIELD_LENGTH,
        severity="4" * settings.MAX_FIELD_LENGTH,
        timestamp="5" * settings.MAX_FIELD_LENGTH,
    )
    assert event.source_ip is not None


def test_event_minimal_valid():
    event = SecurityEvent(description="x")
    assert event.description == "x"
    assert event.source_ip is None


# ─── ContextSummary ───────────────────────────────────────────────────────────

def test_context_summary_at_max_length_is_valid():
    s = "C" * settings.MAX_CONTEXT_LENGTH
    ctx = ContextSummary(summary=s)
    assert len(ctx.summary) == settings.MAX_CONTEXT_LENGTH


def test_context_summary_exceeds_max_length_raises():
    s = "C" * (settings.MAX_CONTEXT_LENGTH + 1)
    with pytest.raises(ValidationError) as exc_info:
        ContextSummary(summary=s)
    errors = exc_info.value.errors()
    assert any(e["loc"] == ("summary",) for e in errors)


def test_context_summary_empty_raises():
    with pytest.raises(ValidationError):
        ContextSummary(summary="")


def test_context_additional_context_exceeds_max_raises():
    ctx_text = "D" * (settings.MAX_CONTEXT_LENGTH + 1)
    with pytest.raises(ValidationError) as exc_info:
        ContextSummary(summary="Test.", additional_context=ctx_text)
    errors = exc_info.value.errors()
    assert any(e["loc"] == ("additional_context",) for e in errors)


def test_context_entity_exceeds_max_field_length_raises():
    entity = "E" * (settings.MAX_FIELD_LENGTH + 1)
    with pytest.raises(ValidationError) as exc_info:
        ContextSummary(summary="Test.", entity=entity)
    errors = exc_info.value.errors()
    assert any(e["loc"] == ("entity",) for e in errors)


def test_context_minimal_valid():
    ctx = ContextSummary(summary="Suspicious lateral movement detected.")
    assert ctx.entity is None
    assert ctx.time_window is None


# ─── RawPromptRequest ─────────────────────────────────────────────────────────

def test_raw_prompt_at_max_length_is_valid():
    p = "F" * settings.MAX_PROMPT_LENGTH
    req = RawPromptRequest(prompt=p)
    assert len(req.prompt) == settings.MAX_PROMPT_LENGTH


def test_raw_prompt_exceeds_max_length_raises():
    p = "F" * (settings.MAX_PROMPT_LENGTH + 1)
    with pytest.raises(ValidationError) as exc_info:
        RawPromptRequest(prompt=p)
    errors = exc_info.value.errors()
    assert any(e["loc"] == ("prompt",) for e in errors)


def test_raw_prompt_empty_raises():
    with pytest.raises(ValidationError):
        RawPromptRequest(prompt="")


def test_raw_prompt_minimal_valid():
    req = RawPromptRequest(prompt="Hello")
    assert req.prompt == "Hello"


# ─── HTTP-level size rejection ────────────────────────────────────────────────

def test_oversized_description_returns_422_via_http():
    """FastAPI should return 422 for oversized description without reaching Ollama."""
    from fastapi.testclient import TestClient
    from unittest.mock import patch
    from app.config import Settings

    test_settings = Settings(LOCAL_LLM_API_KEY=None, RATE_LIMIT_ENABLED=False)
    with patch("app.config.get_settings", return_value=test_settings), \
         patch("app.middleware.auth.get_settings", return_value=test_settings), \
         patch("app.middleware.rate_limiter.get_settings", return_value=test_settings), \
         patch("app.routes.analyze.settings", test_settings):
        import importlib, app.main
        importlib.reload(app.main)
        from app.main import app as _app
        client = TestClient(_app, raise_server_exceptions=False)
        oversized = "X" * (settings.MAX_DESCRIPTION_LENGTH + 1)
        resp = client.post("/analyze-event", json={"description": oversized})

    assert resp.status_code == 422


def test_oversized_context_summary_returns_422_via_http():
    from fastapi.testclient import TestClient
    from unittest.mock import patch
    from app.config import Settings

    test_settings = Settings(LOCAL_LLM_API_KEY=None, RATE_LIMIT_ENABLED=False)
    with patch("app.config.get_settings", return_value=test_settings), \
         patch("app.middleware.auth.get_settings", return_value=test_settings), \
         patch("app.middleware.rate_limiter.get_settings", return_value=test_settings), \
         patch("app.routes.analyze.settings", test_settings):
        import importlib, app.main
        importlib.reload(app.main)
        from app.main import app as _app
        client = TestClient(_app, raise_server_exceptions=False)
        oversized = "Y" * (settings.MAX_CONTEXT_LENGTH + 1)
        resp = client.post("/analyze-context", json={"summary": oversized})

    assert resp.status_code == 422
