"""
Tests for API key authentication.

Covers:
- Auth disabled (no key configured): all requests pass
- Auth enabled: missing key → 401
- Auth enabled: wrong key → 403
- Auth enabled: correct key → request proceeds (Ollama call may fail; that's OK)
- Health/debug endpoints are never protected
"""
import os
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from app.config import get_settings, Settings

# Force all app modules to be imported cleanly BEFORE any test patches run.
# If these imports happen inside a test while `app.config.get_settings` is
# patched, `verify_api_key`'s Depends() captures the MagicMock instead of the
# real function — causing FastAPI to emit 422 for unknown query parameters.
import app.main                      # noqa: E402
import app.middleware.auth           # noqa: E402
import app.routes.analyze            # noqa: E402


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_settings_cache():
    """Always clear the lru_cache before and after each test."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _set_auth_env(key: str) -> None:
    os.environ["LOCAL_LLM_API_KEY"] = key
    os.environ["RATE_LIMIT_ENABLED"] = "false"
    get_settings.cache_clear()


def _clear_auth_env() -> None:
    os.environ.pop("LOCAL_LLM_API_KEY", None)
    os.environ.pop("RATE_LIMIT_ENABLED", None)
    get_settings.cache_clear()


# ─── Auth disabled ────────────────────────────────────────────────────────────

def test_auth_disabled_no_key_required():
    """When LOCAL_LLM_API_KEY is not set, requests without X-API-Key pass auth."""
    os.environ.pop("LOCAL_LLM_API_KEY", None)
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.LOCAL_LLM_API_KEY is None


def test_auth_disabled_health_always_accessible():
    """Health endpoint is always accessible regardless of auth config."""
    import app.middleware.rate_limiter as rl
    rl._limiter_instance = None
    get_settings.cache_clear()

    with patch(
        "app.services.ollama_client.check_ollama_connectivity",
        new_callable=AsyncMock,
        return_value={
            "reachable": False,
            "configured_model": "phi4-mini",
            "model_available": False,
            "available_models": [],
            "error": "mocked",
        },
    ):
        from app.main import app as _app
        client = TestClient(_app, raise_server_exceptions=False)
        resp = client.get("/health")
    assert resp.status_code == 200


# ─── Auth enabled — missing key ───────────────────────────────────────────────

def test_auth_enabled_missing_key_returns_401():
    """Auth is enabled (env var set); request with no X-API-Key header → 401."""
    _set_auth_env("secret-key-abc")
    try:
        from app.main import app as _app
        client = TestClient(_app, raise_server_exceptions=False)
        resp = client.post("/analyze-event", json={"description": "Port scan detected."})
    finally:
        _clear_auth_env()
    assert resp.status_code == 401


def test_auth_enabled_missing_key_response_body():
    """401 body contains a human-readable message mentioning X-API-Key or auth."""
    _set_auth_env("secret-key-abc")
    try:
        from app.main import app as _app
        client = TestClient(_app, raise_server_exceptions=False)
        resp = client.post("/analyze-event", json={"description": "Test."})
    finally:
        _clear_auth_env()
    body = resp.json()
    assert "detail" in body
    assert "X-API-Key" in body["detail"] or "Authentication" in body["detail"]


# ─── Auth enabled — wrong key ─────────────────────────────────────────────────

def test_auth_enabled_wrong_key_returns_403():
    """Auth is enabled; wrong X-API-Key value → 403."""
    _set_auth_env("correct-key")
    try:
        from app.main import app as _app
        client = TestClient(_app, raise_server_exceptions=False)
        resp = client.post(
            "/analyze-event",
            json={"description": "Port scan."},
            headers={"X-API-Key": "wrong-key"},
        )
    finally:
        _clear_auth_env()
    assert resp.status_code == 403


# ─── Auth dependency unit tests ───────────────────────────────────────────────
# These call verify_api_key directly (no HTTP layer) to test the function logic.

def test_verify_api_key_passes_when_auth_disabled():
    import asyncio
    from app.middleware.auth import verify_api_key

    async def _run():
        await verify_api_key(x_api_key=None, settings=Settings(LOCAL_LLM_API_KEY=None))

    asyncio.run(_run())  # Should not raise


def test_verify_api_key_raises_401_when_key_missing():
    import asyncio
    from fastapi import HTTPException
    from app.middleware.auth import verify_api_key

    async def _run():
        await verify_api_key(x_api_key=None, settings=Settings(LOCAL_LLM_API_KEY="required-key"))

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(_run())
    assert exc_info.value.status_code == 401


def test_verify_api_key_raises_403_when_key_wrong():
    import asyncio
    from fastapi import HTTPException
    from app.middleware.auth import verify_api_key

    async def _run():
        await verify_api_key(x_api_key="wrong", settings=Settings(LOCAL_LLM_API_KEY="required-key"))

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(_run())
    assert exc_info.value.status_code == 403


def test_verify_api_key_passes_with_correct_key():
    import asyncio
    from app.middleware.auth import verify_api_key

    async def _run():
        await verify_api_key(x_api_key="required-key", settings=Settings(LOCAL_LLM_API_KEY="required-key"))

    asyncio.run(_run())  # Should not raise


def test_empty_api_key_env_var_disables_auth():
    """Setting LOCAL_LLM_API_KEY to empty string should disable auth (treated as None)."""
    test_settings = Settings(LOCAL_LLM_API_KEY="")
    assert test_settings.LOCAL_LLM_API_KEY is None
