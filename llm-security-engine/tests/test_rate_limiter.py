"""
Tests for the in-memory sliding window rate limiter.
"""
import asyncio
import time
import pytest
from unittest.mock import MagicMock, patch, AsyncMock

from app.middleware.rate_limiter import RateLimiter


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_request(ip: str = "127.0.0.1", client_id_header: str | None = None) -> MagicMock:
    req = MagicMock()
    req.client = MagicMock()
    req.client.host = ip
    headers = {}
    if client_id_header:
        headers["X-Client-ID"] = client_id_header
    req.headers.get = lambda key, default=None: headers.get(key, default)
    req.url = MagicMock()
    req.url.path = "/analyze-event"
    return req


# ─── Basic allow/deny logic ───────────────────────────────────────────────────

async def test_first_request_is_allowed():
    limiter = RateLimiter(max_requests=5, window_seconds=60)
    req = _make_request("10.0.0.1")
    allowed, retry_after = await limiter.is_allowed(req)
    assert allowed is True
    assert retry_after == 0


async def test_within_limit_all_allowed():
    limiter = RateLimiter(max_requests=5, window_seconds=60)
    req = _make_request("10.0.0.2")
    for _ in range(5):
        allowed, _ = await limiter.is_allowed(req)
        assert allowed is True


async def test_exceeding_limit_is_denied():
    limiter = RateLimiter(max_requests=3, window_seconds=60)
    req = _make_request("10.0.0.3")
    for _ in range(3):
        await limiter.is_allowed(req)
    allowed, retry_after = await limiter.is_allowed(req)
    assert allowed is False
    assert retry_after > 0


async def test_retry_after_is_positive():
    limiter = RateLimiter(max_requests=1, window_seconds=10)
    req = _make_request("10.0.0.4")
    await limiter.is_allowed(req)
    allowed, retry_after = await limiter.is_allowed(req)
    assert allowed is False
    assert 1 <= retry_after <= 11


# ─── Client isolation ─────────────────────────────────────────────────────────

async def test_different_ips_are_independent():
    limiter = RateLimiter(max_requests=1, window_seconds=60)
    req1 = _make_request("10.0.0.5")
    req2 = _make_request("10.0.0.6")
    await limiter.is_allowed(req1)
    # req1 is now at limit, req2 should still be allowed
    allowed1, _ = await limiter.is_allowed(req1)
    allowed2, _ = await limiter.is_allowed(req2)
    assert allowed1 is False
    assert allowed2 is True


async def test_x_client_id_header_used_as_identity():
    limiter = RateLimiter(max_requests=1, window_seconds=60)
    req_a = _make_request("10.0.0.7", client_id_header="client-alpha")
    req_b = _make_request("10.0.0.7", client_id_header="client-beta")
    await limiter.is_allowed(req_a)
    allowed_a, _ = await limiter.is_allowed(req_a)
    allowed_b, _ = await limiter.is_allowed(req_b)
    assert allowed_a is False
    assert allowed_b is True  # Different client-id, own separate window


# ─── Reset ───────────────────────────────────────────────────────────────────

async def test_reset_specific_client_restores_access():
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    req = _make_request("10.0.0.8")
    await limiter.is_allowed(req)
    await limiter.is_allowed(req)
    allowed, _ = await limiter.is_allowed(req)
    assert allowed is False

    limiter.reset("ip:10.0.0.8")
    allowed, _ = await limiter.is_allowed(req)
    assert allowed is True


async def test_reset_all_clears_all_clients():
    limiter = RateLimiter(max_requests=1, window_seconds=60)
    req1 = _make_request("10.0.0.9")
    req2 = _make_request("10.0.0.10")
    await limiter.is_allowed(req1)
    await limiter.is_allowed(req2)

    limiter.reset()

    allowed1, _ = await limiter.is_allowed(req1)
    allowed2, _ = await limiter.is_allowed(req2)
    assert allowed1 is True
    assert allowed2 is True


# ─── Sliding window behavior ──────────────────────────────────────────────────

async def test_old_requests_fall_out_of_window():
    """After the window expires, old requests no longer count."""
    limiter = RateLimiter(max_requests=2, window_seconds=1)
    req = _make_request("10.0.0.11")

    # Use up limit
    await limiter.is_allowed(req)
    await limiter.is_allowed(req)
    denied, _ = await limiter.is_allowed(req)
    assert denied is False

    # Wait for window to expire
    await asyncio.sleep(1.1)

    # Should be allowed again
    allowed, _ = await limiter.is_allowed(req)
    assert allowed is True


# ─── Concurrency safety ───────────────────────────────────────────────────────

async def test_concurrent_requests_respect_limit():
    """Fire many concurrent requests; exactly max_requests should be allowed."""
    limiter = RateLimiter(max_requests=5, window_seconds=60)

    async def check():
        req = _make_request("10.0.0.12")
        return await limiter.is_allowed(req)

    results = await asyncio.gather(*[check() for _ in range(10)])
    allowed_count = sum(1 for allowed, _ in results if allowed)
    # Due to async lock, exactly 5 should be allowed
    assert allowed_count == 5


# ─── Middleware HTTP response ─────────────────────────────────────────────────

async def test_rate_limit_middleware_returns_429():
    from app.config import Settings
    from fastapi.testclient import TestClient

    test_settings = Settings(
        RATE_LIMIT_ENABLED=True,
        RATE_LIMIT_REQUESTS=1,
        RATE_LIMIT_WINDOW_SECONDS=60,
        LOCAL_LLM_API_KEY=None,
    )
    import app.middleware.rate_limiter as rl_mod
    rl_mod._limiter_instance = RateLimiter(max_requests=1, window_seconds=60)

    with patch("app.config.get_settings", return_value=test_settings), \
         patch("app.middleware.auth.get_settings", return_value=test_settings), \
         patch("app.middleware.rate_limiter.get_settings", return_value=test_settings), \
         patch("app.routes.analyze.settings", test_settings), \
         patch("app.routes.health.settings", test_settings), \
         patch("app.services.ollama_client.check_ollama_connectivity",
               new_callable=AsyncMock,
               return_value={"reachable": False, "configured_model": "phi4-mini",
                             "model_available": False, "available_models": [], "error": "test"}):
        import importlib, app.main
        importlib.reload(app.main)
        from app.main import app as _app
        client = TestClient(_app, raise_server_exceptions=False)

        # First request should pass (hits Ollama which is mocked as down, that's fine)
        # Consume the one allowed slot by hitting a non-exempt path
        client.post("/analyze-event", json={"description": "test"})

        # Second request should be rate limited
        resp = client.post("/analyze-event", json={"description": "test"})

    # Clean up
    rl_mod._limiter_instance = None
    assert resp.status_code == 429
    body = resp.json()
    assert "rate_limit_exceeded" in body.get("error", "")
    assert "retry_after_seconds" in body


async def test_rate_limit_middleware_includes_retry_after_header():
    from app.config import Settings
    from fastapi.testclient import TestClient

    test_settings = Settings(
        RATE_LIMIT_ENABLED=True,
        RATE_LIMIT_REQUESTS=1,
        RATE_LIMIT_WINDOW_SECONDS=60,
        LOCAL_LLM_API_KEY=None,
    )
    import app.middleware.rate_limiter as rl_mod
    rl_mod._limiter_instance = RateLimiter(max_requests=1, window_seconds=60)

    with patch("app.config.get_settings", return_value=test_settings), \
         patch("app.middleware.auth.get_settings", return_value=test_settings), \
         patch("app.middleware.rate_limiter.get_settings", return_value=test_settings), \
         patch("app.routes.analyze.settings", test_settings), \
         patch("app.routes.health.settings", test_settings), \
         patch("app.services.ollama_client.check_ollama_connectivity",
               new_callable=AsyncMock,
               return_value={"reachable": False, "configured_model": "phi4-mini",
                             "model_available": False, "available_models": [], "error": "test"}):
        import importlib, app.main
        importlib.reload(app.main)
        from app.main import app as _app
        client = TestClient(_app, raise_server_exceptions=False)
        client.post("/analyze-event", json={"description": "test"})
        resp = client.post("/analyze-event", json={"description": "test"})

    rl_mod._limiter_instance = None
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers
