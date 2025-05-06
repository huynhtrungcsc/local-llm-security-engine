"""
Tests for Ollama client reliability, retry logic, and error handling.
Uses unittest.mock to simulate Ollama responses without a real Ollama instance.
"""
import json
import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock

from app.services.ollama_client import (
    query_ollama,
    check_ollama_connectivity,
    OllamaConnectionError,
    OllamaTimeoutError,
    OllamaModelError,
    OllamaResponseError,
    OllamaError,
)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_response(status_code: int, body: dict) -> MagicMock:
    """Build a minimal mock httpx.Response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = body
    if status_code >= 400:
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            message=f"HTTP {status_code}",
            request=MagicMock(),
            response=mock_resp,
        )
    else:
        mock_resp.raise_for_status.return_value = None
    return mock_resp


def _patch_async_client(post_result=None, get_result=None, post_side_effect=None, get_side_effect=None):
    """
    Context manager factory: patches httpx.AsyncClient so that the async
    context manager returns a client whose post/get are AsyncMocks.
    """
    mock_client = MagicMock()

    if post_side_effect is not None:
        mock_client.post = AsyncMock(side_effect=post_side_effect)
    elif post_result is not None:
        mock_client.post = AsyncMock(return_value=post_result)

    if get_side_effect is not None:
        mock_client.get = AsyncMock(side_effect=get_side_effect)
    elif get_result is not None:
        mock_client.get = AsyncMock(return_value=get_result)

    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    mock_cls = MagicMock(return_value=mock_client)
    return patch("app.services.ollama_client.httpx.AsyncClient", mock_cls)


# ─── Successful response ──────────────────────────────────────────────────────

async def test_query_ollama_success():
    expected = {
        "model": "phi4-mini",
        "response": '{"attack_classification": "benign", "false_positive_likelihood": 0.9, "risk_score": 5, "reason": "Normal."}',
    }
    with _patch_async_client(post_result=_make_response(200, expected)):
        result = await query_ollama("Test prompt")
    assert result["model"] == "phi4-mini"
    assert "response" in result


# ─── 404 — model not found ────────────────────────────────────────────────────

async def test_query_ollama_model_not_found_raises_model_error():
    with _patch_async_client(post_result=_make_response(404, {"error": "model not found"})):
        with pytest.raises(OllamaModelError):
            await query_ollama("Test prompt")


# ─── Ollama model-level error field in 200 response ───────────────────────────

async def test_query_ollama_error_field_in_200_response_raises_model_error():
    body = {"error": "model 'bad-model' not found, try pulling it first"}
    resp = _make_response(200, body)
    with _patch_async_client(post_result=resp):
        with pytest.raises(OllamaModelError):
            await query_ollama("Test prompt")


# ─── Connection refused ───────────────────────────────────────────────────────

async def test_query_ollama_connection_refused_raises_connection_error():
    with _patch_async_client(post_side_effect=httpx.ConnectError("Connection refused")):
        with pytest.raises(OllamaConnectionError):
            await query_ollama("Test prompt")


# ─── Connect timeout is also a connection error ───────────────────────────────

async def test_query_ollama_connect_timeout_raises_connection_error():
    with _patch_async_client(post_side_effect=httpx.ConnectTimeout("Connect timed out")):
        with pytest.raises(OllamaConnectionError):
            await query_ollama("Test prompt")


# ─── Read timeout retries then raises ────────────────────────────────────────

async def test_query_ollama_read_timeout_raises_timeout_error():
    with _patch_async_client(post_side_effect=httpx.ReadTimeout("Read timed out")):
        with patch("app.services.ollama_client.asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(OllamaTimeoutError):
                await query_ollama("Test prompt")


# ─── 500 server error retries then raises ─────────────────────────────────────

async def test_query_ollama_server_error_raises_response_error():
    with _patch_async_client(post_result=_make_response(500, {"error": "internal error"})):
        with patch("app.services.ollama_client.asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises((OllamaResponseError, OllamaError)):
                await query_ollama("Test prompt")


# ─── check_ollama_connectivity ────────────────────────────────────────────────

async def test_connectivity_check_success():
    body = {"models": [{"name": "phi4-mini:latest"}, {"name": "llama3:latest"}]}
    with _patch_async_client(get_result=_make_response(200, body)):
        status = await check_ollama_connectivity()
    assert status["reachable"] is True
    assert "phi4-mini:latest" in status["available_models"]
    assert status["error"] is None


async def test_connectivity_check_unreachable():
    with _patch_async_client(get_side_effect=httpx.ConnectError("Connection refused")):
        status = await check_ollama_connectivity()
    assert status["reachable"] is False
    assert status["error"] is not None
    assert status["available_models"] == []


async def test_connectivity_check_timeout():
    with _patch_async_client(get_side_effect=httpx.TimeoutException("Timeout")):
        status = await check_ollama_connectivity()
    assert status["reachable"] is False
    assert "timeout" in status["error"].lower() or "timed" in status["error"].lower()


async def test_connectivity_check_model_available_flag():
    body = {"models": [{"name": "phi4-mini:latest"}]}
    with _patch_async_client(get_result=_make_response(200, body)):
        status = await check_ollama_connectivity()
    assert "model_available" in status
    # phi4-mini matches phi4-mini:latest via startswith check
    assert status["model_available"] is True


async def test_connectivity_check_model_not_in_list():
    body = {"models": [{"name": "llama3:latest"}]}
    with _patch_async_client(get_result=_make_response(200, body)):
        status = await check_ollama_connectivity()
    assert status["reachable"] is True
    assert status["model_available"] is False


async def test_connectivity_check_empty_model_list():
    body = {"models": []}
    with _patch_async_client(get_result=_make_response(200, body)):
        status = await check_ollama_connectivity()
    assert status["reachable"] is True
    assert status["available_models"] == []
    assert status["model_available"] is False


# ─── Schema stability of connectivity result ──────────────────────────────────

async def test_connectivity_result_has_all_fields():
    body = {"models": []}
    with _patch_async_client(get_result=_make_response(200, body)):
        status = await check_ollama_connectivity()
    for key in ["reachable", "configured_model", "model_available", "available_models", "error"]:
        assert key in status, f"Missing key '{key}' in connectivity result"
