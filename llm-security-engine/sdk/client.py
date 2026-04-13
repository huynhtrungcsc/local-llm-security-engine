"""
Python client for the Local LLM Security Engine.

Provides two classes:

- ``AsyncEngineClient`` — async client built on ``httpx.AsyncClient``.
  Use this in async codebases (FastAPI, aiohttp, asyncio scripts).

- ``EngineClient`` — synchronous wrapper around the async client.
  Use this in synchronous scripts, Jupyter notebooks, or CLI tools.

Both classes support context-manager usage and share the same interface.

Example (async)::

    import asyncio
    from sdk import AsyncEngineClient, SecurityEventRequest

    async def main():
        async with AsyncEngineClient(
            base_url="http://localhost:8000",
            api_key="your-secret-key",
            timeout=90.0,
        ) as client:
            resp = await client.analyze_event(
                SecurityEventRequest(
                    description="Port 22 brute-force: 500 failed attempts in 60s.",
                    source_ip="185.220.101.1",
                    event_type="authentication_failure",
                    severity="high",
                )
            )
            if resp.is_threat:
                print(f"Threat: {resp.attack_classification} (risk {resp.risk_score})")

    asyncio.run(main())

Example (sync)::

    from sdk import EngineClient, SecurityEventRequest

    with EngineClient(base_url="http://localhost:8000") as client:
        ping = client.ping_ollama()
        if not ping.model_available:
            raise RuntimeError(f"Model not available: {ping.configured_model}")

        result = client.analyze_event(
            SecurityEventRequest(description="DNS beaconing every 60s to 185.1.2.3.")
        )
        print(result.risk_score, result.reason)
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Optional

import httpx

from sdk.exceptions import (
    EngineAuthError,
    EngineConnectionError,
    EngineContractError,
    EngineError,
    EngineRateLimitError,
    EngineTimeoutError,
    EngineValidationError,
)
from sdk.models import (
    AnalysisResponse,
    ContextSummaryRequest,
    HealthResponse,
    OllamaPingResponse,
    SecurityEventRequest,
)

_DEFAULT_TIMEOUT = 120.0  # seconds — longer than the engine's OLLAMA_TIMEOUT default


class AsyncEngineClient:
    """
    Async HTTP client for the Local LLM Security Engine.

    Parameters
    ----------
    base_url:
        Base URL of the running engine, e.g. ``http://localhost:8000`` or
        ``https://random-name.trycloudflare.com``.
    api_key:
        Value to send in the ``X-API-Key`` header. Leave ``None`` if the
        engine is running without ``LOCAL_LLM_API_KEY`` set.
    timeout:
        Request timeout in seconds. Should be at least as long as the
        engine's ``OLLAMA_TIMEOUT`` (default 60 s) plus network latency.
    request_id_prefix:
        Optional prefix prepended to auto-generated ``X-Request-ID`` values.
        Useful for correlating SDK calls with a parent request trace.
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: float = _DEFAULT_TIMEOUT,
        request_id_prefix: str = "sdk",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._prefix = request_id_prefix
        self._client: Optional[httpx.AsyncClient] = None

    # ── Context manager ───────────────────────────────────────────────────────

    async def __aenter__(self) -> "AsyncEngineClient":
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=self._timeout,
            headers=self._base_headers(),
        )
        return self

    async def __aexit__(self, *_) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _base_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        return headers

    def _make_request_id(self) -> str:
        return f"{self._prefix}-{uuid.uuid4().hex[:12]}"

    def _client_or_raise(self) -> httpx.AsyncClient:
        if self._client is None:
            raise EngineError(
                "Client is not open. Use 'async with AsyncEngineClient(...) as client'."
            )
        return self._client

    async def _post(self, path: str, payload: dict) -> dict:
        client = self._client_or_raise()
        request_id = self._make_request_id()
        try:
            response = await client.post(
                path,
                json=payload,
                headers={"X-Request-ID": request_id},
            )
        except httpx.ConnectError as exc:
            raise EngineConnectionError(
                f"Cannot connect to engine at {self._base_url}. "
                "Is it running? Is the Cloudflare Tunnel up?"
            ) from exc
        except httpx.TimeoutException as exc:
            raise EngineTimeoutError(
                f"Engine did not respond within {self._timeout}s. "
                "Consider increasing the client timeout or using a smaller model."
            ) from exc

        return self._handle_response(response)

    async def _get(self, path: str) -> dict:
        client = self._client_or_raise()
        try:
            response = await client.get(path)
        except httpx.ConnectError as exc:
            raise EngineConnectionError(
                f"Cannot connect to engine at {self._base_url}."
            ) from exc
        except httpx.TimeoutException as exc:
            raise EngineTimeoutError(
                f"Engine did not respond within {self._timeout}s."
            ) from exc

        return self._handle_response(response)

    @staticmethod
    def _handle_response(response: httpx.Response) -> dict:
        if response.status_code == 401:
            raise EngineAuthError(
                "Missing X-API-Key. Set api_key= when constructing the client.",
                status_code=401,
            )
        if response.status_code == 403:
            raise EngineAuthError(
                "Invalid X-API-Key. Check that LOCAL_LLM_ENGINE_API_KEY matches "
                "the engine's LOCAL_LLM_API_KEY.",
                status_code=403,
            )
        if response.status_code == 422:
            detail = ""
            try:
                detail = response.json().get("detail", "")
            except Exception:
                pass
            raise EngineValidationError(
                f"Request validation failed: {detail}", detail=str(detail)
            )
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", "60"))
            raise EngineRateLimitError(
                f"Rate limit exceeded. Retry after {retry_after}s.",
                retry_after=retry_after,
            )
        if response.status_code >= 500:
            raise EngineError(
                f"Engine returned server error {response.status_code}: "
                f"{response.text[:200]}",
                status_code=response.status_code,
            )
        response.raise_for_status()
        try:
            return response.json()
        except Exception as exc:
            raise EngineContractError(
                f"Engine returned non-JSON body: {response.text[:200]}"
            ) from exc

    # ── Public API ────────────────────────────────────────────────────────────

    async def analyze_event(self, event: SecurityEventRequest) -> AnalysisResponse:
        """
        Classify a normalized security event via POST /analyze-event.

        Returns an AnalysisResponse. Always check ``result.fallback_used``
        before taking automated action on the classification.
        """
        data = await self._post("/analyze-event", event.to_dict())
        try:
            return AnalysisResponse.from_dict(data)
        except (KeyError, TypeError, ValueError) as exc:
            raise EngineContractError(
                f"Engine response missing required fields: {exc}"
            ) from exc

    async def analyze_context(self, context: ContextSummaryRequest) -> AnalysisResponse:
        """
        Classify a SOC context summary via POST /analyze-context.

        Use this when you have aggregated entity-level context (e.g. all alerts
        for a given source IP over the past hour) rather than a single event.
        """
        data = await self._post("/analyze-context", context.to_dict())
        try:
            return AnalysisResponse.from_dict(data)
        except (KeyError, TypeError, ValueError) as exc:
            raise EngineContractError(
                f"Engine response missing required fields: {exc}"
            ) from exc

    async def ping_ollama(self) -> OllamaPingResponse:
        """
        Check Ollama connectivity and model availability via GET /debug/ping-ollama.
        Useful for health-checking the engine before sending a batch of events.
        """
        data = await self._get("/debug/ping-ollama")
        return OllamaPingResponse.from_dict(data)

    async def health(self) -> HealthResponse:
        """Check engine health via GET /health."""
        data = await self._get("/health")
        return HealthResponse.from_dict(data)


class EngineClient:
    """
    Synchronous wrapper around AsyncEngineClient.

    Runs an internal event loop. Not suitable for use inside an already-running
    async loop — use AsyncEngineClient directly in that case.

    Usage::

        with EngineClient(base_url="http://localhost:8000") as client:
            result = client.analyze_event(SecurityEventRequest(
                description="Lateral movement detected on internal subnet."
            ))
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: float = _DEFAULT_TIMEOUT,
        request_id_prefix: str = "sdk-sync",
    ) -> None:
        self._async = AsyncEngineClient(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            request_id_prefix=request_id_prefix,
        )
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def __enter__(self) -> "EngineClient":
        self._loop = asyncio.new_event_loop()
        self._loop.run_until_complete(self._async.__aenter__())
        return self

    def __exit__(self, *args) -> None:
        if self._loop:
            self._loop.run_until_complete(self._async.__aexit__(*args))
            self._loop.close()
            self._loop = None

    def _run(self, coro):
        if not self._loop:
            raise EngineError("Client is not open. Use 'with EngineClient(...) as client'.")
        return self._loop.run_until_complete(coro)

    def analyze_event(self, event: SecurityEventRequest) -> AnalysisResponse:
        """Synchronous version of AsyncEngineClient.analyze_event."""
        return self._run(self._async.analyze_event(event))

    def analyze_context(self, context: ContextSummaryRequest) -> AnalysisResponse:
        """Synchronous version of AsyncEngineClient.analyze_context."""
        return self._run(self._async.analyze_context(context))

    def ping_ollama(self) -> OllamaPingResponse:
        """Synchronous version of AsyncEngineClient.ping_ollama."""
        return self._run(self._async.ping_ollama())

    def health(self) -> HealthResponse:
        """Synchronous version of AsyncEngineClient.health."""
        return self._run(self._async.health())
