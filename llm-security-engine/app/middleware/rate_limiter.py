"""
Simple in-memory sliding window rate limiter.

Design:
- Tracks request timestamps per client identity (IP address or X-Client-ID header).
- Uses a sliding window: only counts requests within the last WINDOW seconds.
- Thread-safe via asyncio.Lock.
- Configurable via RATE_LIMIT_REQUESTS and RATE_LIMIT_WINDOW_SECONDS env vars.
- If RATE_LIMIT_ENABLED=false, all requests pass regardless of limits.

Exempt paths (/health, /debug/ping-ollama, /docs, /redoc, /openapi.json) always bypass the limiter.

Returns HTTP 429 with Retry-After header when the limit is exceeded.
"""

import time
import asyncio
from collections import deque
from typing import Deque
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from app.config import get_settings

_EXEMPT_PATHS = {"/health", "/docs", "/redoc", "/openapi.json", "/debug/ping-ollama"}


class RateLimiter:
    """In-memory sliding window rate limiter."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._store: dict[str, Deque[float]] = {}
        self._lock = asyncio.Lock()

    def _client_id(self, request: Request) -> str:
        """Derive a client identity from the request."""
        client_id_header = request.headers.get("X-Client-ID")
        if client_id_header:
            return f"header:{client_id_header}"
        # Fall back to IP address (works behind Cloudflare Tunnel too)
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip:
            return f"ip:{cf_ip}"
        x_forwarded = request.headers.get("X-Forwarded-For")
        if x_forwarded:
            return f"ip:{x_forwarded.split(',')[0].strip()}"
        if request.client:
            return f"ip:{request.client.host}"
        return "ip:unknown"

    async def is_allowed(self, request: Request) -> tuple[bool, int]:
        """
        Check whether the request is within the rate limit.
        Returns (allowed, retry_after_seconds).
        retry_after_seconds is 0 when allowed.
        """
        client = self._client_id(request)
        now = time.monotonic()
        window_start = now - self.window_seconds

        async with self._lock:
            if client not in self._store:
                self._store[client] = deque()

            timestamps = self._store[client]

            # Evict timestamps outside the current window
            while timestamps and timestamps[0] < window_start:
                timestamps.popleft()

            if len(timestamps) >= self.max_requests:
                # Compute how long until the oldest request falls out of the window
                oldest = timestamps[0]
                retry_after = int(self.window_seconds - (now - oldest)) + 1
                return False, retry_after

            timestamps.append(now)
            return True, 0

    def reset(self, client_id: str | None = None) -> None:
        """Clear rate limit state. Pass client_id to clear a specific client, or None for all."""
        if client_id is None:
            self._store.clear()
        else:
            self._store.pop(client_id, None)


_limiter_instance: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    """Return the singleton RateLimiter (created on first call)."""
    global _limiter_instance
    if _limiter_instance is None:
        settings = get_settings()
        _limiter_instance = RateLimiter(
            max_requests=settings.RATE_LIMIT_REQUESTS,
            window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
        )
    return _limiter_instance


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that applies the rate limiter to all non-exempt paths."""

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()

        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)

        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        limiter = get_rate_limiter()
        allowed, retry_after = await limiter.is_allowed(request)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "detail": (
                        f"Rate limit exceeded: {settings.RATE_LIMIT_REQUESTS} requests "
                        f"per {settings.RATE_LIMIT_WINDOW_SECONDS} seconds."
                    ),
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)
