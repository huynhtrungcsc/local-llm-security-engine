"""
Optional API key authentication for the Local LLM Security Engine.

Behavior:
- If LOCAL_LLM_API_KEY is not set in config, auth is disabled (all requests pass).
- If LOCAL_LLM_API_KEY is set, every request to protected routes must include:
    X-API-Key: <value>
- Returns HTTP 401 if the header is missing.
- Returns HTTP 403 if the key is present but incorrect.

This dependency is applied per-route using FastAPI's Depends() mechanism.
Exempt routes (health, debug, docs) do not use this dependency.
"""

from fastapi import Header, HTTPException, Depends
from typing import Optional
from app.config import get_settings, Settings


async def verify_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    settings: Settings = Depends(get_settings),
) -> None:
    """
    FastAPI dependency. Raises HTTPException if auth is enabled and the key is wrong.
    Attach with: `dependencies=[Depends(verify_api_key)]` on a router or route.
    """
    configured_key = settings.LOCAL_LLM_API_KEY
    if not configured_key:
        # Auth disabled — pass all requests
        return

    if x_api_key is None:
        raise HTTPException(
            status_code=401,
            detail="Missing X-API-Key header. Authentication is required.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if x_api_key != configured_key:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key.",
        )
