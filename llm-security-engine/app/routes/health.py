import time
import httpx
from fastapi import APIRouter
from app.config import get_settings
from app.services.ollama_client import check_ollama_connectivity
from app.models.schemas import OllamaPingResponse

router = APIRouter()
settings = get_settings()


@router.get("/health")
async def health_check():
    """
    Service health check. Reports service status and Ollama connectivity.
    Always returns 200 — Ollama unreachability is reported inside the response body.
    """
    ollama_status = await check_ollama_connectivity()

    overall = "ok" if ollama_status["reachable"] else "degraded"

    return {
        "status": overall,
        "service": "Local LLM Security Engine",
        "version": "1.0.0",
        "config": {
            "ollama_base_url": settings.OLLAMA_BASE_URL,
            "ollama_model": settings.OLLAMA_MODEL,
            "ollama_timeout_seconds": settings.OLLAMA_TIMEOUT,
            "debug": settings.DEBUG,
        },
        "ollama": ollama_status,
    }


@router.get("/debug/ping-ollama", response_model=OllamaPingResponse)
async def ping_ollama():
    """
    Development-only endpoint: lightweight Ollama connectivity probe.
    Returns reachability, configured model availability, and round-trip latency.
    """
    start = time.monotonic()
    status = await check_ollama_connectivity()
    latency_ms = round((time.monotonic() - start) * 1000, 2)

    return OllamaPingResponse(
        reachable=status["reachable"],
        base_url=settings.OLLAMA_BASE_URL,
        configured_model=settings.OLLAMA_MODEL,
        model_available=status.get("model_available", False),
        available_models=status.get("available_models", []),
        error=status.get("error"),
        latency_ms=latency_ms,
    )
