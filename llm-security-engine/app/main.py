from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from app.config import get_settings
from app.routes.health import router as health_router
from app.routes.analyze import router as analyze_router
from app.middleware.rate_limiter import RateLimitMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.lib.logger import get_logger

settings = get_settings()
log = get_logger(__name__)

app = FastAPI(
    title="Local LLM Security Engine",
    description=(
        "A local AI inference service for cybersecurity reasoning. "
        "Accepts normalized security events and context summaries, "
        "runs them through a local Ollama model, and returns structured JSON analysis."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Middleware (applied in reverse order — last added = outermost) ───────────
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestIDMiddleware)


# ── Request logging middleware ───────────────────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    rid = getattr(request.state, "request_id", "unknown")
    log.info(
        "request_received",
        request_id=rid,
        method=request.method,
        path=request.url.path,
        client=str(request.client.host) if request.client else "unknown",
    )
    response = await call_next(request)
    log.info(
        "request_complete",
        request_id=rid,
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
    )
    return response


# ── Routes ───────────────────────────────────────────────────────────────────
app.include_router(health_router)
app.include_router(analyze_router)
