"""
Local LLM Security Engine — Python Client SDK
==============================================

Provides both async (AsyncEngineClient) and synchronous (EngineClient) wrappers
around the engine's REST API, with full type annotations and structured errors.

Quickstart::

    from sdk import AsyncEngineClient, SecurityEventRequest

    async with AsyncEngineClient(base_url="http://localhost:8000") as client:
        result = await client.analyze_event(
            SecurityEventRequest(description="57 failed SSH logins then 1 success.")
        )
        print(result.attack_classification, result.risk_score)

For environments that cannot use async::

    from sdk import EngineClient, SecurityEventRequest

    with EngineClient(base_url="http://localhost:8000") as client:
        result = client.analyze_event(
            SecurityEventRequest(description="DNS query to known C2 domain.")
        )
"""

from sdk.client import AsyncEngineClient, EngineClient
from sdk.models import (
    SecurityEventRequest,
    ContextSummaryRequest,
    AnalysisResponse,
    OllamaPingResponse,
    HealthResponse,
)
from sdk.exceptions import (
    EngineError,
    EngineConnectionError,
    EngineTimeoutError,
    EngineAuthError,
    EngineRateLimitError,
    EngineValidationError,
    EngineContractError,
)

__all__ = [
    "AsyncEngineClient",
    "EngineClient",
    "SecurityEventRequest",
    "ContextSummaryRequest",
    "AnalysisResponse",
    "OllamaPingResponse",
    "HealthResponse",
    "EngineError",
    "EngineConnectionError",
    "EngineTimeoutError",
    "EngineAuthError",
    "EngineRateLimitError",
    "EngineValidationError",
    "EngineContractError",
]

__version__ = "1.0.0"
