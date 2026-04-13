"""
Exception hierarchy for the Local LLM Security Engine Python SDK.

All SDK exceptions inherit from EngineError so callers can catch them
with a single except clause while still being able to distinguish causes.

Example::

    from sdk.exceptions import EngineError, EngineConnectionError

    try:
        result = await client.analyze_event(...)
    except EngineConnectionError:
        logger.error("Engine is unreachable — check Ollama and the tunnel")
    except EngineRateLimitError as e:
        await asyncio.sleep(e.retry_after)
    except EngineError as e:
        logger.error("Engine call failed: %s", e)
"""

from typing import Optional


class EngineError(Exception):
    """Base class for all SDK errors."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class EngineConnectionError(EngineError):
    """
    Raised when the engine is unreachable (connection refused, DNS failure,
    tunnel down, or the request was aborted before a response arrived).
    """


class EngineTimeoutError(EngineError):
    """
    Raised when the engine does not respond within the configured timeout.
    This may indicate that Ollama is running a slow inference — consider
    increasing the client timeout or switching to a smaller model.
    """


class EngineAuthError(EngineError):
    """
    Raised on HTTP 401 (missing X-API-Key) or 403 (wrong X-API-Key).
    Check that LOCAL_LLM_ENGINE_API_KEY matches the engine's LOCAL_LLM_API_KEY.
    """


class EngineRateLimitError(EngineError):
    """
    Raised on HTTP 429 (rate limit exceeded).
    ``retry_after`` is the number of seconds to wait before retrying,
    as reported by the engine's Retry-After header.
    """

    def __init__(self, message: str, retry_after: int = 60) -> None:
        super().__init__(message, status_code=429)
        self.retry_after = retry_after


class EngineValidationError(EngineError):
    """
    Raised on HTTP 422 (request body failed validation).
    This usually means a required field is missing, a string exceeds the
    configured MAX_*_LENGTH, or the model named in OLLAMA_MODEL is not pulled.
    ``detail`` contains the engine's validation error detail string.
    """

    def __init__(self, message: str, detail: str = "") -> None:
        super().__init__(message, status_code=422)
        self.detail = detail


class EngineContractError(EngineError):
    """
    Raised when the engine returns HTTP 200 but the response body does not
    conform to the expected AnalysisResponse schema. This should not happen
    against a compatible engine version; it indicates a version mismatch or
    an unexpected engine-side bug.
    """
