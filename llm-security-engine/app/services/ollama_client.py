import asyncio
import httpx
from app.config import get_settings

settings = get_settings()

_RETRY_ATTEMPTS = 3
_RETRY_BACKOFF_BASE = 1.0  # seconds


class OllamaError(Exception):
    """Base class for Ollama client errors."""


class OllamaConnectionError(OllamaError):
    """Raised when Ollama is unreachable."""


class OllamaTimeoutError(OllamaError):
    """Raised when Ollama does not respond within the timeout."""


class OllamaModelError(OllamaError):
    """Raised when Ollama responds with a model-level error (e.g. model not loaded)."""


class OllamaResponseError(OllamaError):
    """Raised when Ollama returns an unexpected HTTP status."""


async def query_ollama(prompt: str) -> dict:
    """
    Send a prompt to the local Ollama API and return the full response dict.

    Retries up to _RETRY_ATTEMPTS times on transient failures (timeouts, 5xx).
    Raises OllamaError subclasses on terminal failure.
    """
    url = f"{settings.OLLAMA_BASE_URL}/api/generate"
    payload = {
        "model": settings.OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
    }

    last_error: Exception | None = None

    for attempt in range(1, _RETRY_ATTEMPTS + 1):
        try:
            async with httpx.AsyncClient(timeout=settings.OLLAMA_TIMEOUT) as client:
                response = await client.post(url, json=payload)

                if response.status_code == 404:
                    raise OllamaModelError(
                        f"Model '{settings.OLLAMA_MODEL}' not found on Ollama. "
                        f"Run: ollama pull {settings.OLLAMA_MODEL}"
                    )

                if response.status_code >= 500:
                    raise OllamaResponseError(
                        f"Ollama returned server error {response.status_code} on attempt {attempt}."
                    )

                response.raise_for_status()
                data = response.json()

                if "error" in data:
                    raise OllamaModelError(f"Ollama model error: {data['error']}")

                return data

        except (httpx.ConnectError, httpx.ConnectTimeout) as e:
            last_error = OllamaConnectionError(
                f"Cannot connect to Ollama at {settings.OLLAMA_BASE_URL}. Is it running?"
            )
            break  # Connection refused is terminal — do not retry

        except httpx.ReadTimeout as e:
            last_error = OllamaTimeoutError(
                f"Ollama timed out after {settings.OLLAMA_TIMEOUT}s on attempt {attempt}."
            )
            if attempt < _RETRY_ATTEMPTS:
                await asyncio.sleep(_RETRY_BACKOFF_BASE * attempt)
            continue

        except OllamaModelError:
            raise  # Terminal — model issues won't resolve on retry

        except OllamaResponseError as e:
            last_error = e
            if attempt < _RETRY_ATTEMPTS:
                await asyncio.sleep(_RETRY_BACKOFF_BASE * attempt)
            continue

        except httpx.HTTPStatusError as e:
            last_error = OllamaResponseError(
                f"Ollama HTTP error {e.response.status_code} on attempt {attempt}."
            )
            if attempt < _RETRY_ATTEMPTS:
                await asyncio.sleep(_RETRY_BACKOFF_BASE * attempt)
            continue

    raise last_error or OllamaError("Ollama query failed after all retry attempts.")


async def check_ollama_connectivity() -> dict:
    """
    Check if the Ollama service is reachable.
    Returns a structured dict with connectivity info, model list, and target model status.
    """
    try:
        url = f"{settings.OLLAMA_BASE_URL}/api/tags"
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            models = [m.get("name", "") for m in data.get("models", [])]
            configured_model = settings.OLLAMA_MODEL
            model_available = any(
                m == configured_model or m.startswith(f"{configured_model}:")
                for m in models
            )
            return {
                "reachable": True,
                "configured_model": configured_model,
                "model_available": model_available,
                "available_models": models,
                "error": None,
            }
    except httpx.ConnectError:
        return {
            "reachable": False,
            "configured_model": settings.OLLAMA_MODEL,
            "model_available": False,
            "available_models": [],
            "error": f"Connection refused at {settings.OLLAMA_BASE_URL}",
        }
    except httpx.TimeoutException:
        return {
            "reachable": False,
            "configured_model": settings.OLLAMA_MODEL,
            "model_available": False,
            "available_models": [],
            "error": "Connectivity check timed out after 5 seconds",
        }
    except Exception as e:
        return {
            "reachable": False,
            "configured_model": settings.OLLAMA_MODEL,
            "model_available": False,
            "available_models": [],
            "error": str(e),
        }
