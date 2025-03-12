from fastapi import APIRouter, HTTPException, Depends, Request
from app.models.schemas import (
    SecurityEvent,
    ContextSummary,
    RawPromptRequest,
    AnalysisResponse,
    RawOllamaResponse,
)
from app.services.prompt_builder import build_event_prompt, build_context_prompt
from app.services.ollama_client import (
    query_ollama,
    OllamaConnectionError,
    OllamaTimeoutError,
    OllamaModelError,
    OllamaResponseError,
    OllamaError,
)
from app.services.parser import extract_json_from_response
from app.services.validator import validate_analysis_result, FALLBACK_RESULT
from app.middleware.auth import verify_api_key
from app.lib.logger import get_logger
from app.config import get_settings

log = get_logger(__name__)
router = APIRouter(dependencies=[Depends(verify_api_key)])
settings = get_settings()


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "unknown")


async def _run_analysis(prompt: str, request_id: str) -> AnalysisResponse:
    """
    Core analysis pipeline:
    1. Call Ollama (with retry)
    2. Parse the raw response into a dict
    3. Validate all fields
    4. Return a fully populated AnalysisResponse

    Never raises — on any Ollama failure, returns a safe fallback with the
    error captured in ollama_error.
    """
    log.info(
        "ollama_call_start",
        request_id=request_id,
        model=settings.OLLAMA_MODEL,
        prompt_length=len(prompt),
    )

    try:
        ollama_response = await query_ollama(prompt)
        raw_text = ollama_response.get("response", "")
        model_used = ollama_response.get("model", settings.OLLAMA_MODEL)

        log.info(
            "ollama_call_complete",
            request_id=request_id,
            model=model_used,
            response_length=len(raw_text),
        )

        parse_result = extract_json_from_response(raw_text)
        log.info(
            "parse_complete",
            request_id=request_id,
            parse_success=parse_result.success,
            parse_strategy=parse_result.strategy,
        )

    except OllamaConnectionError as e:
        log.error("ollama_error", request_id=request_id, error_type="OllamaConnectionError", detail=str(e))
        return AnalysisResponse(
            **FALLBACK_RESULT.model_dump(),
            model_used=settings.OLLAMA_MODEL,
            provider="ollama",
            raw_parse_success=False,
            parse_strategy=None,
            ollama_error=str(e),
            request_id=request_id,
        )

    except OllamaTimeoutError as e:
        log.error("ollama_error", request_id=request_id, error_type="OllamaTimeoutError", detail=str(e))
        return AnalysisResponse(
            **FALLBACK_RESULT.model_dump(),
            model_used=settings.OLLAMA_MODEL,
            provider="ollama",
            raw_parse_success=False,
            parse_strategy=None,
            ollama_error=str(e),
            request_id=request_id,
        )

    except OllamaModelError as e:
        log.error("ollama_error", request_id=request_id, error_type="OllamaModelError", detail=str(e))
        raise HTTPException(status_code=422, detail=str(e))

    except (OllamaResponseError, OllamaError) as e:
        log.error("ollama_error", request_id=request_id, error_type=type(e).__name__, detail=str(e))
        return AnalysisResponse(
            **FALLBACK_RESULT.model_dump(),
            model_used=settings.OLLAMA_MODEL,
            provider="ollama",
            raw_parse_success=False,
            parse_strategy=None,
            ollama_error=str(e),
            request_id=request_id,
        )

    validated = validate_analysis_result(parse_result.data if parse_result else None)

    if validated.fallback_used:
        log.warning(
            "fallback_used",
            request_id=request_id,
            reason=validated.reason,
            parse_strategy=parse_result.strategy if parse_result else None,
        )

    return AnalysisResponse(
        **validated.model_dump(),
        model_used=model_used,
        provider="ollama",
        raw_parse_success=parse_result.success if parse_result else False,
        parse_strategy=parse_result.strategy if parse_result else None,
        ollama_error=None,
        request_id=request_id,
    )


@router.post("/analyze-event", response_model=AnalysisResponse)
async def analyze_event(event: SecurityEvent, request: Request):
    """
    Analyze a normalized security event using the local LLM.

    Returns a structured classification with attack type, risk score,
    false-positive likelihood, and provenance metadata for SOC integration.
    """
    rid = _request_id(request)
    log.info("analyze_event_request", request_id=rid, description_length=len(event.description))
    prompt = build_event_prompt(event)
    return await _run_analysis(prompt, rid)


@router.post("/analyze-context", response_model=AnalysisResponse)
async def analyze_context(context: ContextSummary, request: Request):
    """
    Analyze a SOC context summary for an entity or session.

    Returns a structured classification with attack type, risk score,
    false-positive likelihood, and provenance metadata for SOC integration.
    """
    rid = _request_id(request)
    log.info("analyze_context_request", request_id=rid, summary_length=len(context.summary))
    prompt = build_context_prompt(context)
    return await _run_analysis(prompt, rid)


@router.post("/raw-ollama-test", response_model=RawOllamaResponse)
async def raw_ollama_test(request_body: RawPromptRequest, request: Request):
    """
    Debug endpoint: send a raw prompt directly to Ollama and return the full response.
    Use this to inspect raw model output and test Ollama connectivity.
    """
    rid = _request_id(request)
    log.info("raw_ollama_test_request", request_id=rid, prompt_length=len(request_body.prompt))
    try:
        ollama_response = await query_ollama(request_body.prompt)
        return RawOllamaResponse(
            prompt=request_body.prompt,
            raw_response=ollama_response.get("response", ""),
            model=ollama_response.get("model", settings.OLLAMA_MODEL),
        )
    except OllamaConnectionError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except OllamaTimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except OllamaModelError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except OllamaError as e:
        raise HTTPException(status_code=502, detail=str(e))
