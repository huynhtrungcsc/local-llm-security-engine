from pydantic import BaseModel, Field, model_validator
from typing import Literal, Optional
from app.config import get_settings

VALID_ATTACK_CLASSIFICATIONS = Literal[
    "reconnaissance",
    "credential_access",
    "initial_access",
    "lateral_movement",
    "command_and_control",
    "benign",
    "unknown",
]

_s = get_settings()


class SecurityEvent(BaseModel):
    source_ip: Optional[str] = Field(
        default=None, max_length=_s.MAX_FIELD_LENGTH
    )
    destination_ip: Optional[str] = Field(
        default=None, max_length=_s.MAX_FIELD_LENGTH
    )
    event_type: Optional[str] = Field(
        default=None, max_length=_s.MAX_FIELD_LENGTH
    )
    severity: Optional[str] = Field(
        default=None, max_length=_s.MAX_FIELD_LENGTH
    )
    description: str = Field(
        ...,
        min_length=1,
        max_length=_s.MAX_DESCRIPTION_LENGTH,
        description="Event description or raw log summary",
    )
    timestamp: Optional[str] = Field(
        default=None, max_length=_s.MAX_FIELD_LENGTH
    )
    additional_context: Optional[str] = Field(
        default=None, max_length=_s.MAX_CONTEXT_LENGTH
    )


class ContextSummary(BaseModel):
    entity: Optional[str] = Field(
        default=None, max_length=_s.MAX_FIELD_LENGTH
    )
    summary: str = Field(
        ...,
        min_length=1,
        max_length=_s.MAX_CONTEXT_LENGTH,
        description="Short SOC context summary for an entity or session",
    )
    time_window: Optional[str] = Field(
        default=None, max_length=_s.MAX_FIELD_LENGTH
    )
    additional_context: Optional[str] = Field(
        default=None, max_length=_s.MAX_CONTEXT_LENGTH
    )


class RawPromptRequest(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=_s.MAX_PROMPT_LENGTH,
        description="Raw prompt to send directly to Ollama",
    )


class AnalysisResult(BaseModel):
    """Core analysis fields — validated output from the LLM."""
    attack_classification: VALID_ATTACK_CLASSIFICATIONS
    false_positive_likelihood: float = Field(..., ge=0.0, le=1.0)
    risk_score: int = Field(..., ge=0, le=100)
    reason: str = Field(..., min_length=1)
    fallback_used: bool = False


class AnalysisResponse(AnalysisResult):
    """
    Normalized response for SOC integration.
    Extends AnalysisResult with provenance and parse metadata.
    Downstream consumers should use this schema for stable integration.
    """
    model_used: str = Field(..., description="Ollama model that produced this result")
    provider: str = Field(default="ollama", description="LLM provider (always 'ollama' for this service)")
    raw_parse_success: bool = Field(
        ...,
        description="Whether the raw model output was parsed as valid JSON (false means fallback was used)"
    )
    parse_strategy: Optional[str] = Field(
        default=None,
        description="JSON extraction strategy that succeeded, or null if parsing failed"
    )
    ollama_error: Optional[str] = Field(
        default=None,
        description="Ollama error message if the request failed, null on success"
    )
    request_id: Optional[str] = Field(
        default=None,
        description="Request trace ID echoed from X-Request-ID header (or server-generated)"
    )


class RawOllamaResponse(BaseModel):
    prompt: str
    raw_response: str
    model: str


class OllamaPingResponse(BaseModel):
    reachable: bool
    base_url: str
    configured_model: str
    model_available: bool
    available_models: list[str]
    error: Optional[str] = None
    latency_ms: Optional[float] = None


class ErrorResponse(BaseModel):
    """Standard error response shape returned by all error paths."""
    error: str
    detail: str
    request_id: Optional[str] = None
