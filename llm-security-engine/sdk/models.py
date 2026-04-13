"""
Request and response models for the Local LLM Security Engine Python SDK.

These mirror the engine's Pydantic schemas exactly. Keeping them here means
SDK consumers do not need to import from the engine's internal app package.
"""

from __future__ import annotations

from typing import Literal, Optional
from dataclasses import dataclass, field


# ── Valid classification labels ───────────────────────────────────────────────

AttackClassification = Literal[
    "reconnaissance",
    "credential_access",
    "initial_access",
    "lateral_movement",
    "command_and_control",
    "benign",
    "unknown",
]

VALID_CLASSIFICATIONS: frozenset[str] = frozenset({
    "reconnaissance",
    "credential_access",
    "initial_access",
    "lateral_movement",
    "command_and_control",
    "benign",
    "unknown",
})


# ── Request models ────────────────────────────────────────────────────────────

@dataclass
class SecurityEventRequest:
    """
    Maps to the engine's SecurityEvent schema (POST /analyze-event).

    Only ``description`` is required. All other fields are optional but
    improve classification accuracy when provided.
    """

    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    timestamp: Optional[str] = None
    additional_context: Optional[str] = None

    def to_dict(self) -> dict:
        d: dict = {"description": self.description}
        if self.source_ip is not None:
            d["source_ip"] = self.source_ip
        if self.destination_ip is not None:
            d["destination_ip"] = self.destination_ip
        if self.event_type is not None:
            d["event_type"] = self.event_type
        if self.severity is not None:
            d["severity"] = self.severity
        if self.timestamp is not None:
            d["timestamp"] = self.timestamp
        if self.additional_context is not None:
            d["additional_context"] = self.additional_context
        return d


@dataclass
class ContextSummaryRequest:
    """
    Maps to the engine's ContextSummary schema (POST /analyze-context).

    ``summary`` is a short free-text description of an entity or session,
    e.g. aggregated SOC alert context for a specific IP or user account.
    """

    summary: str
    entity: Optional[str] = None
    time_window: Optional[str] = None
    additional_context: Optional[str] = None

    def to_dict(self) -> dict:
        d: dict = {"summary": self.summary}
        if self.entity is not None:
            d["entity"] = self.entity
        if self.time_window is not None:
            d["time_window"] = self.time_window
        if self.additional_context is not None:
            d["additional_context"] = self.additional_context
        return d


# ── Response models ───────────────────────────────────────────────────────────

@dataclass
class AnalysisResponse:
    """
    Stable response schema returned by /analyze-event and /analyze-context.

    Always check ``fallback_used`` before acting on ``attack_classification``.
    A fallback result (fallback_used=True) should be routed for human review.
    """

    attack_classification: str
    false_positive_likelihood: float
    risk_score: int
    reason: str
    fallback_used: bool
    model_used: str
    provider: str
    raw_parse_success: bool
    parse_strategy: Optional[str]
    ollama_error: Optional[str]
    request_id: Optional[str]

    @classmethod
    def from_dict(cls, data: dict) -> "AnalysisResponse":
        return cls(
            attack_classification=data["attack_classification"],
            false_positive_likelihood=float(data["false_positive_likelihood"]),
            risk_score=int(data["risk_score"]),
            reason=data["reason"],
            fallback_used=bool(data["fallback_used"]),
            model_used=data["model_used"],
            provider=data["provider"],
            raw_parse_success=bool(data["raw_parse_success"]),
            parse_strategy=data.get("parse_strategy"),
            ollama_error=data.get("ollama_error"),
            request_id=data.get("request_id"),
        )

    @property
    def is_reliable(self) -> bool:
        """True when the result came from the model, not a fallback."""
        return not self.fallback_used

    @property
    def is_threat(self) -> bool:
        """True when classified as a non-benign, non-unknown, reliable result."""
        return (
            self.is_reliable
            and self.attack_classification not in ("benign", "unknown")
        )


@dataclass
class OllamaPingResponse:
    """Response from GET /debug/ping-ollama."""

    reachable: bool
    base_url: str
    configured_model: str
    model_available: bool
    available_models: list[str]
    error: Optional[str] = None
    latency_ms: Optional[float] = None

    @classmethod
    def from_dict(cls, data: dict) -> "OllamaPingResponse":
        return cls(
            reachable=data["reachable"],
            base_url=data["base_url"],
            configured_model=data["configured_model"],
            model_available=data["model_available"],
            available_models=data.get("available_models", []),
            error=data.get("error"),
            latency_ms=data.get("latency_ms"),
        )


@dataclass
class HealthResponse:
    """Response from GET /health."""

    status: str
    version: str

    @classmethod
    def from_dict(cls, data: dict) -> "HealthResponse":
        return cls(status=data["status"], version=data["version"])
