from typing import Optional
from app.models.schemas import AnalysisResult

VALID_ATTACK_CLASSIFICATIONS = {
    "reconnaissance",
    "credential_access",
    "initial_access",
    "lateral_movement",
    "command_and_control",
    "benign",
    "unknown",
}

_FALLBACK_REASON = "Analysis failed or returned invalid data. Manual review required."

FALLBACK_RESULT = AnalysisResult(
    attack_classification="unknown",
    false_positive_likelihood=0.5,
    risk_score=50,
    reason=_FALLBACK_REASON,
    fallback_used=True,
)


def _make_fallback(reason: Optional[str] = None) -> AnalysisResult:
    """Return a safe fallback AnalysisResult with an optional custom reason."""
    return AnalysisResult(
        attack_classification="unknown",
        false_positive_likelihood=0.5,
        risk_score=50,
        reason=reason or _FALLBACK_REASON,
        fallback_used=True,
    )


def validate_analysis_result(data: Optional[dict]) -> AnalysisResult:
    """
    Validate a parsed JSON dict against the AnalysisResult schema.

    Validation rules:
    - attack_classification must be one of the 7 allowed labels (case-insensitive)
    - false_positive_likelihood must be a float strictly in [0.0, 1.0]
    - risk_score must be an integer strictly in [0, 100]
    - reason must be a non-empty, non-whitespace string

    Returns the validated result or a safe fallback if any check fails.
    """
    if data is None:
        return _make_fallback()

    if not isinstance(data, dict):
        return _make_fallback()

    try:
        # --- attack_classification ---
        raw_cls = data.get("attack_classification")
        if raw_cls is None:
            return _make_fallback("Model returned null attack_classification.")
        attack_classification = str(raw_cls).lower().strip()
        if attack_classification not in VALID_ATTACK_CLASSIFICATIONS:
            return _make_fallback(
                f"Invalid attack_classification: '{raw_cls}'. "
                f"Must be one of: {', '.join(sorted(VALID_ATTACK_CLASSIFICATIONS))}."
            )

        # --- false_positive_likelihood ---
        raw_fp = data.get("false_positive_likelihood")
        if raw_fp is None:
            return _make_fallback("Model returned null false_positive_likelihood.")
        try:
            false_positive_likelihood = float(raw_fp)
        except (TypeError, ValueError):
            return _make_fallback(f"false_positive_likelihood is not a number: '{raw_fp}'.")
        if not (0.0 <= false_positive_likelihood <= 1.0):
            return _make_fallback(
                f"false_positive_likelihood {false_positive_likelihood} is out of range [0.0, 1.0]."
            )

        # --- risk_score ---
        raw_rs = data.get("risk_score")
        if raw_rs is None:
            return _make_fallback("Model returned null risk_score.")
        try:
            risk_score = int(float(raw_rs))  # accept "85" or 85.0 from LLM
        except (TypeError, ValueError):
            return _make_fallback(f"risk_score is not a number: '{raw_rs}'.")
        if not (0 <= risk_score <= 100):
            return _make_fallback(
                f"risk_score {risk_score} is out of range [0, 100]."
            )

        # --- reason ---
        raw_reason = data.get("reason")
        if raw_reason is None:
            return _make_fallback("Model returned null reason.")
        reason = str(raw_reason).strip()
        if not reason:
            return _make_fallback("Model returned an empty reason string.")

        return AnalysisResult(
            attack_classification=attack_classification,
            false_positive_likelihood=false_positive_likelihood,
            risk_score=risk_score,
            reason=reason,
            fallback_used=False,
        )

    except Exception as e:
        return _make_fallback(f"Unexpected validation error: {e}")
