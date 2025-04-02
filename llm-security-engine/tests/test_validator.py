import pytest
from app.services.validator import validate_analysis_result, FALLBACK_RESULT


def _make_valid(**overrides):
    base = {
        "attack_classification": "reconnaissance",
        "false_positive_likelihood": 0.1,
        "risk_score": 80,
        "reason": "Detected port scan from external IP.",
    }
    base.update(overrides)
    return base


# ─── Valid inputs ────────────────────────────────────────────────────────────

def test_valid_full_result():
    result = validate_analysis_result(_make_valid())
    assert result.fallback_used is False
    assert result.attack_classification == "reconnaissance"
    assert result.risk_score == 80
    assert result.false_positive_likelihood == 0.1


def test_all_valid_classifications():
    for cls in ["reconnaissance", "credential_access", "initial_access",
                "lateral_movement", "command_and_control", "benign", "unknown"]:
        result = validate_analysis_result(_make_valid(attack_classification=cls))
        assert result.fallback_used is False
        assert result.attack_classification == cls


def test_boundary_values_min():
    result = validate_analysis_result(_make_valid(
        attack_classification="benign",
        false_positive_likelihood=0.0,
        risk_score=0,
        reason="Clean.",
    ))
    assert result.fallback_used is False
    assert result.risk_score == 0
    assert result.false_positive_likelihood == 0.0


def test_boundary_values_max():
    result = validate_analysis_result(_make_valid(
        false_positive_likelihood=1.0,
        risk_score=100,
    ))
    assert result.fallback_used is False
    assert result.risk_score == 100
    assert result.false_positive_likelihood == 1.0


def test_risk_score_as_float_string_is_accepted():
    result = validate_analysis_result(_make_valid(risk_score=85.0))
    assert result.fallback_used is False
    assert result.risk_score == 85


def test_classification_case_insensitive():
    result = validate_analysis_result(_make_valid(attack_classification="RECONNAISSANCE"))
    assert result.fallback_used is False
    assert result.attack_classification == "reconnaissance"


def test_classification_strips_whitespace():
    result = validate_analysis_result(_make_valid(attack_classification="  benign  "))
    assert result.fallback_used is False
    assert result.attack_classification == "benign"


# ─── Invalid classification ───────────────────────────────────────────────────

def test_invalid_attack_classification():
    result = validate_analysis_result(_make_valid(attack_classification="malware_execution"))
    assert result.fallback_used is True
    assert result.attack_classification == "unknown"


def test_empty_attack_classification():
    result = validate_analysis_result(_make_valid(attack_classification=""))
    assert result.fallback_used is True


def test_null_attack_classification():
    result = validate_analysis_result(_make_valid(attack_classification=None))
    assert result.fallback_used is True


# ─── Invalid false_positive_likelihood ───────────────────────────────────────

def test_fp_too_high():
    result = validate_analysis_result(_make_valid(false_positive_likelihood=1.5))
    assert result.fallback_used is True


def test_fp_too_low():
    result = validate_analysis_result(_make_valid(false_positive_likelihood=-0.1))
    assert result.fallback_used is True


def test_fp_none():
    result = validate_analysis_result(_make_valid(false_positive_likelihood=None))
    assert result.fallback_used is True


def test_fp_not_a_number():
    result = validate_analysis_result(_make_valid(false_positive_likelihood="high"))
    assert result.fallback_used is True


# ─── Invalid risk_score ───────────────────────────────────────────────────────

def test_risk_score_too_high():
    result = validate_analysis_result(_make_valid(risk_score=150))
    assert result.fallback_used is True


def test_risk_score_negative():
    result = validate_analysis_result(_make_valid(risk_score=-5))
    assert result.fallback_used is True


def test_risk_score_none():
    result = validate_analysis_result(_make_valid(risk_score=None))
    assert result.fallback_used is True


def test_risk_score_not_a_number():
    result = validate_analysis_result(_make_valid(risk_score="critical"))
    assert result.fallback_used is True


# ─── Invalid reason ───────────────────────────────────────────────────────────

def test_empty_reason():
    result = validate_analysis_result(_make_valid(reason=""))
    assert result.fallback_used is True


def test_whitespace_only_reason():
    result = validate_analysis_result(_make_valid(reason="   "))
    assert result.fallback_used is True


def test_null_reason():
    result = validate_analysis_result(_make_valid(reason=None))
    assert result.fallback_used is True


# ─── None / bad input ────────────────────────────────────────────────────────

def test_none_input():
    result = validate_analysis_result(None)
    assert result.fallback_used is True
    assert result.attack_classification == "unknown"


def test_empty_dict():
    result = validate_analysis_result({})
    assert result.fallback_used is True


def test_non_dict_input():
    result = validate_analysis_result("not a dict")  # type: ignore
    assert result.fallback_used is True


def test_list_input():
    result = validate_analysis_result([])  # type: ignore
    assert result.fallback_used is True


# ─── Fallback content ─────────────────────────────────────────────────────────

def test_fallback_contains_safe_values():
    result = validate_analysis_result(None)
    assert result.attack_classification == "unknown"
    assert 0.0 <= result.false_positive_likelihood <= 1.0
    assert 0 <= result.risk_score <= 100
    assert len(result.reason) > 0
    assert result.fallback_used is True


def test_fallback_reason_is_non_empty():
    result = validate_analysis_result({})
    assert isinstance(result.reason, str)
    assert len(result.reason.strip()) > 0
