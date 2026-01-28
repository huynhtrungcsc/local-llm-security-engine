import pytest
from app.services.parser import extract_json_from_response


# ─── Helper ─────────────────────────────────────────────────────────────────

def _valid_json():
    return {
        "raw": '{"attack_classification": "reconnaissance", "false_positive_likelihood": 0.1, "risk_score": 80, "reason": "Port scan detected."}',
        "cls": "reconnaissance",
        "rs": 80,
    }


# ─── Basic cases ────────────────────────────────────────────────────────────

def test_parse_clean_json():
    r = extract_json_from_response(_valid_json()["raw"])
    assert r.success is True
    assert r.data["attack_classification"] == "reconnaissance"
    assert r.data["risk_score"] == 80
    assert r.strategy == "direct"


def test_parse_json_without_code_fences():
    raw = '  {"attack_classification": "credential_access", "false_positive_likelihood": 0.05, "risk_score": 95, "reason": "Brute-force login."}\n'
    r = extract_json_from_response(raw)
    assert r.success is True
    assert r.data["risk_score"] == 95


def test_parse_empty_string():
    r = extract_json_from_response("")
    assert r.success is False
    assert r.data is None
    assert r.strategy == "none"


def test_parse_none():
    r = extract_json_from_response(None)
    assert r.success is False
    assert r.data is None


def test_parse_invalid_json():
    r = extract_json_from_response("not json at all")
    assert r.success is False
    assert r.data is None


# ─── Markdown-wrapped JSON ───────────────────────────────────────────────────

def test_parse_json_with_markdown_json_fence():
    raw = '```json\n{"attack_classification": "benign", "false_positive_likelihood": 0.9, "risk_score": 5, "reason": "Normal traffic."}\n```'
    r = extract_json_from_response(raw)
    assert r.success is True
    assert r.data["attack_classification"] == "benign"
    assert r.strategy == "markdown_json"


def test_parse_json_with_bare_fence():
    raw = '```\n{"attack_classification": "initial_access", "false_positive_likelihood": 0.1, "risk_score": 90, "reason": "Shell obtained."}\n```'
    r = extract_json_from_response(raw)
    assert r.success is True
    assert r.data["attack_classification"] == "initial_access"
    assert r.strategy == "markdown_bare"


# ─── JSON embedded in text ──────────────────────────────────────────────────

def test_parse_json_embedded_in_text():
    raw = 'Here is my analysis: {"attack_classification": "lateral_movement", "false_positive_likelihood": 0.2, "risk_score": 90, "reason": "SMB lateral spread."} Hope this helps.'
    r = extract_json_from_response(raw)
    assert r.success is True
    assert r.data["attack_classification"] == "lateral_movement"
    assert r.strategy == "brace_extract"


def test_parse_json_with_preamble_and_postamble():
    raw = (
        "Based on the event data, I classify this as follows:\n"
        '{"attack_classification": "command_and_control", "false_positive_likelihood": 0.05, "risk_score": 95, "reason": "Beacon detected."}\n'
        "Please note this is based on limited context."
    )
    r = extract_json_from_response(raw)
    assert r.success is True
    assert r.data["attack_classification"] == "command_and_control"


# ─── Near-valid JSON repairs ─────────────────────────────────────────────────

def test_parse_json_with_trailing_comma():
    raw = '{"attack_classification": "reconnaissance", "false_positive_likelihood": 0.3, "risk_score": 60, "reason": "Port scan.",}'
    r = extract_json_from_response(raw)
    assert r.success is True
    assert r.data["attack_classification"] == "reconnaissance"
    assert r.strategy == "trailing_comma_fix"


def test_parse_json_with_single_quotes():
    raw = "{'attack_classification': 'benign', 'false_positive_likelihood': 0.95, 'risk_score': 2, 'reason': 'Routine check.'}"
    r = extract_json_from_response(raw)
    assert r.success is True
    assert r.data["attack_classification"] == "benign"
    assert r.strategy == "single_quote_fix"


def test_parse_json_with_single_quotes_and_trailing_comma():
    """Strategy 7: combined fix — both single-quote AND trailing-comma fixes are required."""
    raw = "{'attack_classification': 'reconnaissance', 'false_positive_likelihood': 0.3, 'risk_score': 60, 'reason': 'Port scan.',}"
    r = extract_json_from_response(raw)
    assert r.success is True
    assert r.data["attack_classification"] == "reconnaissance"
    assert r.strategy == "combined_fix"


# ─── Null field handling ─────────────────────────────────────────────────────

def test_parse_json_with_null_classification():
    raw = '{"attack_classification": null, "false_positive_likelihood": 0.5, "risk_score": 50, "reason": "Unclear."}'
    r = extract_json_from_response(raw)
    assert r.success is True
    assert r.data["attack_classification"] == "unknown"


def test_parse_json_with_null_reason():
    raw = '{"attack_classification": "benign", "false_positive_likelihood": 0.9, "risk_score": 5, "reason": null}'
    r = extract_json_from_response(raw)
    assert r.success is True
    assert r.data["reason"] == ""


def test_parse_json_with_null_risk_score():
    raw = '{"attack_classification": "reconnaissance", "false_positive_likelihood": 0.2, "risk_score": null, "reason": "Scan."}'
    r = extract_json_from_response(raw)
    assert r.success is True
    assert r.data["risk_score"] == 50


def test_parse_json_with_null_fp_likelihood():
    raw = '{"attack_classification": "benign", "false_positive_likelihood": null, "risk_score": 5, "reason": "Normal."}'
    r = extract_json_from_response(raw)
    assert r.success is True
    assert r.data["false_positive_likelihood"] == 0.5


# ─── Missing fields ──────────────────────────────────────────────────────────

def test_parse_json_with_missing_fields_still_returns_dict():
    raw = '{"attack_classification": "unknown"}'
    r = extract_json_from_response(raw)
    assert r.success is True
    assert r.data is not None


def test_parse_returns_parse_result_type():
    from app.services.parser import ParseResult
    r = extract_json_from_response('{"attack_classification": "benign", "false_positive_likelihood": 0.9, "risk_score": 5, "reason": "Normal."}')
    assert isinstance(r, ParseResult)
    assert hasattr(r, "data")
    assert hasattr(r, "success")
    assert hasattr(r, "strategy")
