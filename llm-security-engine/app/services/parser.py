import json
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ParseResult:
    data: Optional[dict]
    success: bool
    strategy: str  # which extraction strategy succeeded, or "none"


def _try_parse(text: str) -> Optional[dict]:
    """Attempt json.loads and return dict or None."""
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
    except (json.JSONDecodeError, ValueError):
        pass
    return None


def _fix_trailing_comma(text: str) -> str:
    """Remove trailing commas before closing braces/brackets (common LLM mistake)."""
    return re.sub(r",\s*([}\]])", r"\1", text)


def _fix_single_quotes(text: str) -> str:
    """
    Replace single-quoted JSON keys/values with double quotes.
    This is a best-effort fix — handles simple cases only.
    """
    # Replace 'key': with "key":
    text = re.sub(r"'([^']+)'(\s*:)", r'"\1"\2', text)
    # Replace : 'value' with : "value"
    text = re.sub(r"(:\s*)'([^']*)'", r'\1"\2"', text)
    return text


def _normalize_null_fields(data: dict) -> dict:
    """Replace None / null values in expected fields with appropriate defaults."""
    defaults = {
        "attack_classification": "unknown",
        "false_positive_likelihood": 0.5,
        "risk_score": 50,
        "reason": "",
    }
    for key, default in defaults.items():
        if key in data and data[key] is None:
            data[key] = default
    return data


def extract_json_from_response(raw_text: Optional[str]) -> ParseResult:
    """
    Attempt to extract a valid JSON object from raw Ollama response text.

    Tries up to 7 strategies in order:
    1. Direct parse of the full text
    2. Extract from markdown ```json ... ``` code block
    3. Extract from any bare ``` ... ``` code block
    4. Regex search for the first {...} block in the text
    5. Apply trailing-comma fix and retry (handles ,} and ,])
    6. Apply single-quote fix and retry (handles 'key': 'value')
    7. Apply both fixes combined (handles ,} AND single-quotes together)

    Returns a ParseResult with the extracted dict (or None) and metadata.
    strategy is set to "none" only internally; callers (routes) normalize it to None.
    """
    if not raw_text or not raw_text.strip():
        return ParseResult(data=None, success=False, strategy="none")

    stripped = raw_text.strip()

    # Strategy 1: clean direct parse
    result = _try_parse(stripped)
    if result is not None:
        _normalize_null_fields(result)
        return ParseResult(data=result, success=True, strategy="direct")

    # Strategy 2: markdown ```json ... ``` block
    match = re.search(r"```json\s*(\{[\s\S]*?\})\s*```", stripped, re.IGNORECASE)
    if match:
        result = _try_parse(match.group(1))
        if result is not None:
            _normalize_null_fields(result)
            return ParseResult(data=result, success=True, strategy="markdown_json")

    # Strategy 3: bare ``` ... ``` block
    match = re.search(r"```\s*(\{[\s\S]*?\})\s*```", stripped)
    if match:
        result = _try_parse(match.group(1))
        if result is not None:
            _normalize_null_fields(result)
            return ParseResult(data=result, success=True, strategy="markdown_bare")

    # Strategy 4: first {...} block in text (handles "Here is my analysis: {...}")
    match = re.search(r"\{[\s\S]*\}", stripped)
    if match:
        candidate = match.group(0)
        result = _try_parse(candidate)
        if result is not None:
            _normalize_null_fields(result)
            return ParseResult(data=result, success=True, strategy="brace_extract")

        # Strategy 5: apply trailing-comma fix
        fixed = _fix_trailing_comma(candidate)
        result = _try_parse(fixed)
        if result is not None:
            _normalize_null_fields(result)
            return ParseResult(data=result, success=True, strategy="trailing_comma_fix")

        # Strategy 6: apply single-quote fix
        fixed = _fix_single_quotes(candidate)
        result = _try_parse(fixed)
        if result is not None:
            _normalize_null_fields(result)
            return ParseResult(data=result, success=True, strategy="single_quote_fix")

        # Combined fix
        fixed = _fix_trailing_comma(_fix_single_quotes(candidate))
        result = _try_parse(fixed)
        if result is not None:
            _normalize_null_fields(result)
            return ParseResult(data=result, success=True, strategy="combined_fix")

    return ParseResult(data=None, success=False, strategy="none")
