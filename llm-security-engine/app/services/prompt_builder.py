from app.models.schemas import SecurityEvent, ContextSummary

_LABEL_DEFINITIONS = """\
CLASSIFICATION LABELS — use exactly one:
  reconnaissance       : Scanning, probing, enumeration, or information gathering before an attack.
                         Use when the activity is preparatory, not yet exploiting access.
  credential_access    : Stealing, dumping, or abusing credentials (passwords, hashes, tokens).
                         Use when the goal is OBTAINING credentials, not using them to get in.
  initial_access       : First successful entry into an environment (phishing, exploit, valid accounts).
                         Use when the attacker HAS gained access using credentials or a vulnerability.
  lateral_movement     : Moving between systems inside an already-compromised network.
                         Use when the actor is expanding within an internal environment.
  command_and_control  : Outbound communication to attacker infrastructure from a compromised host.
                         Use when internal hosts are beaconing or receiving commands from outside.
  benign               : Normal, expected, or clearly non-malicious activity.
                         Use only when there is no realistic threat scenario.
  unknown              : Cannot classify with confidence from available data.
                         Use when the event is ambiguous or lacks enough context.

DISTINGUISHING SIMILAR LABELS:
  credential_access vs initial_access:
    - 57 failed logins → credential_access (trying to steal/brute-force creds)
    - 57 failed logins + 1 success → initial_access (access was gained)
    - password hash dump from memory → credential_access
    - attacker logging in with stolen creds → initial_access
  reconnaissance vs initial_access:
    - Nmap scan of external surface → reconnaissance (no access yet)
    - Exploit followed by shell → initial_access (access achieved)
"""

_OUTPUT_FORMAT = """\
OUTPUT FORMAT — return only this JSON, nothing else:
{
  "attack_classification": "<label>",
  "false_positive_likelihood": <0.0 to 1.0>,
  "risk_score": <0 to 100>,
  "reason": "<one or two sentences, specific and factual>"
}

Rules:
- No markdown, no code fences, no explanations outside the JSON
- attack_classification must be exactly one of the 7 allowed labels
- false_positive_likelihood: 0.0 = certain real threat, 1.0 = certain false positive
- risk_score: 0 = no risk, 100 = critical, immediate risk
- reason: factual, brief, references specific indicators from the input
"""

SYSTEM_INSTRUCTION = f"""You are a cybersecurity threat analyst AI embedded in a SOC (Security Operations Center).
Your task is to analyze security events or context summaries and return structured threat classifications.

{_LABEL_DEFINITIONS}
{_OUTPUT_FORMAT}"""


def build_event_prompt(event: SecurityEvent) -> str:
    parts = [
        SYSTEM_INSTRUCTION,
        "\n--- SECURITY EVENT ---",
    ]

    if event.timestamp:
        parts.append(f"Timestamp        : {event.timestamp}")
    if event.source_ip:
        parts.append(f"Source IP        : {event.source_ip}")
    if event.destination_ip:
        parts.append(f"Destination IP   : {event.destination_ip}")
    if event.event_type:
        parts.append(f"Event Type       : {event.event_type}")
    if event.severity:
        parts.append(f"Severity         : {event.severity}")

    parts.append(f"Description      : {event.description}")

    if event.additional_context:
        parts.append(f"Additional Info  : {event.additional_context}")

    parts.append("\nReturn only the JSON object.")

    return "\n".join(parts)


def build_context_prompt(context: ContextSummary) -> str:
    parts = [
        SYSTEM_INSTRUCTION,
        "\n--- SOC CONTEXT SUMMARY ---",
    ]

    if context.entity:
        parts.append(f"Entity           : {context.entity}")
    if context.time_window:
        parts.append(f"Time Window      : {context.time_window}")

    parts.append(f"Summary          : {context.summary}")

    if context.additional_context:
        parts.append(f"Additional Info  : {context.additional_context}")

    parts.append("\nReturn only the JSON object.")

    return "\n".join(parts)
