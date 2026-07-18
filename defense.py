"""
The defense layer: LLM Guard.

A guardrail is just a filter that inspects text BEFORE it reaches the model
(input scanning) or BEFORE it leaves the system (output scanning), and can
block it. LLM Guard ships ~35 such scanners; we use two:

  - PromptInjection : an ML model that scores how "injection-like" some text is.
  - Secrets         : spots API keys / credentials so they can't be exfiltrated.

KEY INSIGHT for indirect injection: the attack does NOT arrive in the user's
message. It arrives inside a *document the agent reads*. So guarding only the
user input catches nothing. You must also scan tool OUTPUT (the retrieved
content) and the OUTGOING email. That's what this module does.

The whole layer is behind GUARD_ENABLED so you can run the exact same attack
with defense OFF, then ON, and measure the difference.
"""

import os

GUARD_ENABLED = os.getenv("GUARD_ENABLED", "false").lower() == "true"

_scanners = None  # loaded once, lazily (the ML models are a few hundred MB)


def _load_scanners():
    global _scanners
    if _scanners is None:
        from llm_guard.input_scanners import PromptInjection, Secrets
        from llm_guard.input_scanners.prompt_injection import MatchType

        _scanners = {
            "injection": PromptInjection(threshold=0.5, match_type=MatchType.FULL),
            "secrets": Secrets(),
        }
    return _scanners


def inspect_incoming_text(text: str) -> tuple[bool, str]:
    """
    Scan a piece of text coming INTO the agent (user message OR tool output).
    Returns (is_safe, reason). If GUARD is off, everything passes.
    """
    if not GUARD_ENABLED:
        return True, ""
    scanner = _load_scanners()["injection"]
    _sanitized, is_valid, score = scanner.scan(text)
    if not is_valid:
        return False, f"prompt-injection detector fired (score={score:.2f})"
    return True, ""


def inspect_outgoing_text(text: str) -> tuple[bool, str]:
    """
    Scan text about to LEAVE the system (e.g. an email body) for leaked secrets.
    Returns (is_safe, reason).
    """
    if not GUARD_ENABLED:
        return True, ""
    scanner = _load_scanners()["secrets"]
    _sanitized, is_valid, score = scanner.scan(text)
    if not is_valid:
        return False, "outgoing text contains a secret/credential"
    return True, ""
