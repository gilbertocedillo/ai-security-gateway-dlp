#!/usr/bin/env python3
"""
DLP Engine - AI Security Gateway

Standalone Data Loss Prevention engine usable outside n8n.
Scans a prompt for sensitive data, redacts it, and returns structured findings.

Design principles:
- Regex/pattern layer FIRST, before any LLM call (cheap, deterministic, no data leak to a 3rd party for the scan itself)
- Secrets (AWS keys, API tokens, passwords) are CRITICAL: caller should fail-closed / block, not just redact-and-forward in strict mode
- Credit cards are validated with Luhn to cut false positives on random 16-digit numbers
- Findings NEVER contain the full raw secret in logs intended for storage: only type, count, and a masked preview

Author: Gilberto A. Cedillo Soto
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Pattern


def luhn_valid(number: str) -> bool:
    """Luhn checksum for credit-card candidate validation."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    alt = False
    for d in reversed(digits):
        if alt:
            d = d * 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


@dataclass
class Finding:
    type: str          # e.g. "aws_access_key", "email", "credit_card"
    severity: str      # "critical" | "high" | "medium"
    count: int
    masked_preview: str  # e.g. "AKIA************MPLE" - never the full secret

    def to_dict(self):
        return asdict(self)


@dataclass
class DLPResult:
    redacted_text: str
    findings: list[Finding] = field(default_factory=list)
    has_critical: bool = False
    total_redactions: int = 0

    def to_dict(self):
        return {
            "redacted_text": self.redacted_text,
            "findings": [f.to_dict() for f in self.findings],
            "has_critical": self.has_critical,
            "total_redactions": self.total_redactions,
        }


def _mask(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * (len(value) - keep * 2)}{value[-keep:]}"


# (name, severity, compiled pattern, placeholder, validator or None)
# Order matters: specific secrets before generic patterns.
_PATTERNS: list[tuple[str, str, Pattern, str, object]] = [
    ("aws_access_key", "critical",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]", None),
    ("aws_secret_key", "critical",
     re.compile(r"(?i)(?:aws_secret_access_key|aws_secret)\s*[:=]\s*[A-Za-z0-9/+=]{40}"),
     "[REDACTED_AWS_SECRET]", None),
    ("openai_api_key", "critical",
     re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"), "[REDACTED_OPENAI_KEY]", None),
    ("anthropic_api_key", "critical",
     re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "[REDACTED_ANTHROPIC_KEY]", None),
    ("github_token", "critical",
     re.compile(r"\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]", None),
    ("slack_token", "critical",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "[REDACTED_SLACK_TOKEN]", None),
    ("private_key_block", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.S),
     "[REDACTED_PRIVATE_KEY]", None),
    ("jwt", "high",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "[REDACTED_JWT]", None),
    ("generic_password_assignment", "critical",
     re.compile(r"(?i)\b(?:password|passwd|pwd|api[_-]?key|secret|token)\s*[:=]\s*\S{4,}"),
     "[REDACTED_CREDENTIAL]", None),
    ("credit_card", "high",
     re.compile(r"\b(?:\d[ \-]?){13,19}\b"), "[REDACTED_CREDIT_CARD]", luhn_valid),
    ("us_ssn", "high",
     re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), "[REDACTED_SSN]", None),
    ("email", "medium",
     re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]", None),
    ("phone_us", "medium",
     re.compile(r"(?<!\d)(?:\+1[ \-]?)?(?:\(?\d{3}\)?[ \-.]?)\d{3}[ \-.]?\d{4}(?!\d)"), "[REDACTED_PHONE]", None),
    ("ipv4_private_context", "medium",
     # Only flagged, still redacted in strict PII mode by caller choice; default: redact
     re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
     "[REDACTED_PRIVATE_IP]", None),
]


def scan_and_redact(text: str) -> DLPResult:
    """Scan `text`, redact every match, return result + findings."""
    if not text:
        return DLPResult(redacted_text=text or "")

    redacted = text
    findings: list[Finding] = []

    for name, severity, pattern, placeholder, validator in _PATTERNS:
        matches = list(pattern.finditer(redacted))
        valid_matches = []
        for m in matches:
            if validator is not None and not validator(m.group(0)):
                continue
            valid_matches.append(m)
        if not valid_matches:
            continue
        preview = _mask(valid_matches[0].group(0))

        # For credit cards, only replace validated spans (rebuild manually)
        if validator is not None:
            def _repl(m, _v=validator, _p=placeholder):
                return _p if _v(m.group(0)) else m.group(0)
            redacted = pattern.sub(_repl, redacted)
        else:
            redacted = pattern.sub(placeholder, redacted)

        findings.append(Finding(type=name, severity=severity,
                                count=len(valid_matches), masked_preview=preview))

    total = sum(f.count for f in findings)
    return DLPResult(
        redacted_text=redacted,
        findings=findings,
        has_critical=any(f.severity == "critical" for f in findings),
        total_redactions=total,
    )


if __name__ == "__main__":
    demo = ("My email is john.doe@example.com, AWS key AKIAIOSFODNN7EXAMPLE, "
            "card 4242424242424242, password= hunter2secret, call me at (801) 555-0142")
    r = scan_and_redact(demo)
    import json
    print(json.dumps(r.to_dict(), indent=2))
