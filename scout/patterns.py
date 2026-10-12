"""Commodity secret patterns. Extend here for org-specific formats."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern[str]


PATTERNS: list[Pattern] = [
    Pattern("aws_access_key_id", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    Pattern("github_pat", re.compile(r"\b(ghp_[A-Za-z0-9_]{36,})\b")),
    Pattern("github_oauth", re.compile(r"\b(gho_[A-Za-z0-9_]{36,})\b")),
    Pattern("slack_token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    Pattern(
        "generic_api_assignment",
        re.compile(
            r"(?i)(?:api[_-]?key|secret|password|token)\s*[=:]\s*['\"]([^'\"]{12,})['\"]"
        ),
    ),
]


def redact(value: str) -> str:
    if len(value) <= 8:
        return "••••"
    return f"{value[:4]}••••{value[-4:]}"
