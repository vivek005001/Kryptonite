"""Detector for hardcoded secrets, API keys, and credentials."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from kryptonite.core.finding import Evidence, Finding, SeverityLevel

if TYPE_CHECKING:
    from kryptonite.core.ipa_parser import AppContext

# ── Regex patterns ──────────────────────────────────────────────────
_PATTERNS: list[tuple[str, str, re.Pattern[str], SeverityLevel]] = [
    (
        "SEC-001",
        "AWS Access Key ID",
        re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
        SeverityLevel.CRITICAL,
    ),
    (
        "SEC-002",
        "AWS Secret Access Key",
        re.compile(r"""(?:aws_secret_access_key|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""", re.I),
        SeverityLevel.CRITICAL,
    ),
    (
        "SEC-003",
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        SeverityLevel.HIGH,
    ),
    (
        "SEC-004",
        "Firebase API Key",
        re.compile(r"""(?:firebase|FIREBASE)[_\s]*(?:API[_\s]*KEY|api[_\s]*key)\s*[:=]\s*['"]([^'"]{10,})['"]"""),
        SeverityLevel.HIGH,
    ),
    (
        "SEC-005",
        "Generic API Key / Token",
        re.compile(r"""(?:api[_\-\s]?key|api[_\-\s]?token|access[_\-\s]?token|auth[_\-\s]?token|secret[_\-\s]?key)\s*[:=]\s*['"]([A-Za-z0-9\-_\.]{16,})['"]""", re.I),
        SeverityLevel.HIGH,
    ),
    (
        "SEC-006",
        "Private Key Block",
        re.compile(r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        SeverityLevel.CRITICAL,
    ),
    (
        "SEC-007",
        "Hardcoded Password",
        re.compile(r"""(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{4,})['"]""", re.I),
        SeverityLevel.HIGH,
    ),
    (
        "SEC-008",
        "Bearer Token",
        re.compile(r"""[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}"""),
        SeverityLevel.HIGH,
    ),
    (
        "SEC-009",
        "Database Connection String",
        re.compile(r"""(?:mongodb|postgres|mysql|redis|amqp)://[^\s'"]{10,}""", re.I),
        SeverityLevel.CRITICAL,
    ),
    (
        "SEC-010",
        "Slack Webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        SeverityLevel.HIGH,
    ),
    (
        "SEC-011",
        "GitHub / GitLab Token",
        re.compile(r"(?:ghp_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9\-]{20,})"),
        SeverityLevel.CRITICAL,
    ),
]


def _scan_file(path: Path) -> list[tuple[str, int, str]]:
    """Return (line_text, lineno, snippet) for each line of a text file."""
    results: list[tuple[str, int, str]] = []
    try:
        text = path.read_text(errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            results.append((line, lineno, line.strip()[:200]))
    except Exception:
        pass
    return results


def run(ctx: AppContext) -> list[Finding]:
    """Scan all text files and binary strings for hardcoded secrets."""
    findings: list[Finding] = []
    seen: set[str] = set()

    # ── Scan text files ──────────────────────────────────────────
    for fpath in ctx.text_files():
        rel = str(fpath.relative_to(ctx.app_dir))
        for line_text, lineno, snippet in _scan_file(fpath):
            for fid, title, pattern, severity in _PATTERNS:
                if pattern.search(line_text):
                    dedup_key = f"{fid}:{rel}:{lineno}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    findings.append(Finding(
                        id=fid,
                        title=title,
                        description=(
                            f"A potential {title.lower()} was found hardcoded "
                            f"in the application bundle."
                        ),
                        severity=severity,
                        owasp_category="M1",
                        evidence=[Evidence(file=rel, line=lineno, snippet=snippet)],
                        remediation=(
                            "Remove hardcoded credentials from source code. "
                            "Use secure storage mechanisms such as the iOS "
                            "Keychain, environment variables injected at build "
                            "time, or a remote secrets manager."
                        ),
                    ))

    # ── Scan binary strings ──────────────────────────────────────
    for idx, s in enumerate(ctx.binary_strings):
        for fid, title, pattern, severity in _PATTERNS:
            if pattern.search(s):
                dedup_key = f"{fid}:binary:{s[:60]}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(Finding(
                    id=fid,
                    title=f"{title} (in binary)",
                    description=(
                        f"A potential {title.lower()} was found embedded in "
                        f"the application binary."
                    ),
                    severity=severity,
                    owasp_category="M1",
                    evidence=[Evidence(
                        file="<binary>",
                        line=idx + 1,
                        snippet=s.strip()[:200],
                    )],
                    remediation=(
                        "Remove hardcoded credentials from source code before "
                        "compilation. Use the iOS Keychain or a secure "
                        "server-side configuration service."
                    ),
                ))

    return findings
