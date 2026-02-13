"""Detect debug logging and diagnostic code left in release builds."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from kryptonite.core.finding import Evidence, Finding, SeverityLevel

if TYPE_CHECKING:
    from kryptonite.core.ipa_parser import AppContext

# Logging function patterns to look for in binary strings.
_LOG_PATTERNS: list[tuple[str, str, re.Pattern[str], SeverityLevel, str]] = [
    (
        "LOG-001",
        "NSLog Usage Detected",
        re.compile(r"\bNSLog\b"),
        SeverityLevel.MEDIUM,
        "NSLog writes to the system console and can leak sensitive "
        "information to anyone with device access. Use os_log with "
        "appropriate privacy levels or remove logging in release builds.",
    ),
    (
        "LOG-002",
        "print() / debugPrint() in Binary",
        re.compile(r"\b(?:debugPrint|Swift\.print)\b"),
        SeverityLevel.LOW,
        "Swift print/debugPrint statements are compiled into release "
        "builds by default. Use #if DEBUG guards or os_log.",
    ),
    (
        "LOG-003",
        "printf / fprintf Usage",
        re.compile(r"\b(?:printf|fprintf|NSLog)\b"),
        SeverityLevel.LOW,
        "C-level print functions may leak information. Remove or guard "
        "with preprocessor macros for release builds.",
    ),
]

_DEBUG_INDICATORS: list[tuple[str, str, re.Pattern[str], SeverityLevel, str]] = [
    (
        "LOG-004",
        "Debug Menu / Debug Mode Indicator",
        re.compile(r"""(?:isDebug|debugMode|DEBUG_MODE|kDebug|enableDebug|showDebug)""", re.I),
        SeverityLevel.MEDIUM,
        "Debug mode indicators suggest development features may be "
        "reachable in the production build. Remove all debug flags and "
        "menus from release builds.",
    ),
    (
        "LOG-005",
        "Test / Staging Server References",
        re.compile(r"""(?:staging\.|\.staging|test\.api|api-test\.|dev\.api|localhost|127\.0\.0\.1|0\.0\.0\.0)""", re.I),
        SeverityLevel.MEDIUM,
        "References to staging or test servers were found. These may "
        "expose development infrastructure. Remove all non-production "
        "server references from release builds.",
    ),
    (
        "LOG-006",
        "Verbose / Trace Logging Level",
        re.compile(r"""(?:LOG_LEVEL_VERBOSE|LOG_LEVEL_TRACE|kLogLevelDebug|\.verbose|LogLevel\.debug)"""),
        SeverityLevel.LOW,
        "Verbose logging may expose sensitive application flow details. "
        "Set logging to WARNING or ERROR level in release builds.",
    ),
]


def run(ctx: AppContext) -> list[Finding]:
    """Scan binary strings for logging and debug code indicators."""
    findings: list[Finding] = []
    seen: set[str] = set()

    all_patterns = _LOG_PATTERNS + _DEBUG_INDICATORS

    for idx, s in enumerate(ctx.binary_strings):
        for fid, title, pattern, severity, remediation in all_patterns:
            if pattern.search(s):
                # Deduplicate by finding ID (report each category once)
                if fid in seen:
                    continue
                seen.add(fid)
                findings.append(Finding(
                    id=fid,
                    title=title,
                    description=f"{title} in the application binary.",
                    severity=severity,
                    owasp_category="M8",
                    evidence=[Evidence(
                        file="<binary>",
                        line=idx + 1,
                        snippet=s.strip()[:200],
                    )],
                    remediation=remediation,
                ))

    # Also scan text files for debug indicators
    for fpath in ctx.text_files():
        rel = str(fpath.relative_to(ctx.app_dir))
        try:
            text = fpath.read_text(errors="replace")
        except Exception:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for fid, title, pattern, severity, remediation in _DEBUG_INDICATORS:
                if pattern.search(line):
                    key = f"{fid}:{rel}"
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(Finding(
                        id=fid,
                        title=title,
                        description=f"{title} found in bundle file.",
                        severity=severity,
                        owasp_category="M8",
                        evidence=[Evidence(
                            file=rel, line=lineno,
                            snippet=line.strip()[:200],
                        )],
                        remediation=remediation,
                    ))

    return findings
