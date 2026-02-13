"""Analyze App Transport Security (ATS) and insecure communication patterns."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from kryptonite.core.finding import Evidence, Finding, SeverityLevel

if TYPE_CHECKING:
    from kryptonite.core.ipa_parser import AppContext


def run(ctx: AppContext) -> list[Finding]:
    """Check Info.plist ATS settings and scan for http:// URLs."""
    findings: list[Finding] = []
    plist = ctx.info_plist

    ats = plist.get("NSAppTransportSecurity", {})

    # ── NSAllowsArbitraryLoads ───────────────────────────────────
    if ats.get("NSAllowsArbitraryLoads", False):
        findings.append(Finding(
            id="TRANS-001",
            title="App Transport Security Disabled Globally",
            description=(
                "NSAllowsArbitraryLoads is set to YES, which disables "
                "App Transport Security for all network connections. "
                "This allows the app to make insecure HTTP connections."
            ),
            severity=SeverityLevel.HIGH,
            owasp_category="M5",
            evidence=[Evidence(
                file="Info.plist",
                snippet="NSAllowsArbitraryLoads = true",
            )],
            remediation=(
                "Set NSAllowsArbitraryLoads to NO and configure "
                "per-domain exceptions only for domains that truly "
                "require HTTP. Use HTTPS everywhere."
            ),
        ))

    # ── NSAllowsArbitraryLoadsInWebContent ───────────────────────
    if ats.get("NSAllowsArbitraryLoadsInWebContent", False):
        findings.append(Finding(
            id="TRANS-002",
            title="Arbitrary Loads Allowed in Web Content",
            description=(
                "NSAllowsArbitraryLoadsInWebContent is enabled, "
                "allowing insecure loads within WebViews."
            ),
            severity=SeverityLevel.MEDIUM,
            owasp_category="M5",
            evidence=[Evidence(
                file="Info.plist",
                snippet="NSAllowsArbitraryLoadsInWebContent = true",
            )],
            remediation=(
                "Disable this flag and ensure all web content is "
                "served over HTTPS."
            ),
        ))

    # ── Per-domain exceptions ────────────────────────────────────
    exception_domains = ats.get("NSExceptionDomains", {})
    for domain, settings in exception_domains.items():
        if isinstance(settings, dict):
            if settings.get("NSExceptionAllowsInsecureHTTPLoads", False):
                findings.append(Finding(
                    id="TRANS-003",
                    title=f"Insecure HTTP Allowed for {domain}",
                    description=(
                        f"The domain '{domain}' has "
                        f"NSExceptionAllowsInsecureHTTPLoads enabled, "
                        f"allowing plaintext HTTP connections."
                    ),
                    severity=SeverityLevel.MEDIUM,
                    owasp_category="M5",
                    evidence=[Evidence(
                        file="Info.plist",
                        snippet=f"{domain}: NSExceptionAllowsInsecureHTTPLoads = true",
                    )],
                    remediation=(
                        f"Migrate {domain} to HTTPS and remove this "
                        f"exception."
                    ),
                ))
            if settings.get("NSExceptionMinimumTLSVersion", "") in (
                "TLSv1.0", "TLSv1.1"
            ):
                tls_ver = settings["NSExceptionMinimumTLSVersion"]
                findings.append(Finding(
                    id="TRANS-004",
                    title=f"Weak TLS Version for {domain}",
                    description=(
                        f"Domain '{domain}' allows {tls_ver}, which is "
                        f"deprecated and vulnerable."
                    ),
                    severity=SeverityLevel.HIGH,
                    owasp_category="M5",
                    evidence=[Evidence(
                        file="Info.plist",
                        snippet=f"{domain}: NSExceptionMinimumTLSVersion = {tls_ver}",
                    )],
                    remediation=(
                        f"Require TLS 1.2 or higher for {domain}."
                    ),
                ))

    # ── Hardcoded HTTP URLs ──────────────────────────────────────
    http_pattern = re.compile(r"http://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}")

    # In binary strings
    seen_urls: set[str] = set()
    for idx, s in enumerate(ctx.binary_strings):
        for m in http_pattern.finditer(s):
            url = m.group(0)
            if url not in seen_urls:
                seen_urls.add(url)
                findings.append(Finding(
                    id="TRANS-005",
                    title="Hardcoded HTTP URL",
                    description=(
                        f"A plaintext HTTP URL ({url}) was found in the "
                        f"binary. Data transmitted over HTTP is susceptible "
                        f"to interception."
                    ),
                    severity=SeverityLevel.MEDIUM,
                    owasp_category="M5",
                    evidence=[Evidence(
                        file="<binary>", line=idx + 1, snippet=url,
                    )],
                    remediation=(
                        "Replace all HTTP URLs with HTTPS equivalents."
                    ),
                ))

    # In text files
    for fpath in ctx.text_files():
        rel = str(fpath.relative_to(ctx.app_dir))
        try:
            text = fpath.read_text(errors="replace")
        except Exception:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in http_pattern.finditer(line):
                url = m.group(0)
                if url not in seen_urls:
                    seen_urls.add(url)
                    findings.append(Finding(
                        id="TRANS-005",
                        title="Hardcoded HTTP URL",
                        description=(
                            f"A plaintext HTTP URL ({url}) was found in a "
                            f"bundle file."
                        ),
                        severity=SeverityLevel.MEDIUM,
                        owasp_category="M5",
                        evidence=[Evidence(
                            file=rel, line=lineno, snippet=url,
                        )],
                        remediation=(
                            "Replace all HTTP URLs with HTTPS equivalents."
                        ),
                    ))

    return findings
