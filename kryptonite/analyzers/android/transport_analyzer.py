"""Analyze Android network security configuration and transport security."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from xml.etree import ElementTree

from kryptonite.core.finding import Evidence, Finding, SeverityLevel

if TYPE_CHECKING:
    from kryptonite.core.ipa_parser import AppContext


def run(ctx: AppContext) -> list[Finding]:
    """Check Android network security config and scan for insecure URLs."""
    findings: list[Finding] = []

    if ctx.platform != "android":
        return findings

    manifest = ctx.android_manifest

    # ── network_security_config.xml analysis ─────────────────────
    nsc_ref = manifest.get("network_security_config", "")
    if nsc_ref:
        # Try to find and parse the network security config
        nsc_candidates = [
            p for p in ctx.all_files
            if p.name == "network_security_config.xml"
        ]
        for nsc_path in nsc_candidates:
            try:
                text = nsc_path.read_text(errors="replace")
                _analyze_nsc(text, findings)
            except Exception:
                pass

    # ── Hardcoded HTTP URLs in DEX strings ───────────────────────
    http_pattern = re.compile(r"http://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}")
    seen_urls: set[str] = set()

    for idx, s in enumerate(ctx.binary_strings):
        for m in http_pattern.finditer(s):
            url = m.group(0)
            if url not in seen_urls:
                seen_urls.add(url)
                findings.append(Finding(
                    id="ATRANS-001",
                    title="Hardcoded HTTP URL",
                    description=(
                        f"A plaintext HTTP URL ({url}) was found in the "
                        f"DEX bytecode. Data transmitted over HTTP is "
                        f"susceptible to interception."
                    ),
                    severity=SeverityLevel.MEDIUM,
                    owasp_category="M5",
                    evidence=[Evidence(
                        file="<dex>", line=idx + 1, snippet=url,
                    )],
                    remediation="Replace all HTTP URLs with HTTPS equivalents.",
                ))

    # In text/config files
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
                        id="ATRANS-001",
                        title="Hardcoded HTTP URL",
                        description=(
                            f"A plaintext HTTP URL ({url}) was found in a "
                            f"bundled file."
                        ),
                        severity=SeverityLevel.MEDIUM,
                        owasp_category="M5",
                        evidence=[Evidence(
                            file=rel, line=lineno, snippet=url,
                        )],
                        remediation="Replace all HTTP URLs with HTTPS equivalents.",
                    ))

    # ── Certificate pinning patterns ─────────────────────────────
    pin_patterns = [
        "CertificatePinner", "certificate-pinning",
        "sha256/", "TrustManagerFactory",
        "X509TrustManager", "okhttp3.CertificatePinner",
    ]
    has_pinning = any(
        any(p in s for p in pin_patterns)
        for s in ctx.binary_strings
    )
    if not has_pinning:
        findings.append(Finding(
            id="ATRANS-002",
            title="No Certificate Pinning Detected",
            description=(
                "No evidence of certificate pinning was found in the "
                "application. Without pinning, the app is vulnerable to "
                "MITM attacks using rogue CA certificates."
            ),
            severity=SeverityLevel.MEDIUM,
            owasp_category="M5",
            evidence=[Evidence(
                file="<dex>",
                snippet="No CertificatePinner or TrustManager patterns found",
            )],
            remediation=(
                "Implement certificate pinning using OkHttp's "
                "CertificatePinner, a network_security_config.xml with "
                "<pin-set>, or TrustManagerFactory."
            ),
        ))

    return findings


def _analyze_nsc(xml_text: str, findings: list[Finding]) -> None:
    """Analyze a network_security_config.xml for weaknesses."""
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return

    # Check base config
    base = root.find("base-config")
    if base is not None:
        cleartext = base.get("cleartextTrafficPermitted", "")
        if cleartext.lower() == "true":
            findings.append(Finding(
                id="ATRANS-003",
                title="Network Security Config Allows Cleartext Globally",
                description=(
                    "The network_security_config.xml base-config allows "
                    "cleartext traffic for all domains."
                ),
                severity=SeverityLevel.HIGH,
                owasp_category="M5",
                evidence=[Evidence(
                    file="network_security_config.xml",
                    snippet='cleartextTrafficPermitted="true" in base-config',
                )],
                remediation=(
                    "Set cleartextTrafficPermitted to false in base-config. "
                    "Add domain-specific exceptions only when necessary."
                ),
            ))

        # Check for user CA trust
        trust_anchors = base.find("trust-anchors")
        if trust_anchors is not None:
            for cert in trust_anchors.findall("certificates"):
                src = cert.get("src", "")
                if src == "user":
                    findings.append(Finding(
                        id="ATRANS-004",
                        title="Base Config Trusts User-Installed Certificates",
                        description=(
                            "The network_security_config.xml trusts "
                            "user-installed CA certificates in the base "
                            "configuration. This enables MITM attacks on "
                            "rooted devices."
                        ),
                        severity=SeverityLevel.HIGH,
                        owasp_category="M5",
                        evidence=[Evidence(
                            file="network_security_config.xml",
                            snippet='<certificates src="user" /> in base-config',
                        )],
                        remediation=(
                            "Remove user certificate trust from the base "
                            "config. Only use system certificates."
                        ),
                    ))

    # Check domain configs for cleartext
    for domain_config in root.findall("domain-config"):
        cleartext = domain_config.get("cleartextTrafficPermitted", "")
        domains = [d.text or "" for d in domain_config.findall("domain")]
        if cleartext.lower() == "true" and domains:
            findings.append(Finding(
                id="ATRANS-005",
                title=f"Cleartext Allowed for: {', '.join(domains[:3])}",
                description=(
                    f"The network_security_config.xml allows cleartext "
                    f"traffic for domain(s): {', '.join(domains[:5])}."
                ),
                severity=SeverityLevel.MEDIUM,
                owasp_category="M5",
                evidence=[Evidence(
                    file="network_security_config.xml",
                    snippet=f"cleartext domain exceptions: {', '.join(domains[:3])}",
                )],
                remediation=(
                    "Migrate these domains to HTTPS and remove cleartext "
                    "exceptions."
                ),
            ))
