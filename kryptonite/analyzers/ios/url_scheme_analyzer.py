"""Analyze URL schemes and deep link exposure."""

from __future__ import annotations

from typing import TYPE_CHECKING

from kryptonite.core.finding import Evidence, Finding, SeverityLevel

if TYPE_CHECKING:
    from kryptonite.core.ipa_parser import AppContext


def run(ctx: AppContext) -> list[Finding]:
    """Examine CFBundleURLTypes and Universal Links configuration."""
    findings: list[Finding] = []
    plist = ctx.info_plist

    url_types = plist.get("CFBundleURLTypes", [])
    if not url_types:
        return findings

    all_schemes: list[str] = []

    for entry in url_types:
        if not isinstance(entry, dict):
            continue
        schemes = entry.get("CFBundleURLSchemes", [])
        name = entry.get("CFBundleURLName", "unnamed")

        for scheme in schemes:
            all_schemes.append(scheme)

            # Custom schemes (non-system) are risky
            system_schemes = {
                "http", "https", "mailto", "tel", "sms", "facetime",
                "facetime-audio", "maps", "itms", "itms-apps",
            }
            if scheme.lower() not in system_schemes:
                findings.append(Finding(
                    id="URL-001",
                    title=f"Custom URL Scheme: {scheme}://",
                    description=(
                        f"The app registers a custom URL scheme '{scheme}://'. "
                        f"Custom URL schemes can be hijacked by malicious apps "
                        f"and do not support origin validation like Universal "
                        f"Links."
                    ),
                    severity=SeverityLevel.MEDIUM,
                    owasp_category="M3",
                    evidence=[Evidence(
                        file="Info.plist",
                        snippet=f"CFBundleURLSchemes = [{scheme}], Name = {name}",
                    )],
                    remediation=(
                        "Migrate to Universal Links (Associated Domains) "
                        "which provide origin validation. If custom URL schemes "
                        "are required, validate all incoming parameters and "
                        "never pass sensitive data through URL scheme callbacks."
                    ),
                ))

    # ── Multiple URL schemes ─────────────────────────────────────
    custom_schemes = [s for s in all_schemes if s.lower() not in {
        "http", "https", "mailto", "tel", "sms",
    }]
    if len(custom_schemes) > 3:
        findings.append(Finding(
            id="URL-002",
            title="Excessive URL Schemes Registered",
            description=(
                f"The app registers {len(custom_schemes)} custom URL schemes: "
                f"{', '.join(custom_schemes[:6])}. Each scheme expands the "
                f"app's attack surface."
            ),
            severity=SeverityLevel.MEDIUM,
            owasp_category="M3",
            evidence=[Evidence(
                file="Info.plist",
                snippet=f"{len(custom_schemes)} custom URL schemes",
            )],
            remediation=(
                "Minimize the number of URL schemes. Prefer Universal Links."
            ),
        ))

    # ── Check for Universal Links (positive signal) ──────────────
    entitlements = ctx.entitlements
    associated_domains = entitlements.get("com.apple.developer.associated-domains", [])
    has_universal_links = any(
        d.startswith("applinks:") for d in associated_domains
    ) if associated_domains else False

    if custom_schemes and not has_universal_links:
        findings.append(Finding(
            id="URL-003",
            title="No Universal Links Configured",
            description=(
                "The app uses custom URL schemes but does not configure "
                "Universal Links (Associated Domains with applinks:). "
                "Universal Links provide cryptographic origin verification "
                "that custom URL schemes lack."
            ),
            severity=SeverityLevel.LOW,
            owasp_category="M3",
            evidence=[Evidence(
                file="Entitlements",
                snippet="No applinks: entries in associated-domains",
            )],
            remediation=(
                "Implement Universal Links via Associated Domains. "
                "See Apple's documentation on Supporting Universal Links."
            ),
        ))

    return findings
