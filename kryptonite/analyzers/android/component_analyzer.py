"""Analyze exported Android components and deep link exposure."""

from __future__ import annotations

from typing import TYPE_CHECKING

from kryptonite.core.finding import Evidence, Finding, SeverityLevel

if TYPE_CHECKING:
    from kryptonite.core.ipa_parser import AppContext


def run(ctx: AppContext) -> list[Finding]:
    """Examine exported components and deep link handlers."""
    findings: list[Finding] = []

    if ctx.platform != "android" or not ctx.android_manifest:
        return findings

    manifest = ctx.android_manifest

    # ── Exported components without permissions ──────────────────
    for comp_type in ("activity", "service", "receiver", "provider"):
        components = manifest.get(f"{comp_type}s", [])
        for comp in components:
            name = comp.get("name", "unknown")
            exported = comp.get("exported", False)
            implicitly_exported = comp.get("implicitly_exported", False)
            permission = comp.get("permission", "")
            intent_filters = comp.get("intent_filters", [])

            is_exported = exported or implicitly_exported

            if is_exported and not permission:
                # Skip main launcher activities — they must be exported
                is_launcher = any(
                    "android.intent.action.MAIN" in f.get("actions", [])
                    and "android.intent.category.LAUNCHER" in f.get("categories", [])
                    for f in intent_filters
                )
                if is_launcher:
                    continue

                severity = SeverityLevel.HIGH
                if comp_type == "provider":
                    severity = SeverityLevel.HIGH
                elif comp_type == "service":
                    severity = SeverityLevel.HIGH
                elif comp_type == "receiver":
                    severity = SeverityLevel.MEDIUM
                else:
                    severity = SeverityLevel.MEDIUM

                export_type = "explicitly" if exported else "implicitly (has intent-filter)"
                findings.append(Finding(
                    id="ACOMP-001",
                    title=f"Exported {comp_type.title()}: {name.split('.')[-1]}",
                    description=(
                        f"The {comp_type} '{name}' is {export_type} exported "
                        f"without a permission guard. Other apps can interact "
                        f"with it, potentially leading to data leakage or "
                        f"unauthorized actions."
                    ),
                    severity=severity,
                    owasp_category="M8",
                    evidence=[Evidence(
                        file="AndroidManifest.xml",
                        snippet=f"<{comp_type} android:name=\"{name}\" "
                                f"android:exported=\"true\" />",
                    )],
                    remediation=(
                        f"Add android:permission to restrict access, or set "
                        f"android:exported=\"false\" if the {comp_type} is "
                        f"not intended for external use."
                    ),
                ))

    # ── Deep link / Custom scheme analysis ───────────────────────
    all_schemes: list[str] = []
    system_schemes = {"http", "https", "mailto", "tel", "sms", "geo", "market"}

    for comp_type in ("activity",):
        for comp in manifest.get(f"{comp_type}s", []):
            for intent_filter in comp.get("intent_filters", []):
                data_schemes = intent_filter.get("data_schemes", [])
                data_hosts = intent_filter.get("data_hosts", [])

                for scheme in data_schemes:
                    all_schemes.append(scheme)
                    if scheme.lower() not in system_schemes:
                        comp_name = comp.get("name", "unknown").split(".")[-1]
                        findings.append(Finding(
                            id="ACOMP-002",
                            title=f"Custom URI Scheme: {scheme}://",
                            description=(
                                f"The activity '{comp_name}' handles the custom "
                                f"URI scheme '{scheme}://'. Custom schemes can "
                                f"be hijacked by malicious apps and do not "
                                f"provide origin validation."
                            ),
                            severity=SeverityLevel.MEDIUM,
                            owasp_category="M3",
                            evidence=[Evidence(
                                file="AndroidManifest.xml",
                                snippet=f"<data android:scheme=\"{scheme}\" /> "
                                        f"in {comp_name}",
                            )],
                            remediation=(
                                "Migrate to Android App Links (verified deep links) "
                                "which provide domain verification. If custom schemes "
                                "are required, validate all incoming parameters."
                            ),
                        ))

    # ── App Links verification ───────────────────────────────────
    has_app_links = any(
        "android.intent.action.VIEW" in f.get("actions", [])
        and any(s in ("http", "https") for s in f.get("data_schemes", []))
        and "android.intent.category.BROWSABLE" in f.get("categories", [])
        for comp in manifest.get("activitys", [])
        for f in comp.get("intent_filters", [])
    )

    custom_schemes = [s for s in all_schemes if s.lower() not in system_schemes]
    if custom_schemes and not has_app_links:
        findings.append(Finding(
            id="ACOMP-003",
            title="No Verified App Links Configured",
            description=(
                "The app uses custom URI schemes but does not configure "
                "Android App Links (verified HTTP intent filters). App Links "
                "provide domain ownership verification that custom schemes lack."
            ),
            severity=SeverityLevel.LOW,
            owasp_category="M3",
            evidence=[Evidence(
                file="AndroidManifest.xml",
                snippet=f"Custom schemes: {', '.join(custom_schemes[:5])}; "
                        f"no verified App Links",
            )],
            remediation=(
                "Implement Android App Links with autoVerify=\"true\" and "
                "host a Digital Asset Links JSON file on your domain."
            ),
        ))

    # ── Exported content providers ───────────────────────────────
    providers = manifest.get("providers", [])
    for prov in providers:
        name = prov.get("name", "unknown")
        exported = prov.get("exported", False) or prov.get("implicitly_exported", False)
        permission = prov.get("permission", "")

        if exported and not permission:
            findings.append(Finding(
                id="ACOMP-004",
                title=f"Exported Content Provider: {name.split('.')[-1]}",
                description=(
                    f"The content provider '{name}' is exported without "
                    f"permission restrictions. This may allow other apps "
                    f"to read or modify application data via content:// URIs."
                ),
                severity=SeverityLevel.HIGH,
                owasp_category="M9",
                evidence=[Evidence(
                    file="AndroidManifest.xml",
                    snippet=f"<provider android:name=\"{name}\" "
                            f"android:exported=\"true\" />",
                )],
                remediation=(
                    "Set android:exported=\"false\" or add android:permission / "
                    "android:readPermission / android:writePermission to restrict "
                    "access. Use grantUriPermissions for controlled sharing."
                ),
            ))

    return findings
