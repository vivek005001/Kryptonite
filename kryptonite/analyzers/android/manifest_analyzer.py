"""Analyze AndroidManifest.xml for security misconfigurations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from kryptonite.core.finding import Evidence, Finding, SeverityLevel

if TYPE_CHECKING:
    from kryptonite.core.ipa_parser import AppContext


def run(ctx: AppContext) -> list[Finding]:
    """Check AndroidManifest.xml for security misconfigurations."""
    findings: list[Finding] = []

    if ctx.platform != "android" or not ctx.android_manifest:
        return findings

    manifest = ctx.android_manifest

    # ── android:debuggable ───────────────────────────────────────
    if manifest.get("debuggable", False):
        findings.append(Finding(
            id="MANIFEST-001",
            title="Application is Debuggable",
            description=(
                "The application has android:debuggable set to true. "
                "This allows attackers to attach a debugger, inspect "
                "memory, and bypass security controls."
            ),
            severity=SeverityLevel.CRITICAL,
            owasp_category="M8",
            evidence=[Evidence(
                file="AndroidManifest.xml",
                snippet='android:debuggable="true"',
            )],
            remediation=(
                "Set android:debuggable to false in the release build. "
                "Ensure your build configuration uses a release build type "
                "which sets this automatically."
            ),
        ))

    # ── android:allowBackup ──────────────────────────────────────
    if manifest.get("allow_backup", True):
        findings.append(Finding(
            id="MANIFEST-002",
            title="Application Allows Backup",
            description=(
                "The application allows backup via adb (android:allowBackup "
                "is true or not set). An attacker with physical access or "
                "ADB connectivity can extract application data."
            ),
            severity=SeverityLevel.MEDIUM,
            owasp_category="M9",
            evidence=[Evidence(
                file="AndroidManifest.xml",
                snippet='android:allowBackup="true"',
            )],
            remediation=(
                "Set android:allowBackup to false in the <application> tag, "
                "or implement a BackupAgent with encryption for sensitive data."
            ),
        ))

    # ── android:usesCleartextTraffic ─────────────────────────────
    if manifest.get("uses_cleartext", False):
        findings.append(Finding(
            id="MANIFEST-003",
            title="Cleartext Traffic Allowed",
            description=(
                "The application has android:usesCleartextTraffic set to true, "
                "allowing unencrypted HTTP connections which can be intercepted."
            ),
            severity=SeverityLevel.HIGH,
            owasp_category="M5",
            evidence=[Evidence(
                file="AndroidManifest.xml",
                snippet='android:usesCleartextTraffic="true"',
            )],
            remediation=(
                "Set android:usesCleartextTraffic to false and use HTTPS "
                "for all network communication. Define a network security "
                "configuration if specific domains require exceptions."
            ),
        ))

    # ── Missing networkSecurityConfig ────────────────────────────
    if not manifest.get("network_security_config"):
        findings.append(Finding(
            id="MANIFEST-004",
            title="No Network Security Configuration",
            description=(
                "The application does not define a network security "
                "configuration (android:networkSecurityConfig). A "
                "network_security_config.xml enables certificate pinning, "
                "cleartext traffic restrictions, and custom trust anchors."
            ),
            severity=SeverityLevel.MEDIUM,
            owasp_category="M5",
            evidence=[Evidence(
                file="AndroidManifest.xml",
                snippet="android:networkSecurityConfig not set",
            )],
            remediation=(
                "Add a network_security_config.xml to restrict cleartext "
                "traffic, enable certificate pinning, and control trust anchors. "
                "Reference it in the <application> tag."
            ),
        ))

    # ── Low targetSdkVersion ─────────────────────────────────────
    target_sdk = manifest.get("target_sdk", "")
    try:
        target_sdk_int = int(target_sdk)
        if target_sdk_int < 28:
            findings.append(Finding(
                id="MANIFEST-005",
                title=f"Low Target SDK Version ({target_sdk_int})",
                description=(
                    f"The application targets SDK {target_sdk_int}, which is "
                    f"below Android 9 (SDK 28). Lower target SDKs miss "
                    f"important security defaults like cleartext traffic "
                    f"blocking and scoped storage."
                ),
                severity=SeverityLevel.MEDIUM,
                owasp_category="M8",
                evidence=[Evidence(
                    file="AndroidManifest.xml",
                    snippet=f"targetSdkVersion={target_sdk_int}",
                )],
                remediation=(
                    "Target SDK 33 or higher for maximum security defaults "
                    "and latest platform protections."
                ),
            ))
    except (ValueError, TypeError):
        pass

    return findings
