"""Audit Android permissions from AndroidManifest.xml."""

from __future__ import annotations

from typing import TYPE_CHECKING

from kryptonite.core.finding import Evidence, Finding, SeverityLevel

if TYPE_CHECKING:
    from kryptonite.core.ipa_parser import AppContext

# Android dangerous permissions and their risk levels
_DANGEROUS_PERMISSIONS: dict[str, tuple[str, SeverityLevel]] = {
    "android.permission.CAMERA":                    ("Camera",               SeverityLevel.MEDIUM),
    "android.permission.RECORD_AUDIO":              ("Microphone",           SeverityLevel.MEDIUM),
    "android.permission.ACCESS_FINE_LOCATION":      ("Fine Location",        SeverityLevel.HIGH),
    "android.permission.ACCESS_COARSE_LOCATION":    ("Coarse Location",      SeverityLevel.MEDIUM),
    "android.permission.ACCESS_BACKGROUND_LOCATION":("Background Location",  SeverityLevel.HIGH),
    "android.permission.READ_CONTACTS":             ("Read Contacts",        SeverityLevel.MEDIUM),
    "android.permission.WRITE_CONTACTS":            ("Write Contacts",       SeverityLevel.MEDIUM),
    "android.permission.READ_CALENDAR":             ("Read Calendar",        SeverityLevel.LOW),
    "android.permission.WRITE_CALENDAR":            ("Write Calendar",       SeverityLevel.LOW),
    "android.permission.READ_SMS":                  ("Read SMS",             SeverityLevel.HIGH),
    "android.permission.SEND_SMS":                  ("Send SMS",             SeverityLevel.HIGH),
    "android.permission.RECEIVE_SMS":               ("Receive SMS",          SeverityLevel.HIGH),
    "android.permission.READ_PHONE_STATE":          ("Phone State",          SeverityLevel.MEDIUM),
    "android.permission.READ_PHONE_NUMBERS":        ("Phone Numbers",        SeverityLevel.MEDIUM),
    "android.permission.CALL_PHONE":                ("Make Calls",           SeverityLevel.MEDIUM),
    "android.permission.READ_CALL_LOG":             ("Read Call Log",        SeverityLevel.HIGH),
    "android.permission.WRITE_CALL_LOG":            ("Write Call Log",       SeverityLevel.HIGH),
    "android.permission.READ_EXTERNAL_STORAGE":     ("Read Storage",         SeverityLevel.MEDIUM),
    "android.permission.WRITE_EXTERNAL_STORAGE":    ("Write Storage",        SeverityLevel.MEDIUM),
    "android.permission.ACCESS_MEDIA_LOCATION":     ("Media Location",       SeverityLevel.MEDIUM),
    "android.permission.BODY_SENSORS":              ("Body Sensors",         SeverityLevel.MEDIUM),
    "android.permission.ACTIVITY_RECOGNITION":      ("Activity Recognition", SeverityLevel.LOW),
    "android.permission.BLUETOOTH_CONNECT":         ("Bluetooth Connect",    SeverityLevel.LOW),
    "android.permission.BLUETOOTH_SCAN":            ("Bluetooth Scan",       SeverityLevel.LOW),
    "android.permission.NEARBY_WIFI_DEVICES":       ("Nearby WiFi",          SeverityLevel.LOW),
    "android.permission.POST_NOTIFICATIONS":        ("Notifications",        SeverityLevel.LOW),
    "android.permission.READ_MEDIA_IMAGES":         ("Read Images",          SeverityLevel.LOW),
    "android.permission.READ_MEDIA_VIDEO":          ("Read Video",           SeverityLevel.LOW),
    "android.permission.READ_MEDIA_AUDIO":          ("Read Audio",           SeverityLevel.LOW),
}

# Overly broad permissions that are almost always unnecessary
_OVERPRIVILEGED: dict[str, tuple[str, SeverityLevel]] = {
    "android.permission.SYSTEM_ALERT_WINDOW":   ("Draw Over Other Apps",     SeverityLevel.HIGH),
    "android.permission.WRITE_SETTINGS":        ("Modify System Settings",   SeverityLevel.HIGH),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("Install Packages",      SeverityLevel.HIGH),
    "android.permission.MANAGE_EXTERNAL_STORAGE":  ("Manage All Storage",    SeverityLevel.HIGH),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("Accessibility",       SeverityLevel.HIGH),
    "android.permission.BIND_DEVICE_ADMIN":     ("Device Admin",             SeverityLevel.HIGH),
    "android.permission.READ_LOGS":             ("Read System Logs",         SeverityLevel.HIGH),
}


def run(ctx: AppContext) -> list[Finding]:
    """Audit requested Android permissions."""
    findings: list[Finding] = []

    if ctx.platform != "android" or not ctx.android_manifest:
        return findings

    permissions = ctx.android_manifest.get("permissions", [])
    if not permissions:
        return findings

    requested_labels: list[str] = []
    high_risk_count = 0

    for perm in permissions:
        # Check dangerous permissions
        if perm in _DANGEROUS_PERMISSIONS:
            label, severity = _DANGEROUS_PERMISSIONS[perm]
            requested_labels.append(f"{label} ({perm.split('.')[-1]})")
            if severity in (SeverityLevel.HIGH, SeverityLevel.MEDIUM):
                high_risk_count += 1

        # Check overprivileged permissions
        if perm in _OVERPRIVILEGED:
            label, severity = _OVERPRIVILEGED[perm]
            findings.append(Finding(
                id="APERM-001",
                title=f"Overprivileged Permission: {label}",
                description=(
                    f"The app requests the {label} permission ({perm}), "
                    f"which is a powerful system permission that is rarely "
                    f"needed by standard applications."
                ),
                severity=severity,
                owasp_category="M6",
                evidence=[Evidence(
                    file="AndroidManifest.xml",
                    snippet=f'<uses-permission android:name="{perm}" />',
                )],
                remediation=(
                    f"Remove the {perm} permission unless absolutely "
                    f"necessary. Use more restrictive alternatives when "
                    f"available."
                ),
            ))

    # Flag excessive dangerous permissions
    if high_risk_count >= 8:
        findings.append(Finding(
            id="APERM-002",
            title="Excessive Dangerous Permissions",
            description=(
                f"The app requests {high_risk_count} dangerous permissions. "
                f"Excessive permissions increase the attack surface and may "
                f"indicate data over-collection."
            ),
            severity=SeverityLevel.MEDIUM,
            owasp_category="M6",
            evidence=[Evidence(
                file="AndroidManifest.xml",
                snippet=f"{high_risk_count} dangerous permissions requested",
            )],
            remediation=(
                "Review each permission and remove any that are not strictly "
                "necessary for core app functionality. Follow the principle "
                "of least privilege."
            ),
        ))

    # Informational summary
    if requested_labels:
        findings.append(Finding(
            id="APERM-003",
            title="Permissions Summary",
            description=(
                f"The app requests {len(permissions)} permissions "
                f"({len(requested_labels)} are dangerous/sensitive): "
                + ", ".join(requested_labels[:15])
                + ("..." if len(requested_labels) > 15 else "") + "."
            ),
            severity=SeverityLevel.INFO,
            owasp_category="M6",
            evidence=[Evidence(
                file="AndroidManifest.xml",
                snippet=f"{len(permissions)} total, {len(requested_labels)} dangerous",
            )],
            remediation="Review permissions for compliance with privacy regulations.",
        ))

    return findings
