"""Audit Info.plist permissions and privacy-sensitive usage descriptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from kryptonite.core.finding import Evidence, Finding, SeverityLevel

if TYPE_CHECKING:
    from kryptonite.core.ipa_parser import AppContext

# Map of Info.plist permission keys → human-readable labels and risk.
_SENSITIVE_PERMISSIONS: dict[str, tuple[str, SeverityLevel]] = {
    "NSCameraUsageDescription":              ("Camera",              SeverityLevel.MEDIUM),
    "NSMicrophoneUsageDescription":          ("Microphone",          SeverityLevel.MEDIUM),
    "NSLocationAlwaysUsageDescription":      ("Location (Always)",   SeverityLevel.HIGH),
    "NSLocationAlwaysAndWhenInUseUsageDescription": ("Location (Always)", SeverityLevel.HIGH),
    "NSLocationWhenInUseUsageDescription":   ("Location (When In Use)", SeverityLevel.LOW),
    "NSContactsUsageDescription":            ("Contacts",            SeverityLevel.MEDIUM),
    "NSCalendarsUsageDescription":           ("Calendars",           SeverityLevel.LOW),
    "NSRemindersUsageDescription":           ("Reminders",           SeverityLevel.LOW),
    "NSPhotoLibraryUsageDescription":        ("Photos",              SeverityLevel.LOW),
    "NSPhotoLibraryAddUsageDescription":     ("Photos (Add Only)",   SeverityLevel.LOW),
    "NSHealthShareUsageDescription":         ("HealthKit (Read)",    SeverityLevel.HIGH),
    "NSHealthUpdateUsageDescription":        ("HealthKit (Write)",   SeverityLevel.HIGH),
    "NSMotionUsageDescription":              ("Motion & Fitness",    SeverityLevel.MEDIUM),
    "NSBluetoothAlwaysUsageDescription":     ("Bluetooth",           SeverityLevel.MEDIUM),
    "NSBluetoothPeripheralUsageDescription": ("Bluetooth Peripheral", SeverityLevel.MEDIUM),
    "NFCReaderUsageDescription":             ("NFC",                 SeverityLevel.LOW),
    "NSSpeechRecognitionUsageDescription":   ("Speech Recognition",  SeverityLevel.MEDIUM),
    "NSFaceIDUsageDescription":              ("Face ID",             SeverityLevel.MEDIUM),
    "NSLocalNetworkUsageDescription":        ("Local Network",       SeverityLevel.MEDIUM),
    "NSUserTrackingUsageDescription":        ("App Tracking (ATT)",  SeverityLevel.MEDIUM),
    "NSAppleMusicUsageDescription":          ("Media Library",       SeverityLevel.LOW),
    "NSSiriUsageDescription":                ("Siri",                SeverityLevel.LOW),
    "NSHomeKitUsageDescription":             ("HomeKit",             SeverityLevel.MEDIUM),
}


def run(ctx: AppContext) -> list[Finding]:
    """Audit requested permissions from Info.plist."""
    findings: list[Finding] = []
    plist = ctx.info_plist

    requested: list[str] = []

    for key, (label, severity) in _SENSITIVE_PERMISSIONS.items():
        value = plist.get(key)
        if value is not None:
            requested.append(f"{label} ({key})")

            # Flag if usage description is empty or generic
            if isinstance(value, str) and len(value.strip()) < 10:
                findings.append(Finding(
                    id="PERM-001",
                    title=f"Insufficient Usage Description for {label}",
                    description=(
                        f"The {label} permission ({key}) has a very short or "
                        f"empty usage description: \"{value}\". Apple may "
                        f"reject apps with vague privacy descriptions, and "
                        f"users cannot make informed consent decisions."
                    ),
                    severity=SeverityLevel.MEDIUM,
                    owasp_category="M6",
                    evidence=[Evidence(
                        file="Info.plist",
                        snippet=f'{key} = "{value}"',
                    )],
                    remediation=(
                        f"Provide a clear, specific usage description for "
                        f"the {label} permission explaining why the app "
                        f"needs this access."
                    ),
                ))

    # Flag apps requesting many high-risk permissions
    high_risk_perms = [
        key for key, (_, sev) in _SENSITIVE_PERMISSIONS.items()
        if plist.get(key) is not None and sev in (SeverityLevel.HIGH, SeverityLevel.MEDIUM)
    ]

    if len(high_risk_perms) >= 5:
        findings.append(Finding(
            id="PERM-002",
            title="Excessive Sensitive Permissions",
            description=(
                f"The app requests {len(high_risk_perms)} sensitive "
                f"permissions. Excessive permissions increase the attack "
                f"surface and may indicate data over-collection."
            ),
            severity=SeverityLevel.MEDIUM,
            owasp_category="M6",
            evidence=[Evidence(
                file="Info.plist",
                snippet=", ".join(high_risk_perms[:8]),
            )],
            remediation=(
                "Review each permission and remove any that are not "
                "strictly necessary for core app functionality. Follow "
                "the principle of least privilege."
            ),
        ))

    # Informational: list all requested permissions
    if requested:
        findings.append(Finding(
            id="PERM-003",
            title="Permissions Summary",
            description=(
                f"The app requests {len(requested)} permissions: "
                + ", ".join(requested) + "."
            ),
            severity=SeverityLevel.INFO,
            owasp_category="M6",
            evidence=[Evidence(
                file="Info.plist",
                snippet=f"{len(requested)} permissions requested",
            )],
            remediation="Review permissions for compliance with privacy regulations.",
        ))

    return findings
