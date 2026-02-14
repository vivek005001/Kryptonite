"""Detect insecure data storage patterns in the app bundle."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from kryptonite.core.finding import Evidence, Finding, SeverityLevel

if TYPE_CHECKING:
    from kryptonite.core.ipa_parser import AppContext


def run(ctx: AppContext) -> list[Finding]:
    """Scan for insecure data storage indicators."""
    findings: list[Finding] = []

    # ── Embedded database files ──────────────────────────────────
    db_extensions = {".sqlite", ".sqlite3", ".db", ".sqlitedb", ".realm"}
    for fpath in ctx.all_files:
        if fpath.suffix.lower() in db_extensions:
            rel = str(fpath.relative_to(ctx.app_dir))
            findings.append(Finding(
                id="DATA-001",
                title="Embedded Database File",
                description=(
                    f"A database file ({fpath.name}) is bundled with the app. "
                    f"If it contains sensitive data, it may be extracted from "
                    f"the IPA without jailbreaking."
                ),
                severity=SeverityLevel.MEDIUM,
                owasp_category="M9",
                evidence=[Evidence(file=rel, snippet=fpath.name)],
                remediation=(
                    "Do not ship pre-populated databases with sensitive data. "
                    "Encrypt databases using SQLCipher or Realm encryption. "
                    "Use NSFileProtectionComplete for data-at-rest protection."
                ),
            ))

    # ── Plist cache / data files ─────────────────────────────────
    for fpath in ctx.all_files:
        if fpath.suffix.lower() == ".plist" and fpath.name != "Info.plist":
            rel = str(fpath.relative_to(ctx.app_dir))
            try:
                import plistlib
                with open(fpath, "rb") as fp:
                    data = plistlib.load(fp)
                # Look for keys that suggest sensitive data
                sensitive_keys = {"password", "token", "secret", "key",
                                  "credential", "auth", "session", "cookie"}
                found_keys = []
                if isinstance(data, dict):
                    for k in data:
                        if any(sk in str(k).lower() for sk in sensitive_keys):
                            found_keys.append(str(k))
                if found_keys:
                    findings.append(Finding(
                        id="DATA-002",
                        title="Plist File Contains Sensitive Keys",
                        description=(
                            f"The plist file {fpath.name} contains keys that "
                            f"suggest sensitive data storage: {', '.join(found_keys[:5])}."
                        ),
                        severity=SeverityLevel.HIGH,
                        owasp_category="M9",
                        evidence=[Evidence(
                            file=rel,
                            snippet=f"Sensitive keys: {', '.join(found_keys[:5])}",
                        )],
                        remediation=(
                            "Move sensitive data to the iOS Keychain. "
                            "Never store credentials, tokens, or secrets in "
                            "property lists."
                        ),
                    ))
            except Exception:
                pass

    # ── NSUserDefaults patterns in binary ────────────────────────
    userdefaults_patterns = [
        re.compile(r"NSUserDefaults"),
        re.compile(r"standardUserDefaults"),
        re.compile(r"UserDefaults\.standard"),
    ]
    sensitive_store_patterns = [
        re.compile(r"""(?:password|token|secret|credential|session|auth)""", re.I),
    ]

    ud_found = False
    for s in ctx.binary_strings:
        if any(p.search(s) for p in userdefaults_patterns):
            ud_found = True
            break

    if ud_found:
        # Check if sensitive data keywords appear near UserDefaults usage
        sensitive_near_ud = any(
            any(sp.search(s) for sp in sensitive_store_patterns)
            and any(up.search(s) for up in userdefaults_patterns)
            for s in ctx.binary_strings
        )

        findings.append(Finding(
            id="DATA-003",
            title="NSUserDefaults Usage Detected",
            description=(
                "The app uses NSUserDefaults, which stores data in plaintext "
                "plist files on disk. "
                + ("Sensitive data keywords were found near UserDefaults references."
                   if sensitive_near_ud else
                   "Verify that no sensitive data is stored via UserDefaults.")
            ),
            severity=SeverityLevel.MEDIUM if sensitive_near_ud else SeverityLevel.LOW,
            owasp_category="M9",
            evidence=[Evidence(
                file="<binary>",
                snippet="NSUserDefaults / standardUserDefaults reference found",
            )],
            remediation=(
                "Do not store sensitive data in NSUserDefaults. "
                "Use the iOS Keychain (kSecClass) for credentials and "
                "tokens. Apply NSFileProtectionComplete to data files."
            ),
        ))

    # ── File protection entitlements ─────────────────────────────
    entitlements = ctx.entitlements
    dp_class = entitlements.get("com.apple.developer.default-data-protection", "")
    if dp_class and dp_class != "NSFileProtectionComplete":
        findings.append(Finding(
            id="DATA-004",
            title="Weak Data Protection Class",
            description=(
                f"Data protection is set to '{dp_class}' instead of "
                f"NSFileProtectionComplete. Files may be accessible when "
                f"the device is locked."
            ),
            severity=SeverityLevel.MEDIUM,
            owasp_category="M9",
            evidence=[Evidence(
                file="Entitlements",
                snippet=f"default-data-protection = {dp_class}",
            )],
            remediation=(
                "Set data protection to NSFileProtectionComplete to ensure "
                "files are only accessible when the device is unlocked."
            ),
        ))

    return findings
