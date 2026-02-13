"""Detect insecure data storage patterns in Android applications."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from kryptonite.core.finding import Evidence, Finding, SeverityLevel

if TYPE_CHECKING:
    from kryptonite.core.ipa_parser import AppContext


def run(ctx: AppContext) -> list[Finding]:
    """Scan for insecure data storage patterns in Android APKs."""
    findings: list[Finding] = []

    if ctx.platform != "android":
        return findings

    # ── Embedded database files ──────────────────────────────────
    db_extensions = {".sqlite", ".sqlite3", ".db", ".sqlitedb", ".realm"}
    for fpath in ctx.all_files:
        if fpath.suffix.lower() in db_extensions:
            rel = str(fpath.relative_to(ctx.app_dir))
            findings.append(Finding(
                id="ADATA-001",
                title="Embedded Database File",
                description=(
                    f"A database file ({fpath.name}) is bundled with the app. "
                    f"If it contains sensitive data, it may be extracted from "
                    f"the APK."
                ),
                severity=SeverityLevel.MEDIUM,
                owasp_category="M9",
                evidence=[Evidence(file=rel, snippet=fpath.name)],
                remediation=(
                    "Do not ship pre-populated databases with sensitive data. "
                    "Encrypt databases using SQLCipher or Realm encryption. "
                    "Use Android's EncryptedSharedPreferences for small data."
                ),
            ))

    # ── SharedPreferences patterns in DEX strings ────────────────
    sp_patterns = [
        re.compile(r"SharedPreferences"),
        re.compile(r"getSharedPreferences"),
        re.compile(r"PreferenceManager"),
    ]
    sensitive_patterns = [
        re.compile(r"(?:password|token|secret|credential|session|auth|key)", re.I),
    ]

    sp_found = any(
        any(p.search(s) for p in sp_patterns)
        for s in ctx.binary_strings
    )

    if sp_found:
        sensitive_near_sp = any(
            any(sp.search(s) for sp in sensitive_patterns)
            and any(up.search(s) for up in sp_patterns)
            for s in ctx.binary_strings
        )

        findings.append(Finding(
            id="ADATA-002",
            title="SharedPreferences Usage Detected",
            description=(
                "The app uses SharedPreferences, which stores data in "
                "plaintext XML files on disk. "
                + ("Sensitive data keywords were found near SharedPreferences "
                   "references." if sensitive_near_sp else
                   "Verify that no sensitive data is stored via SharedPreferences.")
            ),
            severity=SeverityLevel.MEDIUM if sensitive_near_sp else SeverityLevel.LOW,
            owasp_category="M9",
            evidence=[Evidence(
                file="<dex>",
                snippet="SharedPreferences / getSharedPreferences reference found",
            )],
            remediation=(
                "Use EncryptedSharedPreferences from AndroidX Security "
                "library for sensitive data. For credentials and tokens, "
                "use the Android Keystore system."
            ),
        ))

    # ── External storage usage patterns ──────────────────────────
    ext_storage_patterns = [
        "getExternalStorageDirectory",
        "getExternalFilesDir",
        "getExternalCacheDir",
        "Environment.getExternalStorage",
        "EXTERNAL_STORAGE",
    ]
    found_ext = [p for p in ext_storage_patterns
                 if any(p in s for s in ctx.binary_strings)]

    if found_ext:
        findings.append(Finding(
            id="ADATA-003",
            title="External Storage Usage Detected",
            description=(
                "The app uses external storage APIs, which store data "
                "in world-readable locations. Any app with storage "
                "permissions can read this data."
            ),
            severity=SeverityLevel.MEDIUM,
            owasp_category="M9",
            evidence=[Evidence(
                file="<dex>",
                snippet=f"APIs found: {', '.join(found_ext[:3])}",
            )],
            remediation=(
                "Use internal storage (getFilesDir/getCacheDir) for "
                "sensitive data. If external storage is required, use "
                "scoped storage APIs (Android 10+) and encrypt files."
            ),
        ))

    # ── World-readable file mode patterns ────────────────────────
    world_readable_patterns = [
        "MODE_WORLD_READABLE",
        "MODE_WORLD_WRITEABLE",
        "0666", "0777",
    ]
    found_wr = [p for p in world_readable_patterns
                if any(p in s for s in ctx.binary_strings)]

    if found_wr:
        findings.append(Finding(
            id="ADATA-004",
            title="World-Readable/Writable File Mode",
            description=(
                "The app may create files with world-readable or "
                "world-writable permissions, exposing data to other "
                "applications."
            ),
            severity=SeverityLevel.HIGH,
            owasp_category="M9",
            evidence=[Evidence(
                file="<dex>",
                snippet=f"Patterns found: {', '.join(found_wr[:3])}",
            )],
            remediation=(
                "Use MODE_PRIVATE for all file operations. Never use "
                "MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE."
            ),
        ))

    # ── WebView data storage ─────────────────────────────────────
    webview_storage_patterns = [
        "setDomStorageEnabled",
        "setDatabaseEnabled",
        "setAllowFileAccess",
        "setAllowContentAccess",
        "setAllowFileAccessFromFileURLs",
        "setAllowUniversalAccessFromFileURLs",
    ]
    found_wv = [p for p in webview_storage_patterns
                if any(p in s for s in ctx.binary_strings)]

    if found_wv:
        risky = [p for p in found_wv if "Universal" in p or "FromFile" in p]
        if risky:
            findings.append(Finding(
                id="ADATA-005",
                title="WebView File Access Enabled",
                description=(
                    "The app enables WebView file access APIs that could "
                    "allow malicious web content to read local files."
                ),
                severity=SeverityLevel.HIGH,
                owasp_category="M9",
                evidence=[Evidence(
                    file="<dex>",
                    snippet=f"Risky WebView APIs: {', '.join(risky)}",
                )],
                remediation=(
                    "Disable setAllowFileAccessFromFileURLs and "
                    "setAllowUniversalAccessFromFileURLs. Use "
                    "setAllowFileAccess(false) when not needed."
                ),
            ))

    return findings
