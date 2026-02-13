"""Check binary protections for Android DEX and native libraries."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import TYPE_CHECKING

from kryptonite.core.finding import Evidence, Finding, SeverityLevel

if TYPE_CHECKING:
    from kryptonite.core.ipa_parser import AppContext

# ELF constants
_ELF_MAGIC = b"\x7fELF"


def _check_native_lib(lib_path: Path) -> list[Finding]:
    """Analyze an ELF .so file for basic security properties."""
    findings: list[Finding] = []
    lib_name = lib_path.name

    try:
        with open(lib_path, "rb") as fp:
            magic = fp.read(4)
            if magic != _ELF_MAGIC:
                return findings

            # Read ELF header to check for PIE (ET_DYN)
            fp.seek(16)  # e_type offset
            e_type = struct.unpack("<H", fp.read(2))[0]

            # ET_DYN (3) = shared object / PIE, ET_EXEC (2) = not PIE
            if e_type == 2:  # ET_EXEC
                findings.append(Finding(
                    id="ABIN-001",
                    title=f"Native Library Not PIE: {lib_name}",
                    description=(
                        f"The native library {lib_name} is compiled as a fixed "
                        f"executable (ET_EXEC), not as a position-independent "
                        f"shared object. ASLR cannot fully protect it."
                    ),
                    severity=SeverityLevel.HIGH,
                    owasp_category="M7",
                    evidence=[Evidence(
                        file=lib_name,
                        snippet=f"ELF type=ET_EXEC (not PIE)",
                    )],
                    remediation=(
                        "Compile native libraries with -fPIC and link as "
                        "shared objects. Modern NDK defaults handle this."
                    ),
                ))

            # Read full file to check for stack canary and debug symbols
            fp.seek(0)
            content = fp.read()

            # Stack canaries check
            has_canary = (
                b"__stack_chk_fail" in content or
                b"__stack_chk_guard" in content
            )
            if not has_canary:
                findings.append(Finding(
                    id="ABIN-002",
                    title=f"No Stack Canaries in {lib_name}",
                    description=(
                        f"The native library {lib_name} does not appear to "
                        f"use stack canaries (__stack_chk_fail/guard). Stack "
                        f"buffer overflows may be exploitable."
                    ),
                    severity=SeverityLevel.MEDIUM,
                    owasp_category="M7",
                    evidence=[Evidence(
                        file=lib_name,
                        snippet="No __stack_chk symbols found",
                    )],
                    remediation="Compile with -fstack-protector-strong or -fstack-protector-all.",
                ))

    except Exception:
        pass

    return findings


def run(ctx: AppContext) -> list[Finding]:
    """Analyze Android DEX and native binary protections."""
    findings: list[Finding] = []

    if ctx.platform != "android":
        return findings

    # ── DEX analysis ─────────────────────────────────────────────
    if not ctx.dex_files:
        findings.append(Finding(
            id="ABIN-000",
            title="No DEX Files Found",
            description="Could not locate classes.dex in the APK.",
            severity=SeverityLevel.INFO,
            owasp_category="M7",
            evidence=[],
            remediation="Ensure the APK contains valid DEX files.",
        ))
    else:
        # Multidex info
        if len(ctx.dex_files) > 1:
            findings.append(Finding(
                id="ABIN-003",
                title=f"Multidex Application ({len(ctx.dex_files)} DEX files)",
                description=(
                    f"The application contains {len(ctx.dex_files)} DEX files, "
                    f"indicating a large codebase. This is informational."
                ),
                severity=SeverityLevel.INFO,
                owasp_category="M7",
                evidence=[Evidence(
                    file="APK root",
                    snippet=f"{len(ctx.dex_files)} DEX files: "
                            + ", ".join(d.name for d in ctx.dex_files[:5]),
                )],
                remediation="No action needed. Consider code shrinking with R8/ProGuard.",
            ))

        # Check for ProGuard/R8 obfuscation indicators
        strings_set = set(ctx.binary_strings)
        proguard_indicators = [
            "proguard", "ProGuard", "r8", "R8",
        ]
        # If many single-letter class names, likely obfuscated
        single_letter_classes = [s for s in ctx.binary_strings
                                 if s.startswith("L") and len(s) <= 4 and "/" in s]
        has_obfuscation = (
            any(ind in strings_set for ind in proguard_indicators) or
            len(single_letter_classes) > 50
        )

        if not has_obfuscation:
            findings.append(Finding(
                id="ABIN-004",
                title="No Code Obfuscation Detected",
                description=(
                    "The application does not appear to use ProGuard or R8 "
                    "obfuscation. Class and method names are likely readable, "
                    "making reverse engineering easier."
                ),
                severity=SeverityLevel.LOW,
                owasp_category="M7",
                evidence=[Evidence(
                    file="classes.dex",
                    snippet="No obfuscation indicators found",
                )],
                remediation=(
                    "Enable R8/ProGuard in the release build configuration "
                    "(minifyEnabled true). Add appropriate ProGuard rules."
                ),
            ))

    # ── Native library analysis ──────────────────────────────────
    if ctx.native_libs:
        findings.append(Finding(
            id="ABIN-005",
            title=f"Native Libraries Present ({len(ctx.native_libs)})",
            description=(
                f"The app includes {len(ctx.native_libs)} native .so "
                f"libraries. Native code may contain memory safety "
                f"vulnerabilities."
            ),
            severity=SeverityLevel.INFO,
            owasp_category="M7",
            evidence=[Evidence(
                file="lib/",
                snippet=", ".join(p.name for p in ctx.native_libs[:10]),
            )],
            remediation="Audit native libraries for memory safety issues.",
        ))

        # Analyze each native library
        for lib in ctx.native_libs[:10]:  # Limit to 10
            findings.extend(_check_native_lib(lib))

    return findings
