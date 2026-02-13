"""Check Mach-O binary protections: PIE, ARC, stack canaries, stripping."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import TYPE_CHECKING

from kryptonite.core.finding import Evidence, Finding, SeverityLevel

if TYPE_CHECKING:
    from kryptonite.core.ipa_parser import AppContext

# Mach-O constants
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

MH_PIE = 0x200000  # MH_PIE flag in mach_header.flags


def _parse_macho_flags(binary_path: Path) -> int | None:
    """Extract mach_header flags from a Mach-O binary."""
    try:
        with open(binary_path, "rb") as fp:
            magic_bytes = fp.read(4)
            if len(magic_bytes) < 4:
                return None
            magic = struct.unpack("<I", magic_bytes)[0]

            # Handle fat binaries – skip to first arch
            if magic in (FAT_MAGIC, FAT_CIGAM):
                fp.seek(0)
                big_endian = magic == FAT_MAGIC
                fmt = ">" if big_endian else "<"
                fp.read(4)  # magic
                nfat = struct.unpack(f"{fmt}I", fp.read(4))[0]
                if nfat > 0:
                    # fat_arch: cpu_type(4), cpu_subtype(4), offset(4), size(4), align(4)
                    _cpu_type = fp.read(4)
                    _cpu_sub = fp.read(4)
                    offset = struct.unpack(f"{fmt}I", fp.read(4))[0]
                    fp.seek(offset)
                    magic_bytes = fp.read(4)
                    magic = struct.unpack("<I", magic_bytes)[0]

            swapped = magic in (MH_CIGAM, MH_CIGAM_64)
            is_64 = magic in (MH_MAGIC_64, MH_CIGAM_64)
            fmt = ">" if swapped else "<"

            if is_64:
                # 64-bit header: magic(4) cputype(4) cpusubtype(4)
                #   filetype(4) ncmds(4) sizeofcmds(4) flags(4) reserved(4)
                fp.read(4 + 4 + 4 + 4 + 4)  # skip to flags
                flags = struct.unpack(f"{fmt}I", fp.read(4))[0]
            else:
                # 32-bit header: same minus reserved
                fp.read(4 + 4 + 4 + 4 + 4)
                flags = struct.unpack(f"{fmt}I", fp.read(4))[0]

            return flags
    except Exception:
        return None


def run(ctx: AppContext) -> list[Finding]:
    """Analyze binary protections of the main executable."""
    findings: list[Finding] = []
    bp = ctx.binary_path

    if not bp or not bp.exists():
        findings.append(Finding(
            id="BIN-000",
            title="No Executable Binary Found",
            description="Could not locate the main Mach-O executable in the app bundle.",
            severity=SeverityLevel.INFO,
            owasp_category="M7",
            evidence=[],
            remediation="Ensure the IPA contains a valid Mach-O executable.",
        ))
        return findings

    binary_name = bp.name
    strings_set = set(ctx.binary_strings)

    # ── PIE (Position Independent Executable) ────────────────────
    flags = _parse_macho_flags(bp)
    if flags is not None and not (flags & MH_PIE):
        findings.append(Finding(
            id="BIN-001",
            title="Binary Not Compiled as PIE",
            description=(
                "The binary is not Position Independent Executable (PIE). "
                "ASLR cannot fully randomize the memory layout, making "
                "exploitation easier."
            ),
            severity=SeverityLevel.HIGH,
            owasp_category="M7",
            evidence=[Evidence(file=binary_name, snippet=f"flags=0x{flags:08x}, MH_PIE not set")],
            remediation="Compile with -fPIE / -pie linker flag. Xcode enables this by default.",
        ))
    elif flags is not None and (flags & MH_PIE):
        findings.append(Finding(
            id="BIN-001",
            title="PIE Enabled",
            description="The binary is compiled as PIE — ASLR is effective.",
            severity=SeverityLevel.INFO,
            owasp_category="M7",
            evidence=[Evidence(file=binary_name, snippet="PIE flag set")],
            remediation="No action needed.",
        ))

    # ── Stack canaries ───────────────────────────────────────────
    has_canary = any(
        s in strings_set
        for s in ("___stack_chk_fail", "___stack_chk_guard")
    ) or any("stack_chk" in s for s in ctx.binary_strings)

    if not has_canary:
        findings.append(Finding(
            id="BIN-002",
            title="Stack Canaries Not Detected",
            description=(
                "No stack canary symbols (___stack_chk_guard/fail) were found "
                "in the binary. Stack buffer overflows may be exploitable."
            ),
            severity=SeverityLevel.MEDIUM,
            owasp_category="M7",
            evidence=[Evidence(file=binary_name, snippet="No stack_chk symbols found")],
            remediation="Compile with -fstack-protector-all.",
        ))

    # ── ARC (Automatic Reference Counting) ───────────────────────
    has_arc = any("objc_release" in s or "objc_retain" in s or "objc_autoreleaseReturnValue" in s
                  for s in ctx.binary_strings)
    if not has_arc:
        findings.append(Finding(
            id="BIN-003",
            title="ARC (Automatic Reference Counting) Not Detected",
            description=(
                "No ARC-related symbols were found. Manual memory management "
                "is more prone to use-after-free and double-free vulnerabilities."
            ),
            severity=SeverityLevel.MEDIUM,
            owasp_category="M7",
            evidence=[Evidence(file=binary_name, snippet="No objc_release/retain symbols")],
            remediation="Enable ARC in Xcode build settings (-fobjc-arc).",
        ))

    # ── Encryption (App Store encryption flag) ───────────────────
    # Check for LC_ENCRYPTION_INFO presence via string heuristic
    has_encryption = any("cryptid" in s.lower() for s in ctx.binary_strings)
    if not has_encryption:
        findings.append(Finding(
            id="BIN-004",
            title="Binary May Not Be Encrypted",
            description=(
                "No encryption indicators were found. The binary may be "
                "a decrypted dump, making reverse engineering trivial."
            ),
            severity=SeverityLevel.LOW,
            owasp_category="M7",
            evidence=[Evidence(file=binary_name, snippet="No cryptid reference found")],
            remediation=(
                "Ensure the IPA is obtained from the App Store (encrypted). "
                "Consider additional obfuscation for sensitive logic."
            ),
        ))

    # ── Symbol stripping ─────────────────────────────────────────
    # A high number of Objective-C class/method names suggests unstripped
    objc_symbols = [s for s in ctx.binary_strings if s.startswith(("-[", "+["))]
    if len(objc_symbols) > 100:
        findings.append(Finding(
            id="BIN-005",
            title="Binary Contains Unstripped Symbols",
            description=(
                f"The binary contains {len(objc_symbols)} Objective-C "
                f"method symbols, making reverse engineering easier."
            ),
            severity=SeverityLevel.LOW,
            owasp_category="M7",
            evidence=[Evidence(
                file=binary_name,
                snippet=f"{len(objc_symbols)} ObjC symbols found (e.g. {objc_symbols[0][:80]})",
            )],
            remediation=(
                "Strip debug symbols in release builds. Use STRIP_INSTALLED_PRODUCT=YES "
                "in Xcode. Consider obfuscation for sensitive code."
            ),
        ))

    return findings
