"""Detect usage of weak or deprecated cryptographic algorithms."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from kryptonite.core.finding import Evidence, Finding, SeverityLevel

if TYPE_CHECKING:
    from kryptonite.core.ipa_parser import AppContext

# Patterns matched against binary strings and text files.
_WEAK_CRYPTO: list[tuple[str, str, re.Pattern[str], SeverityLevel, str]] = [
    (
        "CRYPTO-001",
        "MD5 Hash Usage",
        re.compile(r"\b(?:CC_MD5|MD5_Init|MD5_Update|MD5_Final|kCCHmacAlgMD5|CommonCrypto.*MD5|MessageDigest\.getInstance\(\"MD5\"\)|DigestUtils\.md5)"),
        SeverityLevel.MEDIUM,
        "MD5 is cryptographically broken and should not be used for "
        "security-sensitive operations. Migrate to SHA-256 or SHA-3.",
    ),
    (
        "CRYPTO-002",
        "SHA-1 Hash Usage",
        re.compile(r"\b(?:CC_SHA1|SHA1_Init|SHA1_Update|SHA1_Final|kCCHmacAlgSHA1|MessageDigest\.getInstance\(\"SHA-?1\"\))"),
        SeverityLevel.MEDIUM,
        "SHA-1 is deprecated due to known collision attacks. "
        "Use SHA-256 or SHA-3 for hashing.",
    ),
    (
        "CRYPTO-003",
        "DES / 3DES Encryption",
        re.compile(r"\b(?:kCCAlgorithmDES|kCCAlgorithm3DES|DES_ecb_encrypt|DES_cbc_encrypt|DESede|DES/CBC|DES/ECB)"),
        SeverityLevel.HIGH,
        "DES and 3DES are deprecated. Migrate to AES-256 with GCM mode.",
    ),
    (
        "CRYPTO-004",
        "RC4 Stream Cipher",
        re.compile(r"\b(?:kCCAlgorithmRC4|RC4_set_key|arc4random_stir|ARCFOUR)"),
        SeverityLevel.HIGH,
        "RC4 is insecure. Replace with AES-GCM or ChaCha20-Poly1305.",
    ),
    (
        "CRYPTO-005",
        "ECB Block Cipher Mode",
        re.compile(r"\b(?:kCCModeECB|ECB_MODE|\.ECB\b|AES/ECB|DES/ECB)"),
        SeverityLevel.HIGH,
        "ECB mode does not provide semantic security; identical plaintext "
        "blocks produce identical ciphertext. Use CBC, CTR, or GCM mode.",
    ),
    (
        "CRYPTO-006",
        "Hardcoded Encryption Key",
        re.compile(r"""(?:encryption[_\s]?key|aes[_\s]?key|crypto[_\s]?key)\s*[:=]\s*['"]([^'"]{8,})['"]""", re.I),
        SeverityLevel.CRITICAL,
        "Encryption keys must never be hardcoded. "
        + "Use the Android Keystore or a key derivation function "
          "(PBKDF2, Argon2) for key management."
        if False else  # Always use full message below
        "Encryption keys must never be hardcoded. Use the iOS Keychain, "
        "Android Keystore, or a key derivation function (PBKDF2, Argon2).",
    ),
    (
        "CRYPTO-007",
        "Hardcoded IV / Nonce",
        re.compile(r"""(?:iv|nonce|initialization.vector)\s*[:=]\s*['"]([^'"]{8,})['"]""", re.I),
        SeverityLevel.HIGH,
        "IVs and nonces must be randomly generated for each encryption "
        "operation. Hardcoded values destroy confidentiality.",
    ),
    (
        "CRYPTO-008",
        "Insecure Random Number Generator",
        re.compile(r"\b(?:srand|rand\(\)|random\(\)|drand48|java\.util\.Random|Math\.random)\b"),
        SeverityLevel.MEDIUM,
        "Use SecRandomCopyBytes (iOS), java.security.SecureRandom (Android), "
        "or arc4random_buf for cryptographically secure random numbers.",
    ),
]


def run(ctx: AppContext) -> list[Finding]:
    """Scan binary strings and text files for weak cryptography usage."""
    findings: list[Finding] = []
    seen: set[str] = set()

    # ── Binary strings ───────────────────────────────────────────
    for idx, s in enumerate(ctx.binary_strings):
        for fid, title, pattern, severity, remediation in _WEAK_CRYPTO:
            if pattern.search(s):
                key = f"{fid}:binary:{s[:60]}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    id=fid,
                    title=title,
                    description=(
                        f"Usage of {title.lower()} detected in the "
                        f"application binary."
                    ),
                    severity=severity,
                    owasp_category="M10",
                    evidence=[Evidence(
                        file="<binary>",
                        line=idx + 1,
                        snippet=s.strip()[:200],
                    )],
                    remediation=remediation,
                ))

    # ── Text files ───────────────────────────────────────────────
    for fpath in ctx.text_files():
        rel = str(fpath.relative_to(ctx.app_dir))
        try:
            text = fpath.read_text(errors="replace")
        except Exception:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for fid, title, pattern, severity, remediation in _WEAK_CRYPTO:
                if pattern.search(line):
                    key = f"{fid}:{rel}:{lineno}"
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(Finding(
                        id=fid,
                        title=title,
                        description=(
                            f"Usage of {title.lower()} detected in "
                            f"configuration/source file."
                        ),
                        severity=severity,
                        owasp_category="M10",
                        evidence=[Evidence(
                            file=rel, line=lineno,
                            snippet=line.strip()[:200],
                        )],
                        remediation=remediation,
                    ))

    return findings
