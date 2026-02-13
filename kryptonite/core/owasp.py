"""OWASP Mobile Top 10 (2024) category definitions."""

from __future__ import annotations

import enum


class OwaspCategory(enum.Enum):
    """OWASP Mobile Top 10 — 2024 edition."""

    M1 = ("M1", "Improper Credential Usage",
           "Hardcoded credentials, insecure credential storage, or improper "
           "use of biometric APIs.")
    M2 = ("M2", "Inadequate Supply Chain Security",
           "Third-party libraries with known vulnerabilities, unsigned code, "
           "or unverified SDKs.")
    M3 = ("M3", "Insecure Authentication/Authorization",
           "Weak authentication mechanisms, missing session management, "
           "or insecure deep-link handling.")
    M4 = ("M4", "Insufficient Input/Output Validation",
           "SQL injection, XSS, path traversal, or other injection attacks "
           "via unvalidated input.")
    M5 = ("M5", "Insecure Communication",
           "Cleartext traffic, disabled certificate pinning, or weak TLS "
           "configurations.")
    M6 = ("M6", "Inadequate Privacy Controls",
           "Excessive permissions, PII leakage, or missing privacy "
           "disclosures.")
    M7 = ("M7", "Insufficient Binary Protections",
           "Missing PIE, stack canaries, ARC, or code stripping; lack of "
           "obfuscation or anti-tamper controls.")
    M8 = ("M8", "Security Misconfiguration",
           "Debug logging in production builds, insecure default settings, "
           "or exported components without restrictions.")
    M9 = ("M9", "Insecure Data Storage",
           "Sensitive data stored in plaintext plists, SQLite databases, "
           "or NSUserDefaults without protection.")
    M10 = ("M10", "Insufficient Cryptography",
            "Use of weak/deprecated algorithms (MD5, SHA-1, DES, RC4), "
            "hardcoded keys, or insufficient key lengths.")

    def __init__(self, code: str, title: str, description: str) -> None:
        self.code = code
        self.category_title = title
        self.category_description = description

    @classmethod
    def by_code(cls, code: str) -> OwaspCategory:
        """Look up a category by its short code, e.g. 'M1'."""
        for member in cls:
            if member.code == code:
                return member
        raise ValueError(f"Unknown OWASP category code: {code}")

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "title": self.category_title,
            "description": self.category_description,
        }
