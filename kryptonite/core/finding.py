"""Data structures for security findings."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class SeverityLevel(enum.Enum):
    """Severity levels for security findings, ordered from most to least severe."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def numeric(self) -> int:
        return {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1,
        }[self]

    def __lt__(self, other: SeverityLevel) -> bool:
        return self.numeric < other.numeric


@dataclass
class Evidence:
    """A piece of evidence supporting a finding."""

    file: str
    line: int | None = None
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line, "snippet": self.snippet}


@dataclass
class Finding:
    """A single security finding produced by an analyzer."""

    id: str
    title: str
    description: str
    severity: SeverityLevel
    owasp_category: str  # e.g. "M1"
    evidence: list[Evidence] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "owasp_category": self.owasp_category,
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation,
        }
