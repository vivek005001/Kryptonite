"""Unit tests for core finding classes."""

import pytest

from kryptonite.core.finding import Evidence, Finding, SeverityLevel


def test_severity_level_numeric():
    """Test severity level numeric values."""
    assert SeverityLevel.CRITICAL.numeric == 5
    assert SeverityLevel.HIGH.numeric == 4
    assert SeverityLevel.MEDIUM.numeric == 3
    assert SeverityLevel.LOW.numeric == 2
    assert SeverityLevel.INFO.numeric == 1


def test_severity_level_lt():
    """Test severity level comparison."""
    assert SeverityLevel.CRITICAL > SeverityLevel.HIGH
    assert SeverityLevel.LOW < SeverityLevel.MEDIUM
    assert not (SeverityLevel.INFO < SeverityLevel.INFO)


def test_evidence_to_dict():
    """Test Evidence to_dict method."""
    evidence = Evidence(file="test.txt", line=10, snippet="code")
    data = evidence.to_dict()
    assert data == {"file": "test.txt", "line": 10, "snippet": "code"}


def test_evidence_to_dict_no_line():
    """Test Evidence to_dict with no line number."""
    evidence = Evidence(file="binary", snippet="data")
    data = evidence.to_dict()
    assert data == {"file": "binary", "line": None, "snippet": "data"}


def test_finding_to_dict():
    """Test Finding to_dict method."""
    finding = Finding(
        id="TEST-001",
        title="Test Finding",
        description="A test finding",
        severity=SeverityLevel.HIGH,
        owasp_category="M1",
        evidence=[Evidence(file="test.txt", line=5, snippet="bad code")],
        remediation="Fix it"
    )
    data = finding.to_dict()
    expected = {
        "id": "TEST-001",
        "title": "Test Finding",
        "description": "A test finding",
        "severity": "High",
        "owasp_category": "M1",
        "evidence": [{"file": "test.txt", "line": 5, "snippet": "bad code"}],
        "remediation": "Fix it"
    }
    assert data == expected


def test_finding_minimal():
    """Test Finding with minimal required fields."""
    finding = Finding(
        id="TEST-002",
        title="Minimal",
        description="desc",
        severity=SeverityLevel.LOW,
        owasp_category="M2"
    )
    assert finding.evidence == []
    assert finding.remediation == ""