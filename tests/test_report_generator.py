"""Unit tests for report generator."""

import json
import tempfile
from pathlib import Path

import pytest

from kryptonite.core.finding import Finding, SeverityLevel
from kryptonite.reports.report_generator import (
    _build_report_data,
    _risk_label,
    _risk_score,
    generate_html,
    generate_json,
)


def test_risk_score_no_findings():
    """Test risk score calculation with no findings."""
    assert _risk_score([]) == 0


def test_risk_score_various_severities():
    """Test risk score calculation with different severity levels."""
    findings = [
        Finding("TEST-001", "Test", "desc", SeverityLevel.CRITICAL, "M1"),
        Finding("TEST-002", "Test", "desc", SeverityLevel.HIGH, "M1"),
        Finding("TEST-003", "Test", "desc", SeverityLevel.MEDIUM, "M1"),
        Finding("TEST-004", "Test", "desc", SeverityLevel.LOW, "M1"),
        Finding("TEST-005", "Test", "desc", SeverityLevel.INFO, "M1"),
    ]
    score = _risk_score(findings)
    # 25 + 15 + 8 + 3 + 0 = 51
    assert score == 51


def test_risk_score_capped_at_100():
    """Test that risk score is capped at 100."""
    findings = [Finding("TEST-001", "Test", "desc", SeverityLevel.CRITICAL, "M1")] * 5
    # 5 * 25 = 125, but capped at 100
    assert _risk_score(findings) == 100


def test_risk_label():
    """Test risk label assignment."""
    assert _risk_label(0) == "None"
    assert _risk_label(10) == "Low"
    assert _risk_label(30) == "Medium"
    assert _risk_label(60) == "High"
    assert _risk_label(80) == "Critical"


def test_build_report_data():
    """Test building report data structure."""
    findings = [
        Finding("TEST-001", "Test Finding", "Description", SeverityLevel.HIGH, "M1"),
    ]
    app_info = {
        "platform": "iOS",
        "bundle_name": "TestApp",
        "bundle_id": "com.test.app",
        "bundle_version": "1.0.0",
        "min_os_version": "14.0",
        "app_file": "test.ipa",
        "total_files": "10",
    }

    data = _build_report_data(findings, app_info)

    assert data["app_info"] == app_info
    assert len(data["findings"]) == 1
    assert data["summary"]["total_findings"] == 1
    assert data["summary"]["risk_score"] == 15  # HIGH = 15
    assert data["summary"]["risk_label"] == "Low"
    assert data["summary"]["severity_breakdown"]["High"] == 1


def test_generate_json():
    """Test JSON report generation."""
    findings = [
        Finding("TEST-001", "Test", "desc", SeverityLevel.MEDIUM, "M1"),
    ]
    app_info = {"platform": "iOS", "bundle_name": "Test"}

    with tempfile.TemporaryDirectory() as temp_dir:
        output_path = Path(temp_dir) / "report.json"
        result_path = generate_json(findings, app_info, output_path)

        assert result_path == output_path
        assert output_path.exists()

        with open(output_path) as f:
            data = json.load(f)
            assert data["app_info"]["platform"] == "iOS"
            assert len(data["findings"]) == 1


def test_generate_html():
    """Test HTML report generation."""
    findings = [
        Finding("TEST-001", "Test", "desc", SeverityLevel.LOW, "M1"),
    ]
    app_info = {"platform": "Android", "bundle_name": "Test"}

    with tempfile.TemporaryDirectory() as temp_dir:
        output_path = Path(temp_dir) / "report.html"
        result_path = generate_html(findings, app_info, output_path)

        assert result_path == output_path
        assert output_path.exists()

        html_content = output_path.read_text()
        assert "Test" in html_content
        assert "<html" in html_content