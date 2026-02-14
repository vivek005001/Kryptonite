"""Unit tests for secrets analyzer."""

import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from kryptonite.analyzers.secrets_analyzer import run
from kryptonite.core.finding import SeverityLevel
from kryptonite.core.ipa_parser import AppContext


@pytest.fixture
def mock_app_context():
    """Create a mock AppContext with temporary directory."""
    temp_dir = Path(tempfile.mkdtemp())
    app_dir = temp_dir / "app"
    app_dir.mkdir()

    ctx = AppContext(
        ipa_path=temp_dir / "test.ipa",
        temp_dir=temp_dir,
        app_dir=app_dir,
        platform="ios",
        binary_strings=[]
    )
    yield ctx
    # Cleanup
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_secrets_analyzer_no_findings(mock_app_context):
    """Test that no findings are reported when no secrets are present."""
    # Create a text file without secrets
    test_file = mock_app_context.app_dir / "config.txt"
    test_file.write_text("some config value = 123\nanother = abc")

    mock_app_context.all_files = [test_file]

    findings = run(mock_app_context)
    assert len(findings) == 0


def test_secrets_analyzer_aws_key_in_file(mock_app_context):
    """Test detection of AWS access key in text file."""
    test_file = mock_app_context.app_dir / "config.json"
    test_file.write_text('{"aws_key": "AKIAIOSFODNN7EXAMPLE"}')

    mock_app_context.all_files = [test_file]

    findings = run(mock_app_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "SEC-001"
    assert finding.title == "AWS Access Key ID"
    assert finding.severity == SeverityLevel.CRITICAL
    assert len(finding.evidence) == 1
    assert finding.evidence[0].file == "config.json"
    assert finding.evidence[0].line == 1


def test_secrets_analyzer_private_key_in_binary(mock_app_context):
    """Test detection of private key in binary strings."""
    mock_app_context.binary_strings = [
        "some string",
        "-----BEGIN RSA PRIVATE KEY-----",
        "another string"
    ]

    findings = run(mock_app_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "SEC-006"
    assert finding.title == "Private Key Block (in binary)"
    assert finding.severity == SeverityLevel.CRITICAL


def test_secrets_analyzer_multiple_secrets(mock_app_context):
    """Test detection of multiple different secrets."""
    test_file = mock_app_context.app_dir / "secrets.py"
    test_file.write_text("""
api_key = "sk-proj-abc123456789012345678901234567890"
password = "SuperSecret123!"
firebase_api_key = "AIzaSyC-FAKE-KEY-1234567890abcdefghijklmnop"
""")

    mock_app_context.all_files = [test_file]
    mock_app_context.binary_strings = ["AKIAIOSFODNN7EXAMPLE"]

    findings = run(mock_app_context)
    # Should find API key, password (generic), Firebase key, and AWS key
    finding_ids = {f.id for f in findings}
    assert "SEC-001" in finding_ids  # AWS
    assert "SEC-005" in finding_ids  # Generic API key
    assert "SEC-003" in finding_ids  # Firebase


def test_secrets_analyzer_deduplication(mock_app_context):
    """Test that duplicate findings are deduplicated."""
    test_file = mock_app_context.app_dir / "duplicate.txt"
    test_file.write_text("AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE")

    mock_app_context.all_files = [test_file]

    findings = run(mock_app_context)
    # Should only find one instance
    assert len(findings) == 1