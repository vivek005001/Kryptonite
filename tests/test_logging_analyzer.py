"""Unit tests for logging analyzer."""

import tempfile
from pathlib import Path

import pytest

from kryptonite.analyzers.logging_analyzer import run
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


def test_logging_analyzer_no_findings(mock_app_context):
    """Test that no findings are reported when no logging is present."""
    test_file = mock_app_context.app_dir / "code.java"
    test_file.write_text("some code without logging")

    mock_app_context.all_files = [test_file]

    findings = run(mock_app_context)
    assert len(findings) == 0


def test_logging_analyzer_nslog_in_binary(mock_app_context):
    """Test detection of NSLog in binary strings."""
    mock_app_context.binary_strings = [
        "some string",
        "NSLog(@\"Debug message\")",
        "another string"
    ]

    findings = run(mock_app_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "LOG-001"
    assert finding.title == "NSLog Usage Detected"
    assert finding.severity == SeverityLevel.MEDIUM


def test_logging_analyzer_android_log_in_binary(mock_app_context):
    """Test detection of Android Log calls in binary strings."""
    mock_app_context.binary_strings = [
        "Log.d(TAG, \"debug message\")",
        "Log.e(TAG, \"error\")"
    ]

    findings = run(mock_app_context)
    # Should find LOG-007 once (deduplicated)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "LOG-007"


def test_logging_analyzer_debug_in_file(mock_app_context):
    """Test detection of debug indicators in text files."""
    test_file = mock_app_context.app_dir / "config.plist"
    test_file.write_text("""
<key>isDebug</key>
<true/>
<key>debugMode</key>
<string>enabled</string>
""")

    mock_app_context.all_files = [test_file]

    findings = run(mock_app_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "LOG-004"
    assert finding.title == "Debug Menu / Debug Mode Indicator"


def test_logging_analyzer_multiple_logging(mock_app_context):
    """Test detection of multiple logging types."""
    mock_app_context.binary_strings = [
        "NSLog(@\"test\")",
        "printf(\"debug\")",
        "Log.v(TAG, \"verbose\")"
    ]

    findings = run(mock_app_context)
    finding_ids = {f.id for f in findings}
    assert "LOG-001" in finding_ids  # NSLog
    assert "LOG-003" in finding_ids  # printf
    assert "LOG-007" in finding_ids  # Android Log


def test_logging_analyzer_deduplication(mock_app_context):
    """Test that duplicate logging findings are deduplicated."""
    mock_app_context.binary_strings = [
        "NSLog(@\"first\")",
        "NSLog(@\"second\")"
    ]

    findings = run(mock_app_context)
    # Should only find one instance of LOG-001
    assert len(findings) == 1