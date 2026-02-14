"""Unit tests for Android manifest analyzer."""

import tempfile
from pathlib import Path

import pytest

from kryptonite.analyzers.android.manifest_analyzer import run
from kryptonite.core.finding import SeverityLevel
from kryptonite.core.ipa_parser import AppContext


@pytest.fixture
def mock_android_context():
    """Create a mock AppContext for Android."""
    temp_dir = Path(tempfile.mkdtemp())
    app_dir = temp_dir / "app"
    app_dir.mkdir()

    ctx = AppContext(
        ipa_path=temp_dir / "test.apk",
        temp_dir=temp_dir,
        app_dir=app_dir,
        platform="android",
        binary_strings=[],
        android_manifest={}
    )
    yield ctx
    # Cleanup
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_manifest_analyzer_non_android(mock_android_context):
    """Test that analyzer returns no findings for non-Android platforms."""
    mock_android_context.platform = "ios"

    findings = run(mock_android_context)
    assert len(findings) == 0


def test_manifest_analyzer_no_manifest(mock_android_context):
    """Test that analyzer returns no findings when no manifest is present."""
    mock_android_context.android_manifest = None

    findings = run(mock_android_context)
    assert len(findings) == 0


def test_manifest_analyzer_debuggable(mock_android_context):
    """Test detection of debuggable application."""
    mock_android_context.android_manifest = {"debuggable": True, "network_security_config": True, "allow_backup": False}

    findings = run(mock_android_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "MANIFEST-001"
    assert finding.title == "Application is Debuggable"
    assert finding.severity == SeverityLevel.CRITICAL


def test_manifest_analyzer_allow_backup(mock_android_context):
    """Test detection of allowBackup enabled."""
    mock_android_context.android_manifest = {"allow_backup": True, "network_security_config": True}

    findings = run(mock_android_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "MANIFEST-002"
    assert finding.title == "Application Allows Backup"


def test_manifest_analyzer_cleartext_traffic(mock_android_context):
    """Test detection of cleartext traffic allowed."""
    mock_android_context.android_manifest = {"uses_cleartext": True, "network_security_config": True, "allow_backup": False}

    findings = run(mock_android_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "MANIFEST-003"
    assert finding.title == "Cleartext Traffic Allowed"


def test_manifest_analyzer_no_network_security_config(mock_android_context):
    """Test detection of missing network security config."""
    mock_android_context.android_manifest = {"allow_backup": False}

    findings = run(mock_android_context)
    # Should include MANIFEST-004
    finding_ids = {f.id for f in findings}
    assert "MANIFEST-004" in finding_ids


def test_manifest_analyzer_low_target_sdk(mock_android_context):
    """Test detection of low target SDK version."""
    mock_android_context.android_manifest = {"target_sdk": "25", "network_security_config": True, "allow_backup": False}

    findings = run(mock_android_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "MANIFEST-005"
    assert "25" in finding.title


def test_manifest_analyzer_multiple_issues(mock_android_context):
    """Test detection of multiple manifest issues."""
    mock_android_context.android_manifest = {
        "debuggable": True,
        "allow_backup": True,
        "uses_cleartext": True,
        "target_sdk": "25",
        "network_security_config": True
    }

    findings = run(mock_android_context)
    finding_ids = {f.id for f in findings}
    assert "MANIFEST-001" in finding_ids
    assert "MANIFEST-002" in finding_ids
    assert "MANIFEST-003" in finding_ids
    assert "MANIFEST-005" in finding_ids