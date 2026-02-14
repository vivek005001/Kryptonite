"""Unit tests for Android permissions analyzer."""

import tempfile
from pathlib import Path

import pytest

from kryptonite.analyzers.android.permissions_analyzer import run
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


def test_permissions_analyzer_non_android(mock_android_context):
    """Test that analyzer returns no findings for non-Android platforms."""
    mock_android_context.platform = "ios"

    findings = run(mock_android_context)
    assert len(findings) == 0


def test_permissions_analyzer_no_permissions(mock_android_context):
    """Test that analyzer returns no findings when no permissions are present."""
    mock_android_context.android_manifest = {"permissions": []}

    findings = run(mock_android_context)
    assert len(findings) == 0


def test_permissions_analyzer_overprivileged_permission(mock_android_context):
    """Test detection of overprivileged permissions."""
    mock_android_context.android_manifest = {
        "permissions": ["android.permission.SYSTEM_ALERT_WINDOW"]
    }

    findings = run(mock_android_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "APERM-001"
    assert "Draw Over Other Apps" in finding.title


def test_permissions_analyzer_excessive_dangerous_permissions(mock_android_context):
    """Test detection of excessive dangerous permissions."""
    # Create 8+ dangerous permissions
    dangerous_perms = [
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    ]
    mock_android_context.android_manifest = {"permissions": dangerous_perms}

    findings = run(mock_android_context)
    finding_ids = {f.id for f in findings}
    assert "APERM-002" in finding_ids  # Excessive permissions


def test_permissions_analyzer_summary(mock_android_context):
    """Test that permissions summary is generated."""
    mock_android_context.android_manifest = {
        "permissions": ["android.permission.CAMERA", "android.permission.INTERNET"]
    }

    findings = run(mock_android_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "APERM-003"
    assert finding.severity == SeverityLevel.INFO


def test_permissions_analyzer_mixed_permissions(mock_android_context):
    """Test analysis of mixed dangerous and normal permissions."""
    mock_android_context.android_manifest = {
        "permissions": [
            "android.permission.CAMERA",  # dangerous
            "android.permission.INTERNET",  # normal
            "android.permission.SYSTEM_ALERT_WINDOW",  # overprivileged
        ]
    }

    findings = run(mock_android_context)
    finding_ids = {f.id for f in findings}
    assert "APERM-001" in finding_ids  # overprivileged
    assert "APERM-003" in finding_ids  # summary