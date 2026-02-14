"""Unit tests for iOS permissions analyzer."""

import tempfile
from pathlib import Path

import pytest

from kryptonite.analyzers.ios.permissions_analyzer import run
from kryptonite.core.finding import SeverityLevel
from kryptonite.core.ipa_parser import AppContext


@pytest.fixture
def mock_ios_context():
    """Create a mock AppContext for iOS."""
    temp_dir = Path(tempfile.mkdtemp())
    app_dir = temp_dir / "app"
    app_dir.mkdir()

    ctx = AppContext(
        ipa_path=temp_dir / "test.ipa",
        temp_dir=temp_dir,
        app_dir=app_dir,
        platform="ios",
        binary_strings=[],
        info_plist={}
    )
    yield ctx
    # Cleanup
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_permissions_analyzer_non_ios(mock_ios_context):
    """Test that analyzer returns no findings for non-iOS platforms."""
    mock_ios_context.platform = "android"

    findings = run(mock_ios_context)
    assert len(findings) == 0


def test_permissions_analyzer_no_permissions(mock_ios_context):
    """Test that analyzer returns no findings when no permissions are present."""
    mock_ios_context.info_plist = {}

    findings = run(mock_ios_context)
    assert len(findings) == 0


def test_permissions_analyzer_insufficient_description(mock_ios_context):
    """Test detection of insufficient usage descriptions."""
    mock_ios_context.info_plist = {
        "NSCameraUsageDescription": "cam",
        "NSLocationAlwaysUsageDescription": "This app needs location access for features."
    }

    findings = run(mock_ios_context)
    assert len(findings) == 2  # One for insufficient desc, one for summary
    finding = findings[0]
    assert finding.id == "PERM-001"
    assert "Camera" in finding.title


def test_permissions_analyzer_excessive_permissions(mock_ios_context):
    """Test detection of excessive sensitive permissions."""
    # Create 5+ high/medium risk permissions
    mock_ios_context.info_plist = {
        "NSCameraUsageDescription": "Camera access",
        "NSMicrophoneUsageDescription": "Microphone access",
        "NSLocationAlwaysUsageDescription": "Location access",
        "NSContactsUsageDescription": "Contacts access",
        "NSHealthShareUsageDescription": "Health access",
        "NSMotionUsageDescription": "Motion access",
    }

    findings = run(mock_ios_context)
    finding_ids = {f.id for f in findings}
    assert "PERM-002" in finding_ids  # Excessive permissions


def test_permissions_analyzer_summary(mock_ios_context):
    """Test that permissions summary is generated."""
    mock_ios_context.info_plist = {
        "NSCameraUsageDescription": "Camera access for photos",
        "NSPhotoLibraryUsageDescription": "Photo library access"
    }

    findings = run(mock_ios_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "PERM-003"
    assert finding.severity == SeverityLevel.INFO


def test_permissions_analyzer_mixed_permissions(mock_ios_context):
    """Test analysis of mixed permissions with good and bad descriptions."""
    mock_ios_context.info_plist = {
        "NSCameraUsageDescription": "cam",  # bad
        "NSLocationWhenInUseUsageDescription": "Location for maps",  # good
    }

    findings = run(mock_ios_context)
    finding_ids = {f.id for f in findings}
    assert "PERM-001" in finding_ids  # insufficient description
    assert "PERM-003" in finding_ids  # summary