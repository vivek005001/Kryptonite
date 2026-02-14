"""Unit tests for iOS transport analyzer."""

import tempfile
from pathlib import Path

import pytest

from kryptonite.analyzers.ios.transport_analyzer import run
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


def test_transport_analyzer_non_ios(mock_ios_context):
    """Test that analyzer returns no findings for non-iOS platforms."""
    mock_ios_context.platform = "android"

    findings = run(mock_ios_context)
    assert len(findings) == 0


def test_transport_analyzer_allows_arbitrary_loads(mock_ios_context):
    """Test detection of NSAllowsArbitraryLoads."""
    mock_ios_context.info_plist = {
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True
        }
    }

    findings = run(mock_ios_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "TRANS-001"
    assert finding.severity == SeverityLevel.HIGH


def test_transport_analyzer_insecure_domain_exception(mock_ios_context):
    """Test detection of insecure domain exceptions."""
    mock_ios_context.info_plist = {
        "NSAppTransportSecurity": {
            "NSExceptionDomains": {
                "insecure.example.com": {
                    "NSExceptionAllowsInsecureHTTPLoads": True
                }
            }
        }
    }

    findings = run(mock_ios_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "TRANS-003"


def test_transport_analyzer_weak_tls_version(mock_ios_context):
    """Test detection of weak TLS versions in exceptions."""
    mock_ios_context.info_plist = {
        "NSAppTransportSecurity": {
            "NSExceptionDomains": {
                "legacy.example.com": {
                    "NSExceptionMinimumTLSVersion": "TLSv1.0"
                }
            }
        }
    }

    findings = run(mock_ios_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "TRANS-004"


def test_transport_analyzer_http_url_in_binary(mock_ios_context):
    """Test detection of HTTP URLs in binary strings."""
    mock_ios_context.binary_strings = [
        "some string",
        "http://api.insecure.com/data",
        "another string"
    ]

    findings = run(mock_ios_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "TRANS-005"
    assert "http://api.insecure.com" in finding.description


def test_transport_analyzer_http_url_in_file(mock_ios_context):
    """Test detection of HTTP URLs in text files."""
    test_file = mock_ios_context.app_dir / "config.json"
    test_file.write_text('{"api_url": "http://insecure.example.com/api"}')

    mock_ios_context.all_files = [test_file]

    findings = run(mock_ios_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "TRANS-005"
    assert finding.evidence[0].file == "config.json"


def test_transport_analyzer_multiple_issues(mock_ios_context):
    """Test detection of multiple transport security issues."""
    mock_ios_context.info_plist = {
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True,
            "NSExceptionDomains": {
                "bad.example.com": {
                    "NSExceptionAllowsInsecureHTTPLoads": True,
                    "NSExceptionMinimumTLSVersion": "TLSv1.0"
                }
            }
        }
    }
    mock_ios_context.binary_strings = ["http://hack.com"]

    findings = run(mock_ios_context)
    finding_ids = {f.id for f in findings}
    assert "TRANS-001" in finding_ids
    assert "TRANS-003" in finding_ids
    assert "TRANS-004" in finding_ids
    assert "TRANS-005" in finding_ids