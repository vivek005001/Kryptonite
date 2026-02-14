"""Unit tests for crypto analyzer."""

import tempfile
from pathlib import Path

import pytest

from kryptonite.analyzers.crypto_analyzer import run
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


def test_crypto_analyzer_no_findings(mock_app_context):
    """Test that no findings are reported when no weak crypto is present."""
    test_file = mock_app_context.app_dir / "code.java"
    test_file.write_text("some code without crypto")

    mock_app_context.all_files = [test_file]

    findings = run(mock_app_context)
    assert len(findings) == 0


def test_crypto_analyzer_md5_in_file(mock_app_context):
    """Test detection of MD5 usage in source file."""
    test_file = mock_app_context.app_dir / "crypto.java"
    test_file.write_text('MessageDigest.getInstance("MD5")')

    mock_app_context.all_files = [test_file]

    findings = run(mock_app_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "CRYPTO-001"
    assert finding.title == "MD5 Hash Usage"
    assert finding.severity == SeverityLevel.MEDIUM


def test_crypto_analyzer_des_in_binary(mock_app_context):
    """Test detection of DES in binary strings."""
    mock_app_context.binary_strings = [
        "some string",
        "kCCAlgorithmDES",
        "another string"
    ]

    findings = run(mock_app_context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "CRYPTO-003"
    assert finding.title == "DES / 3DES Encryption"


def test_crypto_analyzer_multiple_weak_crypto(mock_app_context):
    """Test detection of multiple weak crypto usages."""
    test_file = mock_app_context.app_dir / "weak.java"
    test_file.write_text("""
Cipher.getInstance("DES/ECB/PKCS5Padding")
MessageDigest.getInstance("SHA-1")
""")

    mock_app_context.all_files = [test_file]
    mock_app_context.binary_strings = ["kCCAlgorithmRC4"]

    findings = run(mock_app_context)
    finding_ids = {f.id for f in findings}
    assert "CRYPTO-003" in finding_ids  # DES
    assert "CRYPTO-002" in finding_ids  # SHA-1
    assert "CRYPTO-004" in finding_ids  # RC4


def test_crypto_analyzer_deduplication(mock_app_context):
    """Test that duplicate crypto findings are deduplicated."""
    test_file = mock_app_context.app_dir / "duplicate.java"
    test_file.write_text('MD5_Init() MD5_Init()')

    mock_app_context.all_files = [test_file]

    findings = run(mock_app_context)
    # Should only find one instance
    assert len(findings) == 1