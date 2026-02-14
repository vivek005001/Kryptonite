"""Unit tests for OWASP categories."""

import pytest

from kryptonite.core.owasp import OwaspCategory


def test_owasp_category_codes():
    """Test that all OWASP categories have correct codes."""
    assert OwaspCategory.M1.code == "M1"
    assert OwaspCategory.M10.code == "M10"


def test_owasp_category_titles():
    """Test OWASP category titles."""
    assert "Improper Credential Usage" in OwaspCategory.M1.category_title
    assert "Insufficient Cryptography" in OwaspCategory.M10.category_title


def test_owasp_category_by_code():
    """Test looking up categories by code."""
    assert OwaspCategory.by_code("M1") == OwaspCategory.M1
    assert OwaspCategory.by_code("M5") == OwaspCategory.M5


def test_owasp_category_by_code_invalid():
    """Test that invalid codes raise ValueError."""
    with pytest.raises(ValueError, match="Unknown OWASP category code"):
        OwaspCategory.by_code("M11")


def test_owasp_category_to_dict():
    """Test to_dict method."""
    data = OwaspCategory.M1.to_dict()
    assert data["code"] == "M1"
    assert "title" in data
    assert "description" in data