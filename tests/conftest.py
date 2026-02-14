"""Test configuration and shared fixtures."""

import tempfile
from pathlib import Path
from typing import Generator

import pytest

from kryptonite.core.ipa_parser import AppContext


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for tests."""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    # Cleanup
    import shutil
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def mock_app_context(temp_dir: Path) -> AppContext:
    """Create a mock AppContext for testing."""
    app_dir = temp_dir / "app"
    app_dir.mkdir()

    return AppContext(
        ipa_path=temp_dir / "test.ipa",
        temp_dir=temp_dir,
        app_dir=app_dir,
        platform="ios",
        binary_strings=[],
        info_plist={},
        android_manifest={}
    )