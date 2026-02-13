"""IPA file extraction and app-bundle context."""

from __future__ import annotations

import plistlib
import shutil
import struct
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AppContext:
    """Holds all data extracted from an IPA needed by analyzers."""

    ipa_path: Path
    temp_dir: Path
    app_dir: Path
    info_plist: dict[str, Any] = field(default_factory=dict)
    entitlements: dict[str, Any] = field(default_factory=dict)
    binary_path: Path | None = None
    binary_strings: list[str] = field(default_factory=list)
    all_files: list[Path] = field(default_factory=list)

    # ── helpers ──────────────────────────────────────────────────────
    @property
    def bundle_id(self) -> str:
        return self.info_plist.get("CFBundleIdentifier", "unknown")

    @property
    def bundle_name(self) -> str:
        return self.info_plist.get("CFBundleDisplayName",
                                   self.info_plist.get("CFBundleName", "Unknown"))

    @property
    def bundle_version(self) -> str:
        return self.info_plist.get("CFBundleShortVersionString",
                                   self.info_plist.get("CFBundleVersion", "0.0"))

    @property
    def min_os_version(self) -> str:
        return self.info_plist.get("MinimumOSVersion", "unknown")

    def text_files(self) -> list[Path]:
        """Return all text-readable files in the app bundle."""
        text_exts = {
            ".plist", ".xml", ".json", ".strings", ".js", ".html",
            ".css", ".txt", ".cfg", ".conf", ".yml", ".yaml", ".md",
            ".swift", ".m", ".h", ".c", ".cpp", ".storyboard", ".xib",
        }
        return [f for f in self.all_files if f.suffix.lower() in text_exts]

    def cleanup(self) -> None:
        """Remove the temporary extraction directory."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)


# ── IPA parsing ──────────────────────────────────────────────────────

def _find_app_dir(payload_dir: Path) -> Path:
    """Locate the .app bundle inside Payload/."""
    candidates = list(payload_dir.glob("*.app"))
    if not candidates:
        raise FileNotFoundError(
            f"No .app bundle found inside {payload_dir}")
    return candidates[0]


def _read_plist(plist_path: Path) -> dict[str, Any]:
    """Read a binary or XML plist."""
    try:
        with open(plist_path, "rb") as fp:
            return plistlib.load(fp)
    except Exception:
        return {}


_MACHO_MAGICS = {
    0xFEEDFACE,  # MH_MAGIC  (32-bit)
    0xFEEDFACF,  # MH_MAGIC_64
    0xCEFAEDFE,  # MH_CIGAM  (32-bit, swapped)
    0xCFFAEDFE,  # MH_CIGAM_64
    0xCAFEBABE,  # FAT_MAGIC
    0xBEBAFECA,  # FAT_CIGAM
}


def _is_macho(path: Path) -> bool:
    """Quick check if a file is a Mach-O binary."""
    try:
        with open(path, "rb") as fp:
            magic = struct.unpack("<I", fp.read(4))[0]
            return magic in _MACHO_MAGICS
    except Exception:
        return False


def _find_binary(app_dir: Path, info_plist: dict[str, Any]) -> Path | None:
    """Locate the main executable inside the .app bundle."""
    exec_name = info_plist.get("CFBundleExecutable")
    if exec_name:
        candidate = app_dir / exec_name
        if candidate.exists():
            return candidate
    # Fallback: scan for Mach-O files
    for f in app_dir.iterdir():
        if f.is_file() and _is_macho(f):
            return f
    return None


def _extract_strings_python(binary_path: Path, min_length: int = 4) -> list[str]:
    """Pure-Python fallback: extract printable ASCII strings from a binary."""
    import re
    try:
        data = binary_path.read_bytes()
        # Match sequences of printable ASCII characters of min_length+
        pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
        return [m.group(0).decode("ascii") for m in re.finditer(pattern, data)]
    except Exception:
        return []


def _extract_strings(binary_path: Path) -> list[str]:
    """Extract readable strings from a binary; uses system `strings` with Python fallback."""
    result_lines: list[str] = []
    try:
        result = subprocess.run(
            ["strings", str(binary_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        result_lines = result.stdout.splitlines()
    except Exception:
        pass

    # Fallback to Python extraction if system strings returned nothing
    if not result_lines:
        result_lines = _extract_strings_python(binary_path)

    return result_lines


def _extract_entitlements(binary_path: Path) -> dict[str, Any]:
    """Try to extract embedded entitlements from the binary."""
    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", str(binary_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.stdout.strip():
            return plistlib.loads(result.stdout.encode())
    except Exception:
        pass
    # Fallback: look for embedded.mobileprovision or .entitlements files
    return {}


def parse_ipa(ipa_path: str | Path) -> AppContext:
    """
    Extract an IPA file and build an AppContext for analysis.

    Parameters
    ----------
    ipa_path : path-like
        Path to the .ipa file.

    Returns
    -------
    AppContext
        Populated context ready for analyzers.

    Raises
    ------
    FileNotFoundError
        If the IPA doesn't exist or contains no .app bundle.
    zipfile.BadZipFile
        If the IPA is not a valid zip.
    """
    ipa_path = Path(ipa_path).resolve()
    if not ipa_path.exists():
        raise FileNotFoundError(f"IPA file not found: {ipa_path}")

    temp_dir = Path(tempfile.mkdtemp(prefix="kryptonite_"))

    # Extract
    with zipfile.ZipFile(ipa_path, "r") as zf:
        zf.extractall(temp_dir)

    payload_dir = temp_dir / "Payload"
    if not payload_dir.exists():
        # Some IPAs put the .app at root level
        payload_dir = temp_dir

    app_dir = _find_app_dir(payload_dir)
    info_plist = _read_plist(app_dir / "Info.plist")
    binary_path = _find_binary(app_dir, info_plist)

    binary_strings: list[str] = []
    entitlements: dict[str, Any] = {}
    if binary_path:
        binary_strings = _extract_strings(binary_path)
        entitlements = _extract_entitlements(binary_path)

    # Collect all files recursively
    all_files = [p for p in app_dir.rglob("*") if p.is_file()]

    return AppContext(
        ipa_path=ipa_path,
        temp_dir=temp_dir,
        app_dir=app_dir,
        info_plist=info_plist,
        entitlements=entitlements,
        binary_path=binary_path,
        binary_strings=binary_strings,
        all_files=all_files,
    )
