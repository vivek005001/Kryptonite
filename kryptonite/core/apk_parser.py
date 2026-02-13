"""APK file extraction and manifest parsing for Android analysis."""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from kryptonite.core.ipa_parser import AppContext


# ── Android Binary XML constants ─────────────────────────────────────
_CHUNK_AXML = 0x0003
_CHUNK_STRING_POOL = 0x0001
_CHUNK_RESOURCE_MAP = 0x0180
_CHUNK_START_NAMESPACE = 0x0100
_CHUNK_END_NAMESPACE = 0x0101
_CHUNK_START_TAG = 0x0102
_CHUNK_END_TAG = 0x0103
_CHUNK_TEXT = 0x0104

_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOLEAN = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _decode_binary_xml(data: bytes) -> str | None:
    """
    Decode Android binary XML to a plain-text XML string.

    This is a lightweight decoder that handles the most common cases
    needed for AndroidManifest.xml analysis. Falls back gracefully.
    """
    if len(data) < 8:
        return None

    # Check for binary XML magic
    magic = struct.unpack_from("<H", data, 0)[0]
    if magic != _CHUNK_AXML:
        # Not binary XML – might be plain text
        try:
            return data.decode("utf-8")
        except Exception:
            return None

    # Parse string pool
    offset = 8  # skip AXML header (type=2, header_size=2, chunk_size=4)
    if offset + 8 > len(data):
        return None

    sp_type = struct.unpack_from("<H", data, offset)[0]
    if sp_type != _CHUNK_STRING_POOL:
        return None

    sp_header_size = struct.unpack_from("<H", data, offset + 2)[0]
    sp_chunk_size = struct.unpack_from("<I", data, offset + 4)[0]
    string_count = struct.unpack_from("<I", data, offset + 8)[0]
    _style_count = struct.unpack_from("<I", data, offset + 12)[0]
    flags = struct.unpack_from("<I", data, offset + 16)[0]
    strings_start = struct.unpack_from("<I", data, offset + 20)[0]
    _styles_start = struct.unpack_from("<I", data, offset + 24)[0]

    is_utf8 = bool(flags & (1 << 8))

    # Read string offsets
    str_offsets = []
    off_base = offset + 28
    for i in range(string_count):
        if off_base + i * 4 + 4 > len(data):
            break
        str_offsets.append(struct.unpack_from("<I", data, off_base + i * 4)[0])

    strings_abs_start = offset + strings_start
    strings: list[str] = []
    for s_off in str_offsets:
        abs_off = strings_abs_start + s_off
        try:
            if is_utf8:
                # UTF-8: skip char count (1-2 bytes), then byte count (1-2 bytes)
                n = data[abs_off]
                abs_off += 2 if n & 0x80 else 1
                byte_len = data[abs_off]
                abs_off += 2 if byte_len & 0x80 else 1
                # Read until null
                end = data.index(0, abs_off)
                strings.append(data[abs_off:end].decode("utf-8", errors="replace"))
            else:
                # UTF-16
                char_count = struct.unpack_from("<H", data, abs_off)[0]
                abs_off += 2
                raw = data[abs_off:abs_off + char_count * 2]
                strings.append(raw.decode("utf-16-le", errors="replace"))
        except Exception:
            strings.append("")

    # Now walk the XML events and rebuild plain XML
    offset += sp_chunk_size
    ns_map: dict[str, str] = {}  # uri -> prefix
    xml_parts: list[str] = ['<?xml version="1.0" encoding="utf-8"?>']

    def _get_str(idx: int) -> str:
        if 0 <= idx < len(strings):
            return strings[idx]
        return ""

    def _get_attr_value(raw_value: int, value_type: int, value_data: int) -> str:
        if value_type == _TYPE_STRING:
            return _get_str(raw_value)
        if value_type == _TYPE_INT_BOOLEAN:
            return "true" if value_data != 0 else "false"
        if value_type == _TYPE_INT_DEC:
            return str(value_data)
        if value_type == _TYPE_INT_HEX:
            return f"0x{value_data:08x}"
        return str(value_data)

    while offset + 8 <= len(data):
        chunk_type = struct.unpack_from("<H", data, offset)[0]
        _header_sz = struct.unpack_from("<H", data, offset + 2)[0]
        chunk_sz = struct.unpack_from("<I", data, offset + 4)[0]

        if chunk_sz < 8:
            break

        if chunk_type == _CHUNK_START_NAMESPACE:
            if offset + 24 <= len(data):
                prefix_idx = struct.unpack_from("<i", data, offset + 16)[0]
                uri_idx = struct.unpack_from("<i", data, offset + 20)[0]
                prefix = _get_str(prefix_idx)
                uri = _get_str(uri_idx)
                if prefix and uri:
                    ns_map[uri] = prefix

        elif chunk_type == _CHUNK_START_TAG:
            if offset + 28 <= len(data):
                ns_idx = struct.unpack_from("<i", data, offset + 16)[0]
                name_idx = struct.unpack_from("<i", data, offset + 20)[0]
                attr_start = struct.unpack_from("<H", data, offset + 26)[0]
                attr_count = struct.unpack_from("<H", data, offset + 28)[0]

                tag_name = _get_str(name_idx)
                attrs_str = ""

                for a in range(attr_count):
                    a_off = offset + 36 + a * 20
                    if a_off + 20 > len(data):
                        break
                    a_ns = struct.unpack_from("<i", data, a_off)[0]
                    a_name = struct.unpack_from("<i", data, a_off + 4)[0]
                    a_raw = struct.unpack_from("<i", data, a_off + 8)[0]
                    a_type = struct.unpack_from("<H", data, a_off + 14)[0] >> 8
                    a_data = struct.unpack_from("<i", data, a_off + 16)[0]

                    attr_name = _get_str(a_name)
                    attr_ns = _get_str(a_ns) if a_ns >= 0 else ""
                    attr_val = _get_attr_value(a_raw, a_type, a_data)

                    if attr_ns and attr_ns in ns_map:
                        attr_name = f"{ns_map[attr_ns]}:{attr_name}"
                    attrs_str += f' {attr_name}="{attr_val}"'

                # Add namespace declarations on root element
                ns_decls = ""
                if ns_map and tag_name == "manifest":
                    for uri, prefix in ns_map.items():
                        ns_decls += f' xmlns:{prefix}="{uri}"'

                xml_parts.append(f"<{tag_name}{ns_decls}{attrs_str}>")

        elif chunk_type == _CHUNK_END_TAG:
            if offset + 24 <= len(data):
                name_idx = struct.unpack_from("<i", data, offset + 20)[0]
                tag_name = _get_str(name_idx)
                xml_parts.append(f"</{tag_name}>")

        offset += chunk_sz

    return "\n".join(xml_parts)


def _parse_manifest_xml(xml_text: str) -> dict[str, Any]:
    """Parse decoded AndroidManifest.xml into a structured dict."""
    result: dict[str, Any] = {}
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return result

    ns = {"android": ANDROID_NS}

    # Package info
    result["package"] = root.get("package", "")
    result["version_code"] = root.get(f"{{{ANDROID_NS}}}versionCode",
                                       root.get("versionCode", ""))
    result["version_name"] = root.get(f"{{{ANDROID_NS}}}versionName",
                                       root.get("versionName", ""))

    # SDK versions
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        result["min_sdk"] = (
            uses_sdk.get(f"{{{ANDROID_NS}}}minSdkVersion", "") or
            uses_sdk.get("minSdkVersion", "")
        )
        result["target_sdk"] = (
            uses_sdk.get(f"{{{ANDROID_NS}}}targetSdkVersion", "") or
            uses_sdk.get("targetSdkVersion", "")
        )

    # Permissions
    permissions: list[str] = []
    for perm in root.findall("uses-permission"):
        name = (perm.get(f"{{{ANDROID_NS}}}name", "") or
                perm.get("name", ""))
        if name:
            permissions.append(name)
    result["permissions"] = permissions

    # Application attributes
    app = root.find("application")
    if app is not None:
        result["debuggable"] = _attr_bool(app, "debuggable")
        result["allow_backup"] = _attr_bool(app, "allowBackup", default=True)
        result["uses_cleartext"] = _attr_bool(app, "usesCleartextTraffic")
        result["network_security_config"] = (
            app.get(f"{{{ANDROID_NS}}}networkSecurityConfig", "") or
            app.get("networkSecurityConfig", "")
        )
        result["application_label"] = (
            app.get(f"{{{ANDROID_NS}}}label", "") or
            app.get("label", "")
        )

        # Components
        for comp_type in ("activity", "service", "receiver", "provider"):
            components: list[dict[str, Any]] = []
            for comp in app.findall(comp_type):
                comp_info: dict[str, Any] = {
                    "name": (comp.get(f"{{{ANDROID_NS}}}name", "") or
                             comp.get("name", "")),
                    "exported": _attr_bool(comp, "exported"),
                    "permission": (comp.get(f"{{{ANDROID_NS}}}permission", "") or
                                   comp.get("permission", "")),
                }
                # Intent filters
                intent_filters: list[dict[str, list[str]]] = []
                for if_elem in comp.findall("intent-filter"):
                    actions = []
                    for action in if_elem.findall("action"):
                        a_name = (action.get(f"{{{ANDROID_NS}}}name", "") or
                                  action.get("name", ""))
                        if a_name:
                            actions.append(a_name)
                    categories = []
                    for cat in if_elem.findall("category"):
                        c_name = (cat.get(f"{{{ANDROID_NS}}}name", "") or
                                  cat.get("name", ""))
                        if c_name:
                            categories.append(c_name)
                    data_schemes: list[str] = []
                    data_hosts: list[str] = []
                    for d in if_elem.findall("data"):
                        scheme = (d.get(f"{{{ANDROID_NS}}}scheme", "") or
                                  d.get("scheme", ""))
                        host = (d.get(f"{{{ANDROID_NS}}}host", "") or
                                d.get("host", ""))
                        if scheme:
                            data_schemes.append(scheme)
                        if host:
                            data_hosts.append(host)
                    intent_filters.append({
                        "actions": actions,
                        "categories": categories,
                        "data_schemes": data_schemes,
                        "data_hosts": data_hosts,
                    })
                comp_info["intent_filters"] = intent_filters
                # If component has intent filters, it's implicitly exported
                if intent_filters and not comp_info["exported"]:
                    comp_info["implicitly_exported"] = True
                else:
                    comp_info["implicitly_exported"] = False
                components.append(comp_info)
            result[f"{comp_type}s"] = components

    return result


def _attr_bool(elem: Any, attr: str, default: bool = False) -> bool:
    """Read an android: namespaced boolean attribute."""
    val = (elem.get(f"{{{ANDROID_NS}}}{attr}", "") or
           elem.get(attr, ""))
    if val.lower() in ("true", "1", "-1"):
        return True
    if val.lower() in ("false", "0"):
        return False
    return default


def _extract_dex_strings(dex_path: Path, min_length: int = 6) -> list[str]:
    """Extract printable strings from a DEX file."""
    result_lines: list[str] = []
    # Try system strings command first
    try:
        result = subprocess.run(
            ["strings", str(dex_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        result_lines = [s for s in result.stdout.splitlines()
                        if len(s) >= min_length]
    except Exception:
        pass

    # Fallback to Python extraction
    if not result_lines:
        try:
            data = dex_path.read_bytes()
            pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
            result_lines = [
                m.group(0).decode("ascii")
                for m in re.finditer(pattern, data)
            ]
        except Exception:
            pass

    return result_lines


def parse_apk(apk_path: str | Path) -> AppContext:
    """
    Extract an APK file and build an AppContext for analysis.

    Parameters
    ----------
    apk_path : path-like
        Path to the .apk file.

    Returns
    -------
    AppContext
        Populated context ready for analyzers.
    """
    apk_path = Path(apk_path).resolve()
    if not apk_path.exists():
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    temp_dir = Path(tempfile.mkdtemp(prefix="kryptonite_apk_"))

    # Extract
    with zipfile.ZipFile(apk_path, "r") as zf:
        zf.extractall(temp_dir)

    app_dir = temp_dir  # APK contents are at root level

    # ── Parse AndroidManifest.xml ────────────────────────────────
    manifest_path = app_dir / "AndroidManifest.xml"
    manifest_data: dict[str, Any] = {}
    manifest_xml_text = ""

    if manifest_path.exists():
        raw = manifest_path.read_bytes()
        decoded = _decode_binary_xml(raw)
        if decoded:
            manifest_xml_text = decoded
            manifest_data = _parse_manifest_xml(decoded)

    # ── Locate DEX files ─────────────────────────────────────────
    dex_files = sorted(app_dir.glob("*.dex"))

    # ── Extract strings from DEX ─────────────────────────────────
    binary_strings: list[str] = []
    for dex in dex_files:
        binary_strings.extend(_extract_dex_strings(dex))

    # ── Locate native libraries ──────────────────────────────────
    native_libs: list[Path] = []
    lib_dir = app_dir / "lib"
    if lib_dir.exists():
        native_libs = [p for p in lib_dir.rglob("*.so") if p.is_file()]

    # ── Find main binary (first DEX) ─────────────────────────────
    binary_path = dex_files[0] if dex_files else None

    # ── Collect all files ────────────────────────────────────────
    all_files = [p for p in app_dir.rglob("*") if p.is_file()]

    return AppContext(
        ipa_path=apk_path,
        temp_dir=temp_dir,
        app_dir=app_dir,
        platform="android",
        android_manifest=manifest_data,
        package_name=manifest_data.get("package", ""),
        min_sdk_version=manifest_data.get("min_sdk", ""),
        target_sdk_version=manifest_data.get("target_sdk", ""),
        binary_path=binary_path,
        binary_strings=binary_strings,
        dex_files=dex_files,
        native_libs=native_libs,
        all_files=all_files,
    )
