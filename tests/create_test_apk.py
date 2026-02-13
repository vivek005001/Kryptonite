"""Create a synthetic APK file with planted vulnerabilities for testing."""

from __future__ import annotations

import struct
import tempfile
import zipfile
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring


def _build_plain_manifest() -> bytes:
    """Build an AndroidManifest.xml with various vulnerabilities as plain XML.

    We produce plain-text XML (not binary) because the parser supports both.
    """
    manifest = Element("manifest")
    manifest.set("xmlns:android", "http://schemas.android.com/apk/res/android")
    manifest.set("package", "com.insecure.testapp")
    manifest.set("android:versionCode", "1")
    manifest.set("android:versionName", "1.0.0")

    # uses-sdk — low target SDK
    uses_sdk = SubElement(manifest, "uses-sdk")
    uses_sdk.set("android:minSdkVersion", "21")
    uses_sdk.set("android:targetSdkVersion", "25")  # Below 28 → finding

    # Permissions
    for perm in [
        "android.permission.INTERNET",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.SYSTEM_ALERT_WINDOW",  # Overprivileged
    ]:
        up = SubElement(manifest, "uses-permission")
        up.set("android:name", perm)

    # Application
    app = SubElement(manifest, "application")
    app.set("android:label", "InsecureTestApp")
    app.set("android:debuggable", "true")          # → MANIFEST-001
    app.set("android:allowBackup", "true")          # → MANIFEST-002
    app.set("android:usesCleartextTraffic", "true") # → MANIFEST-003
    # No networkSecurityConfig                      # → MANIFEST-004

    # Main launcher activity (should NOT be flagged as exported since it's launcher)
    main_activity = SubElement(app, "activity")
    main_activity.set("android:name", ".MainActivity")
    main_activity.set("android:exported", "true")
    main_if = SubElement(main_activity, "intent-filter")
    action = SubElement(main_if, "action")
    action.set("android:name", "android.intent.action.MAIN")
    cat = SubElement(main_if, "category")
    cat.set("android:name", "android.intent.category.LAUNCHER")

    # Exported activity without permission (should be flagged)
    exported_activity = SubElement(app, "activity")
    exported_activity.set("android:name", ".DeepLinkActivity")
    exported_activity.set("android:exported", "true")
    dl_if = SubElement(exported_activity, "intent-filter")
    dl_action = SubElement(dl_if, "action")
    dl_action.set("android:name", "android.intent.action.VIEW")
    dl_cat = SubElement(dl_if, "category")
    dl_cat.set("android:name", "android.intent.category.DEFAULT")
    dl_cat2 = SubElement(dl_if, "category")
    dl_cat2.set("android:name", "android.intent.category.BROWSABLE")
    dl_data = SubElement(dl_if, "data")
    dl_data.set("android:scheme", "myapp")  # Custom URI scheme → finding

    # Exported service without permission
    svc = SubElement(app, "service")
    svc.set("android:name", ".BackgroundSyncService")
    svc.set("android:exported", "true")

    # Exported provider without permission
    prov = SubElement(app, "provider")
    prov.set("android:name", ".DataProvider")
    prov.set("android:exported", "true")
    prov.set("android:authorities", "com.insecure.testapp.provider")

    # Exported receiver with intent-filter (implicitly exported)
    recv = SubElement(app, "receiver")
    recv.set("android:name", ".BootReceiver")
    recv_if = SubElement(recv, "intent-filter")
    recv_action = SubElement(recv_if, "action")
    recv_action.set("android:name", "android.intent.action.BOOT_COMPLETED")

    return b'<?xml version="1.0" encoding="utf-8"?>\n' + tostring(manifest)


def _build_fake_dex() -> bytes:
    """Build a fake DEX file with planted vulnerable strings."""
    # DEX magic header
    header = b"dex\n035\x00"

    # Pad to look like a DEX file
    padding = b"\x00" * 100

    # Planted strings that analyzers should detect
    planted_strings = [
        # Secrets
        b"AKIAIOSFODNN7EXAMPLE",                   # AWS key
        b"api_key = \"sk_live_abc123def456\"",       # Stripe key
        b"password = \"SuperSecret123!\"",           # Hardcoded pw

        # Weak crypto
        b"MessageDigest.getInstance(\"MD5\"",        # MD5
        b"Cipher.getInstance(\"DES/ECB/PKCS5Padding\"", # DES+ECB
        b"java.util.Random",                        # Insecure random

        # Logging
        b"Log.d(TAG, \"User password: \"",           # Android logging
        b"System.out.println(\"Debug token: \"",     # System.out
        b"e.printStackTrace()",                      # printStackTrace

        # Data storage
        b"getSharedPreferences",                     # SharedPreferences
        b"getExternalStorageDirectory",              # External storage
        b"MODE_WORLD_READABLE",                      # World readable

        # Transport
        b"http://api.example.com/v1/data",           # HTTP URL
        b"http://staging.internal.corp/debug",       # Another HTTP URL

        # Debug indicators
        b"DEBUG_MODE = true",                        # Debug mode
        b"staging.internal.corp",                    # Staging server

        # WebView
        b"setAllowFileAccessFromFileURLs",           # Risky WebView
        b"setAllowUniversalAccessFromFileURLs",      # Risky WebView

        # Additional context
        b"com.insecure.testapp",
        b"InsecureTestApp",
    ]

    content = header + padding
    for s in planted_strings:
        content += b"\x00" * 8 + s + b"\x00"

    return content


def create_test_apk(output_dir: str | Path | None = None) -> Path:
    """Create a test APK file with planted vulnerabilities.

    Parameters
    ----------
    output_dir : path-like, optional
        Directory to write the APK to. Defaults to a temp directory.

    Returns
    -------
    Path
        Path to the generated APK file.
    """
    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="kryptonite_test_"))
    else:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

    apk_path = output_dir / "test_insecure.apk"

    with zipfile.ZipFile(apk_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # AndroidManifest.xml
        zf.writestr("AndroidManifest.xml", _build_plain_manifest())

        # classes.dex with planted strings
        zf.writestr("classes.dex", _build_fake_dex())

        # A second DEX file for multidex detection
        zf.writestr("classes2.dex", _build_fake_dex()[:200])

        # Fake native library
        # Minimal ELF header: ET_EXEC (not PIE) → should trigger ABIN-001
        elf_header = b"\x7fELF"          # magic
        elf_header += b"\x01"             # 32-bit
        elf_header += b"\x01"             # little endian
        elf_header += b"\x01"             # ELF version
        elf_header += b"\x00" * 9         # padding
        elf_header += struct.pack("<H", 2)  # e_type = ET_EXEC (not PIE!)
        elf_header += b"\x00" * 100       # rest of header
        # No __stack_chk symbols → should trigger ABIN-002
        zf.writestr("lib/armeabi-v7a/libnative.so", elf_header)

        # Embedded database
        zf.writestr("assets/data.sqlite", b"SQLite format 3\x00" + b"\x00" * 100)

        # A text file with more secrets
        zf.writestr("assets/config.properties",
                     "api.endpoint=http://api.example.com/v2\n"
                     "api.secret=ghp_ABCDEFghijklmnop1234567890abcdef\n"
                     "debug.enabled=true\n")

        # A res/xml file (not network_security_config, just to add file count)
        zf.writestr("res/values/strings.xml",
                     '<?xml version="1.0"?>\n'
                     '<resources><string name="app_name">InsecureTestApp</string></resources>')

    print(f"✅ Test APK created: {apk_path}")
    print(f"   Size: {apk_path.stat().st_size:,} bytes")
    return apk_path


if __name__ == "__main__":
    create_test_apk(Path(__file__).parent / "output")
