"""Build a synthetic test IPA with planted vulnerabilities for validation."""

import plistlib
import struct
import zipfile
import sys
from pathlib import Path


def create_test_ipa(output_path="tests/test_app.ipa"):
    """Generate a synthetic IPA file for testing."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    app_name = "InsecureTestApp.app"
    ppfx = "Payload/" + app_name

    # --- Build fake binary ---
    MH_MAGIC_64 = 0xFEEDFACF
    header = struct.pack("<IIIIIII", MH_MAGIC_64, 0x0100000C, 0, 2, 0, 0, 0x85)
    header += struct.pack("<I", 0)

    embedded_strings = [
        b"AKIAIOSFODNN7EXAMPLE\x00",
        b'api_key = "sk-proj-abc123456789012345678901234567890"\x00',
        b'password = "SuperSecret123!"\x00',
        b"-----BEGIN RSA PRIVATE KEY-----\x00",
        b"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdefghijk\x00",
        b"mongodb://admin:password@prod.db.example.com:27017/mydb\x00",
        b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234\x00",
        b"CC_MD5\x00",
        b"kCCAlgorithm3DES\x00",
        b"kCCModeECB\x00",
        b'encryption_key = "hardcoded_aes_key_12345678"\x00',
        b"srand\x00",
        b"NSLog\x00",
        b"debugPrint\x00",
        b"isDebug\x00",
        b"staging.api.example.com\x00",
        b"NSUserDefaults\x00",
        b"standardUserDefaults\x00",
        b"http://api.insecure-example.com/v1/data\x00",
        b"http://tracking.example.net/pixel\x00",
    ]
    binary_payload = header
    for s in embedded_strings:
        binary_payload += b"\x00" * 4 + s

    # --- Info.plist ---
    plist_data = {
        "CFBundleIdentifier": "com.example.insecure-app",
        "CFBundleDisplayName": "InsecureTestApp",
        "CFBundleName": "InsecureTestApp",
        "CFBundleShortVersionString": "2.1.0",
        "CFBundleVersion": "42",
        "CFBundleExecutable": "InsecureTestApp",
        "MinimumOSVersion": "14.0",
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True,
            "NSAllowsArbitraryLoadsInWebContent": True,
            "NSExceptionDomains": {
                "legacy-api.example.com": {
                    "NSExceptionAllowsInsecureHTTPLoads": True,
                    "NSExceptionMinimumTLSVersion": "TLSv1.0",
                },
            },
        },
        "CFBundleURLTypes": [
            {
                "CFBundleURLName": "com.example.deeplink",
                "CFBundleURLSchemes": ["insecureapp", "myapp-debug"],
            },
            {
                "CFBundleURLName": "com.example.oauth",
                "CFBundleURLSchemes": ["insecureapp-oauth", "myapp-callback"],
            },
        ],
        "NSCameraUsageDescription": "camera",
        "NSMicrophoneUsageDescription": "",
        "NSLocationAlwaysUsageDescription": "We need your location",
        "NSContactsUsageDescription": "contacts",
        "NSHealthShareUsageDescription": "health",
        "NSMotionUsageDescription": "motion",
        "NSBluetoothAlwaysUsageDescription": "ble",
        "NSFaceIDUsageDescription": "auth",
        "NSLocalNetworkUsageDescription": "network",
        "NSUserTrackingUsageDescription": "We track you for ads",
    }
    info_plist_bytes = plistlib.dumps(plist_data, fmt=plistlib.FMT_BINARY)

    # --- Sensitive cache plist ---
    sens_plist_bytes = plistlib.dumps({
        "user_auth_token": "abc123xyz789",
        "session_cookie": "sid=a1b2c3d4e5f6",
        "api_secret": "super-secret-value",
    }, fmt=plistlib.FMT_BINARY)

    # --- Config JSON ---
    config_json = (
        b'{\n'
        b'  "firebase_api_key": "AIzaSyC-FAKE-KEY-1234567890abcdefgh",\n'
        b'  "api_token": "xoxb-1234567890-abcdefghijklmnop",\n'
        b'  "encryption_key": "my-hardcoded-aes-key-do-not-share",\n'
        b'  "debug_mode": true\n'
        b'}\n'
    )

    # --- Assemble IPA ---
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(ppfx + "/InsecureTestApp", binary_payload)
        zf.writestr(ppfx + "/Info.plist", info_plist_bytes)
        zf.writestr(ppfx + "/UserCache.plist", sens_plist_bytes)
        zf.writestr(ppfx + "/config.json", config_json)
        zf.writestr(ppfx + "/cache.sqlite", b"SQLite format 3\x00" + b"\x00" * 100)

    print("Test IPA created: " + str(out.resolve()), file=sys.stderr)
    return out


if __name__ == "__main__":
    create_test_ipa()
