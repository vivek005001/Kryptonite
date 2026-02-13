#!/usr/bin/env python3
"""Quick script to create the test IPA and run the scan."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Step 1: Create test IPA
import zipfile
import plistlib
import struct
from pathlib import Path

out = Path(os.path.dirname(os.path.abspath(__file__))) / "test_app.ipa"
p = "Payload/InsecureTestApp.app"

# Binary with embedded strings
h = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0x85, 0)

string_data = b"\x00\x00\x00\x00".join([
    b"AKIAIOSFODNN7EXAMPLE",
    b"CC_MD5",
    b"NSLog",
    b"NSUserDefaults",
    b"isDebug",
    b"http://api.insecure.com/data",
    b"kCCAlgorithm3DES",
    b"kCCModeECB",
    b"srand",
    b"debugPrint",
    b"staging.api.example.com",
    b"standardUserDefaults",
    b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"mongodb://admin:pw@prod.db.co:27017/db",
    b"Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop1234",
    b'api_key = "sk-proj-abc123456789012345678901234567890"',
    b'password = "SuperSecret123!"',
    b'encryption_key = "hardcoded_aes_key_12345678"',
    b"http://tracking.example.net/pixel",
])
binary = h + b"\x00" * 4 + string_data

# Info.plist
plist_dict = {
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
    "NSLocationAlwaysUsageDescription": "loc",
    "NSContactsUsageDescription": "contacts",
    "NSHealthShareUsageDescription": "health",
    "NSMotionUsageDescription": "motion",
    "NSBluetoothAlwaysUsageDescription": "ble",
    "NSFaceIDUsageDescription": "auth",
    "NSLocalNetworkUsageDescription": "network",
    "NSUserTrackingUsageDescription": "We track you for ads",
}
info_bytes = plistlib.dumps(plist_dict, fmt=plistlib.FMT_BINARY)

# Sensitive cache plist
sens_bytes = plistlib.dumps(
    {"user_auth_token": "abc123", "session_cookie": "sid=x", "api_secret": "s3cret"},
    fmt=plistlib.FMT_BINARY,
)

# Config JSON
config = b'{"firebase_api_key": "AIzaSyC-FAKE-KEY-1234567890abcdefgh", "api_token": "xoxb-12345-abcdefghijklmnop", "encryption_key": "hardcoded"}'

# Write IPA
with zipfile.ZipFile(str(out), "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr(p + "/InsecureTestApp", binary)
    zf.writestr(p + "/Info.plist", info_bytes)
    zf.writestr(p + "/UserCache.plist", sens_bytes)
    zf.writestr(p + "/config.json", config)
    zf.writestr(p + "/cache.sqlite", b"SQLite format 3\x00" + b"\x00" * 100)

sys.stdout.write("IPA created: " + str(out) + " (" + str(out.stat().st_size) + " bytes)\n")

# Step 2: Run the scan
sys.stdout.write("\n--- Running Kryptonite scan ---\n")
from kryptonite.cli import scan
code = scan(str(out), str(out.parent / "output"), "all")
sys.stdout.write("\nScan exit code: " + str(code) + "\n")
