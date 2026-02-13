#!/usr/bin/env python3
import sys, os, traceback

log = open("/Users/vivek/Downloads/kryptonite/tests/debug_log.txt", "w")
try:
    log.write("Starting...\n")
    log.flush()
    
    sys.path.insert(0, "/Users/vivek/Downloads/kryptonite")
    
    import zipfile, plistlib, struct
    from pathlib import Path
    
    log.write("Imports OK\n")
    log.flush()
    
    out = Path("/Users/vivek/Downloads/kryptonite/tests/test_app.ipa")
    p = "Payload/InsecureTestApp.app"
    
    h = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0x85, 0)
    
    strings_list = [
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
    ]
    binary = h + b"\x00" * 4
    for s in strings_list:
        binary += s + b"\x00" * 4

    log.write("Binary created: %d bytes\n" % len(binary))
    log.flush()

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
            {"CFBundleURLName": "d", "CFBundleURLSchemes": ["insecureapp", "myapp-debug"]},
            {"CFBundleURLName": "o", "CFBundleURLSchemes": ["insecureapp-oauth", "myapp-callback"]},
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
    log.write("Plist created: %d bytes\n" % len(info_bytes))
    log.flush()

    sens_bytes = plistlib.dumps(
        {"user_auth_token": "abc123", "session_cookie": "sid=x", "api_secret": "s3cret"},
        fmt=plistlib.FMT_BINARY,
    )
    config = b'{"firebase_api_key": "AIzaSyC-FAKE-KEY-1234567890abcdefgh", "api_token": "xoxb-12345-abcdefghijklmnop"}'

    with zipfile.ZipFile(str(out), "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(p + "/InsecureTestApp", binary)
        zf.writestr(p + "/Info.plist", info_bytes)
        zf.writestr(p + "/UserCache.plist", sens_bytes)
        zf.writestr(p + "/config.json", config)
        zf.writestr(p + "/cache.sqlite", b"SQLite format 3\x00" + b"\x00" * 100)
    
    log.write("IPA created: %s (%d bytes)\n" % (str(out), out.stat().st_size))
    log.flush()
    
    # Now run the scan
    log.write("\n--- Running scan ---\n")
    log.flush()
    
    from kryptonite.cli import scan
    code = scan(str(out), str(out.parent / "output"), "all")
    log.write("Scan exit code: %d\n" % code)
    log.flush()

except Exception:
    log.write("ERROR:\n")
    traceback.print_exc(file=log)
    log.flush()
finally:
    log.close()
