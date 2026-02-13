"""Run Kryptonite scan against a synthetic test APK and validate results."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def main() -> int:
    """Create a test APK, run the scan, and validate output."""
    print("=" * 60)
    print("  Kryptonite Android APK Test Suite")
    print("=" * 60)

    # ── Step 1: Create test APK ──────────────────────────────────
    print("\n📦 Step 1: Creating synthetic test APK...")
    from tests.create_test_apk import create_test_apk

    work_dir = Path(tempfile.mkdtemp(prefix="kryptonite_apk_test_"))
    apk_path = create_test_apk(work_dir)
    assert apk_path.exists(), f"APK not created at {apk_path}"

    # ── Step 2: Run scan ─────────────────────────────────────────
    print("\n🔍 Step 2: Running Kryptonite scan...")
    output_dir = work_dir / "report"
    result = subprocess.run(
        [
            sys.executable, "-m", "kryptonite",
            "scan", str(apk_path),
            "--output-dir", str(output_dir),
            "--format", "all",
        ],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )

    print(result.stderr)
    if result.returncode not in (0, 1):
        print(f"❌ Scan failed with exit code {result.returncode}")
        if result.stdout:
            print(result.stdout)
        return 1

    # ── Step 3: Validate report ──────────────────────────────────
    print("\n✅ Step 3: Validating results...")
    json_path = output_dir / "report.json"
    html_path = output_dir / "report.html"

    if not json_path.exists():
        print(f"❌ JSON report not found at {json_path}")
        return 1
    if not html_path.exists():
        print(f"❌ HTML report not found at {html_path}")
        return 1

    with open(json_path) as fp:
        report = json.load(fp)

    errors = validate_report(report)

    if errors:
        print(f"\n❌ Validation FAILED with {len(errors)} error(s):")
        for i, err in enumerate(errors, 1):
            print(f"   {i}. {err}")
        return 1

    print("\n" + "=" * 60)
    print("  ✅ ALL ANDROID APK TESTS PASSED")
    print("=" * 60)
    return 0


def validate_report(report: dict) -> list[str]:
    """Validate the report against expected findings."""
    errors: list[str] = []

    # Check report structure
    for key in ("meta", "app_info", "summary", "findings", "owasp_mapping"):
        if key not in report:
            errors.append(f"Missing top-level key: {key}")

    if errors:
        return errors  # Can't validate further

    # ── Meta checks ──────────────────────────────────────────────
    meta = report["meta"]
    if meta.get("version") != "2.0.0":
        errors.append(f"Expected version 2.0.0, got {meta.get('version')}")

    # ── App info checks ──────────────────────────────────────────
    app_info = report["app_info"]
    if app_info.get("platform") != "Android":
        errors.append(f"Expected platform Android, got {app_info.get('platform')}")
    if app_info.get("bundle_id") != "com.insecure.testapp":
        errors.append(f"Expected package com.insecure.testapp, got {app_info.get('bundle_id')}")

    # ── Finding checks ───────────────────────────────────────────
    findings = report["findings"]
    finding_ids = {f["id"] for f in findings}
    finding_titles = {f["title"] for f in findings}

    # Expected findings from our planted vulnerabilities
    expected_ids = {
        # Manifest
        "MANIFEST-001",  # debuggable
        "MANIFEST-002",  # allowBackup
        "MANIFEST-003",  # cleartext
        "MANIFEST-004",  # no network security config
        "MANIFEST-005",  # low target SDK

        # Secrets (from reused SEC-* IDs)
        "SEC-001",       # AWS key

        # Crypto
        "CRYPTO-001",    # MD5
        "CRYPTO-003",    # DES
        "CRYPTO-005",    # ECB

        # Logging
        "LOG-007",       # Log.d
        "LOG-008",       # System.out

        # Binary
        "ABIN-001",      # Non-PIE native lib
        "ABIN-002",      # No stack canaries

        # Transport
        "ATRANS-001",    # HTTP URL

        # Data storage
        "ADATA-001",     # Embedded database
        "ADATA-002",     # SharedPreferences
        "ADATA-003",     # External storage

        # Permissions
        "APERM-001",     # Overprivileged (SYSTEM_ALERT_WINDOW)
        "APERM-003",     # Permissions summary

        # Components
        "ACOMP-001",     # Exported component
        "ACOMP-002",     # Custom URI scheme
    }

    for eid in expected_ids:
        if eid not in finding_ids:
            errors.append(f"Expected finding ID '{eid}' not found in results")

    # Check severities
    severity_counts = report["summary"].get("severity_breakdown", {})
    total = report["summary"].get("total_findings", 0)

    if total < 15:
        errors.append(f"Expected at least 15 findings, got {total}")

    # Check we have some critical/high findings
    crit_high = severity_counts.get("Critical", 0) + severity_counts.get("High", 0)
    if crit_high < 3:
        errors.append(f"Expected at least 3 Critical/High findings, got {crit_high}")

    # Check OWASP mapping has entries
    owasp = report.get("owasp_mapping", [])
    mapped_categories = [o for o in owasp if o.get("finding_count", 0) > 0]
    if len(mapped_categories) < 3:
        errors.append(f"Expected at least 3 OWASP categories with findings, got {len(mapped_categories)}")

    return errors


if __name__ == "__main__":
    sys.exit(main())
