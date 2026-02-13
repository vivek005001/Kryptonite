"""Validate that the scan results contain expected findings."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def validate(output_dir: str = "tests/output") -> bool:
    """Validate the JSON report has expected findings."""
    report_path = Path(output_dir) / "report.json"
    html_path = Path(output_dir) / "report.html"

    if not report_path.exists():
        print(f"❌ JSON report not found: {report_path}")
        return False

    if not html_path.exists():
        print(f"❌ HTML report not found: {html_path}")
        return False

    with open(report_path) as fp:
        data = json.load(fp)

    findings = data["findings"]
    summary = data["summary"]

    print(f"\n📊 Validation Results")
    print(f"{'=' * 50}")
    print(f"  Total findings: {summary['total_findings']}")
    print(f"  Risk score:     {summary['risk_score']}/100 ({summary['risk_label']})")
    print(f"  Severity breakdown:")
    for sev, count in sorted(summary["severity_breakdown"].items()):
        print(f"    {sev}: {count}")

    # ── Validate expected OWASP categories ───────────────────────
    owasp_cats_with_findings = set()
    for f in findings:
        owasp_cats_with_findings.add(f["owasp_category"])

    expected_categories = {"M1", "M3", "M5", "M6", "M7", "M8", "M9", "M10"}
    print(f"\n🔗 OWASP Categories with findings: {sorted(owasp_cats_with_findings)}")

    missing = expected_categories - owasp_cats_with_findings
    if missing:
        print(f"⚠️  Missing expected categories: {sorted(missing)}")

    # ── Validate specific finding IDs ────────────────────────────
    finding_ids = {f["id"] for f in findings}

    expected_ids = {
        "SEC-001":   "AWS Access Key detection",
        "SEC-006":   "Private key block detection",
        "SEC-007":   "Hardcoded password detection",
        "SEC-009":   "DB connection string detection",
        "CRYPTO-001": "MD5 usage",
        "CRYPTO-003": "3DES usage",
        "CRYPTO-005": "ECB mode usage",
        "CRYPTO-006": "Hardcoded encryption key",
        "TRANS-001": "ATS disabled",
        "TRANS-002": "Arbitrary loads in web content",
        "TRANS-003": "Per-domain insecure HTTP",
        "TRANS-004": "Weak TLS version",
        "PERM-001":  "Insufficient usage description",
        "PERM-002":  "Excessive permissions",
        "URL-001":   "Custom URL scheme",
        "URL-002":   "Excessive URL schemes",
        "BIN-001":   "PIE check",
        "BIN-002":   "Stack canary check",
        "BIN-003":   "ARC check",
        "LOG-001":   "NSLog detection",
        "LOG-005":   "Staging server reference",
        "DATA-001":  "Embedded database",
        "DATA-002":  "Sensitive plist keys",
        "DATA-003":  "NSUserDefaults usage",
    }

    print(f"\n🔍 Finding ID Validation:")
    passed = 0
    failed = 0
    for fid, desc in sorted(expected_ids.items()):
        if fid in finding_ids:
            print(f"  ✅ {fid}: {desc}")
            passed += 1
        else:
            print(f"  ❌ {fid}: {desc} — NOT FOUND")
            failed += 1

    # ── Validate severities ──────────────────────────────────────
    print(f"\n📋 Severity distribution check:")
    has_critical = any(f["severity"] == "Critical" for f in findings)
    has_high = any(f["severity"] == "High" for f in findings)
    has_medium = any(f["severity"] == "Medium" for f in findings)

    for level, present in [("Critical", has_critical), ("High", has_high), ("Medium", has_medium)]:
        status = "✅" if present else "❌"
        print(f"  {status} Has {level} findings: {present}")

    # ── Validate report structure ────────────────────────────────
    print(f"\n📄 Report structure check:")
    required_keys = {"meta", "app_info", "summary", "owasp_mapping", "findings"}
    has_all_keys = required_keys.issubset(data.keys())
    print(f"  {'✅' if has_all_keys else '❌'} All top-level keys present")

    all_have_remediation = all(f.get("remediation") for f in findings
                               if f["severity"] != "Info")
    print(f"  {'✅' if all_have_remediation else '❌'} All non-info findings have remediation")

    html_size = html_path.stat().st_size
    print(f"  ✅ HTML report size: {html_size / 1024:.1f} KB")

    # ── Final verdict ────────────────────────────────────────────
    print(f"\n{'=' * 50}")
    print(f"  Passed: {passed}/{passed + failed} expected findings")

    success = failed <= 3  # Allow up to 3 misses
    if success:
        print(f"  🎉 VALIDATION PASSED")
    else:
        print(f"  💥 VALIDATION FAILED ({failed} missing findings)")

    return success


if __name__ == "__main__":
    ok = validate()
    sys.exit(0 if ok else 1)
