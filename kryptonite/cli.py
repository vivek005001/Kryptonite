"""CLI entry point for Kryptonite iOS security scanner."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from kryptonite import __version__
from kryptonite.core.ipa_parser import parse_ipa
from kryptonite.analyzers import (
    secrets_analyzer,
    crypto_analyzer,
    transport_analyzer,
    permissions_analyzer,
    binary_analyzer,
    data_storage_analyzer,
    url_scheme_analyzer,
    logging_analyzer,
)
from kryptonite.reports.report_generator import generate_json, generate_html


BANNER = r"""
 ╔═══════════════════════════════════════════════════════╗
 ║   ██╗  ██╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ║
 ║   ██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗║
 ║   █████╔╝ ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║║
 ║   ██╔═██╗ ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║║
 ║   ██║  ██╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝║
 ║   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ║
 ║        iOS Static Analysis Security Tool               ║
 ╚═══════════════════════════════════════════════════════╝
"""

ALL_ANALYZERS = [
    ("Hardcoded Secrets",      secrets_analyzer),
    ("Weak Cryptography",      crypto_analyzer),
    ("Transport Security",     transport_analyzer),
    ("Permissions Audit",      permissions_analyzer),
    ("Binary Protections",     binary_analyzer),
    ("Data Storage",           data_storage_analyzer),
    ("URL Schemes",            url_scheme_analyzer),
    ("Logging & Debug Code",   logging_analyzer),
]


def _progress(msg: str) -> None:
    """Print progress to stderr."""
    print(f"  ⏳ {msg}", file=sys.stderr)


def _done(msg: str) -> None:
    print(f"  ✅ {msg}", file=sys.stderr)


def _error(msg: str) -> None:
    print(f"  ❌ {msg}", file=sys.stderr)


def scan(ipa_path: str, output_dir: str, fmt: str) -> int:
    """Run the full scan pipeline. Returns exit code."""
    print(BANNER, file=sys.stderr)

    ipa = Path(ipa_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # ── Extract IPA ──────────────────────────────────────────────
    _progress(f"Extracting {ipa.name}...")
    start = time.time()
    try:
        ctx = parse_ipa(ipa)
    except Exception as exc:
        _error(f"Failed to parse IPA: {exc}")
        return 2

    elapsed = time.time() - start
    _done(f"Extracted {len(ctx.all_files)} files from {ctx.bundle_name} "
          f"({ctx.bundle_id}) in {elapsed:.1f}s")
    _done(f"Binary: {ctx.binary_path.name if ctx.binary_path else 'not found'} "
          f"| {len(ctx.binary_strings)} strings extracted")

    # ── Run analyzers ────────────────────────────────────────────
    all_findings = []
    for name, analyzer in ALL_ANALYZERS:
        _progress(f"Running {name} analyzer...")
        try:
            results = analyzer.run(ctx)
            all_findings.extend(results)
            _done(f"{name}: {len(results)} finding(s)")
        except Exception as exc:
            _error(f"{name} analyzer failed: {exc}")

    # ── App metadata ─────────────────────────────────────────────
    app_info = {
        "bundle_name": ctx.bundle_name,
        "bundle_id": ctx.bundle_id,
        "bundle_version": ctx.bundle_version,
        "min_os_version": ctx.min_os_version,
        "ipa_file": ipa.name,
        "total_files": str(len(ctx.all_files)),
    }

    # ── Generate reports ─────────────────────────────────────────
    print("", file=sys.stderr)
    _progress("Generating reports...")

    if fmt in ("json", "all"):
        json_path = generate_json(all_findings, app_info, out / "report.json")
        _done(f"JSON report → {json_path}")

    if fmt in ("html", "all"):
        html_path = generate_html(all_findings, app_info, out / "report.html")
        _done(f"HTML report → {html_path}")

    # ── Summary ──────────────────────────────────────────────────
    print("", file=sys.stderr)
    sev_counts = {}
    for f in all_findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

    print("  ╔══════════════════════════════════════╗", file=sys.stderr)
    print(f"  ║  Scan Complete — {len(all_findings)} findings          ║", file=sys.stderr)
    print("  ╠══════════════════════════════════════╣", file=sys.stderr)
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = sev_counts.get(sev, 0)
        icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡",
                "Low": "🟢", "Info": "🔵"}.get(sev, "⚪")
        print(f"  ║  {icon} {sev:10s}: {count:3d}                    ║", file=sys.stderr)
    print("  ╚══════════════════════════════════════╝", file=sys.stderr)
    print("", file=sys.stderr)

    # Cleanup
    ctx.cleanup()

    return 1 if any(
        f.severity.value in ("Critical", "High") for f in all_findings
    ) else 0


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="kryptonite",
        description="🛡️  Kryptonite — iOS IPA Static Analysis Security Tool",
    )
    parser.add_argument(
        "--version", action="version", version=f"kryptonite {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="Scan an IPA file")
    scan_parser.add_argument("ipa", help="Path to the .ipa file")
    scan_parser.add_argument(
        "--output-dir", "-o", default="./kryptonite-report",
        help="Output directory for reports (default: ./kryptonite-report)",
    )
    scan_parser.add_argument(
        "--format", "-f", choices=["json", "html", "all"], default="all",
        help="Report format (default: all)",
    )

    args = parser.parse_args()

    if args.command != "scan":
        parser.print_help()
        sys.exit(0)

    code = scan(args.ipa, args.output_dir, args.format)
    sys.exit(code)


if __name__ == "__main__":
    main()
