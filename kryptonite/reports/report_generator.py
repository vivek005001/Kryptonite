"""Generate structured JSON and HTML security reports."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Template

from kryptonite.core.finding import Finding, SeverityLevel
from kryptonite.core.owasp import OwaspCategory


def _risk_score(findings: list[Finding]) -> int:
    """Calculate a 0-100 risk score based on findings."""
    if not findings:
        return 0
    weights = {
        SeverityLevel.CRITICAL: 25,
        SeverityLevel.HIGH: 15,
        SeverityLevel.MEDIUM: 8,
        SeverityLevel.LOW: 3,
        SeverityLevel.INFO: 0,
    }
    raw = sum(weights.get(f.severity, 0) for f in findings)
    return min(100, raw)


def _risk_label(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def _build_report_data(
    findings: list[Finding],
    app_info: dict[str, str],
) -> dict[str, Any]:
    """Build the structured report dictionary."""
    severity_counts = Counter(f.severity.value for f in findings)
    owasp_counts: dict[str, int] = Counter()
    for f in findings:
        owasp_counts[f.owasp_category] += 1

    owasp_details: list[dict[str, Any]] = []
    for cat in OwaspCategory:
        count = owasp_counts.get(cat.code, 0)
        cat_findings = [
            fi.to_dict() for fi in findings if fi.owasp_category == cat.code
        ]
        owasp_details.append({
            **cat.to_dict(),
            "finding_count": count,
            "findings": cat_findings,
        })

    score = _risk_score(findings)

    return {
        "meta": {
            "tool": "Kryptonite",
            "version": "1.0.0",
            "scan_date": datetime.now(timezone.utc).isoformat(),
        },
        "app_info": app_info,
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": dict(severity_counts),
            "risk_score": score,
            "risk_label": _risk_label(score),
        },
        "owasp_mapping": owasp_details,
        "findings": [f.to_dict() for f in sorted(
            findings, key=lambda x: x.severity.numeric, reverse=True
        )],
    }


def generate_json(
    findings: list[Finding],
    app_info: dict[str, str],
    output_path: Path,
) -> Path:
    """Write the JSON report and return its path."""
    data = _build_report_data(findings, app_info)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as fp:
        json.dump(data, fp, indent=2)
    return output_path


def generate_html(
    findings: list[Finding],
    app_info: dict[str, str],
    output_path: Path,
) -> Path:
    """Render the HTML report and return its path."""
    data = _build_report_data(findings, app_info)
    template_path = Path(__file__).parent / "template.html"
    template_text = template_path.read_text()
    template = Template(template_text)
    html = template.render(**data)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
    return output_path
