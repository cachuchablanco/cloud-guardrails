"""Human table + JSON report writer."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from cloud_guardrails import __version__
from cloud_guardrails.models import ScanResult

SEV_PAD = {"fail": "FAIL", "warn": "WARN", "pass": "PASS"}


def write_json(result: ScanResult, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "findings.json"
    payload = {
        "scanner": "cloud-guardrails",
        "version": __version__,
        "target": result.target,
        "summary": result.summary,
        "findings": [f.to_dict() for f in result.findings],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def render_table(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append(f"Cloud Guardrails — scanning {result.target}")
    n_files = result.summary["files"]
    n_res = result.summary["resources"]
    lines.append(f"  parsed  {n_res} blocks  from {n_files} file{'s' if n_files != 1 else ''}")
    lines.append("")
    if not result.findings:
        lines.append("Findings")
        lines.append("  (none)")
        return "\n".join(lines)

    grouped: dict[str, list] = defaultdict(list)
    for finding in result.findings:
        grouped[finding.severity].append(finding)

    for sev in ("fail", "warn", "pass"):
        bucket = grouped.get(sev) or []
        if not bucket:
            continue
        label = SEV_PAD[sev]
        lines.append(f"{label}  ({len(bucket)})")
        for finding in bucket:
            loc = f"{finding.file}:{finding.line}"
            lines.append(f"  {label}  {finding.rule_id:<10}  {finding.resource}")
            lines.append(f"        {finding.title}  [{finding.cis}]")
            lines.append(f"        {loc}")
            if finding.evidence:
                lines.append(f"        {finding.evidence}")
            if finding.severity != "pass" and finding.remediation:
                lines.append(f"        → {finding.remediation}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_summary_line(result: ScanResult, json_path: Path) -> str:
    s = result.summary
    return (
        f"Summary  FAIL={s['fail']}  WARN={s['warn']}  PASS={s['pass']}\n"
        f"Wrote {len(result.findings)} findings → {json_path}"
    )
