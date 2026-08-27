"""Run all rules against a Terraform tree."""

from __future__ import annotations

from pathlib import Path

from cloud_guardrails.models import SEV_ORDER, ScanResult
from cloud_guardrails.parser import parse_path
from cloud_guardrails.rules import ALL_RULES, Inventory


def scan(target: Path, *, rules=ALL_RULES) -> ScanResult:
    target = target.resolve()
    resources = parse_path(target)
    files = sorted({str(_rel(r.file)) for r in resources})
    inventory = Inventory(resources=resources)
    findings = []
    for rule in rules:
        findings.extend(rule.check(inventory))
    findings.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), f.rule_id, f.file, f.line, f.resource))
    return ScanResult(
        target=_rel(target),
        resources=resources,
        findings=findings,
        files=files,
    )


def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd()))
    except ValueError:
        return str(path)
