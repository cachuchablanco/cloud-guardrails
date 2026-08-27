from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from cloud_guardrails.cli import main
from tests.conftest import INSECURE, SECURE, ROOT


def test_scan_insecure_exits_one_and_writes_json(tmp_path: Path) -> None:
    out = tmp_path / "out"
    code = main(["scan", str(INSECURE), "--out", str(out)])
    assert code == 1
    report = out / "findings.json"
    assert report.is_file()
    data = json.loads(report.read_text())
    assert data["scanner"] == "cloud-guardrails"
    assert data["summary"]["fail"] >= 8
    required = {
        "severity",
        "rule_id",
        "title",
        "cis",
        "file",
        "line",
        "resource",
        "evidence",
        "remediation",
    }
    assert data["findings"]
    for item in data["findings"]:
        assert required <= set(item)
        assert item["severity"] in {"fail", "warn", "pass"}


def test_scan_secure_exits_zero(tmp_path: Path) -> None:
    code = main(["scan", str(SECURE), "--out", str(tmp_path / "out")])
    assert code == 0


def test_missing_path_exits_two() -> None:
    assert main(["scan", "/no/such/terraform/path"]) == 2


def test_module_entrypoint(tmp_path: Path) -> None:
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, "-m", "cloud_guardrails", "scan", str(INSECURE), "--out", str(out)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "CG-S3-001" in proc.stdout
    assert "FAIL" in proc.stdout
    assert (out / "findings.json").is_file()


def test_insecure_scan_in_pytest_not_ci_step(insecure) -> None:
    """CI must assert the insecure tree FAILs here — do not `scan` as a job step that exits 1."""
    assert insecure.has_fail
    ids = {f.rule_id for f in insecure.findings if f.severity == "fail"}
    assert "CG-S3-001" in ids
    assert "CG-SG-001" in ids
