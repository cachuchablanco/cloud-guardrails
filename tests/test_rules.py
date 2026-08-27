from __future__ import annotations

from cloud_guardrails.models import Finding, ScanResult

RULE_IDS = {
    "CG-S3-001",
    "CG-SG-001",
    "CG-ENC-001",
    "CG-IAM-001",
    "CG-VPC-001",
    "CG-RDS-001",
    "CG-EC2-001",
    "CG-SEC-001",
}


def _fails(result: ScanResult, rule_id: str) -> list[Finding]:
    return [f for f in result.findings if f.rule_id == rule_id and f.severity == "fail"]


def test_insecure_fires_every_rule(insecure: ScanResult) -> None:
    failed_ids = {f.rule_id for f in insecure.findings if f.severity == "fail"}
    missing = RULE_IDS - failed_ids
    assert not missing, f"rules with no FAIL on insecure fixtures: {sorted(missing)}"
    assert insecure.has_fail
    assert insecure.summary["fail"] >= len(RULE_IDS)


def test_s3_public(insecure: ScanResult) -> None:
    fails = _fails(insecure, "CG-S3-001")
    resources = {f.resource for f in fails}
    assert "aws_s3_bucket.public_logs" in resources
    blob = " ".join(f.evidence.lower() for f in fails)
    assert "public" in blob or "principal" in blob or "acl" in blob


def test_security_group_world_open(insecure: ScanResult) -> None:
    fails = _fails(insecure, "CG-SG-001")
    assert fails
    blob = " ".join(f.evidence for f in fails)
    assert "22" in blob
    assert "3389" in blob
    warns = [f for f in insecure.findings if f.rule_id == "CG-SG-001" and f.severity == "warn"]
    assert warns, "HTTP/80 from 0.0.0.0/0 should be WARN"


def test_encryption(insecure: ScanResult) -> None:
    fails = _fails(insecure, "CG-ENC-001")
    resources = {f.resource for f in fails}
    assert "aws_s3_bucket.public_logs" in resources
    assert "aws_ebs_volume.data" in resources
    assert "aws_db_instance.app" in resources
    assert "aws_instance.web" in resources


def test_iam_admin(insecure: ScanResult) -> None:
    fails = _fails(insecure, "CG-IAM-001")
    resources = {f.resource for f in fails}
    assert "aws_iam_policy.full_admin" in resources
    assert any("AdministratorAccess" in f.evidence for f in fails)


def test_vpc_flow_logs(insecure: ScanResult) -> None:
    fails = _fails(insecure, "CG-VPC-001")
    assert any(f.resource == "aws_vpc.main" for f in fails)


def test_public_rds(insecure: ScanResult) -> None:
    fails = _fails(insecure, "CG-RDS-001")
    assert any(f.resource == "aws_db_instance.app" for f in fails)
    assert any("publicly_accessible" in f.evidence for f in fails)


def test_imds(insecure: ScanResult) -> None:
    fails = _fails(insecure, "CG-EC2-001")
    assert any(f.resource == "aws_instance.web" for f in fails)
    assert any("optional" in f.evidence or "http_tokens" in f.evidence for f in fails)


def test_hardcoded_secrets(insecure: ScanResult) -> None:
    fails = _fails(insecure, "CG-SEC-001")
    blob = " ".join(f.evidence.lower() + f.resource for f in fails)
    assert "password" in blob or "aws_db_instance.app" in blob
    assert "access_key" in blob or "secret_key" in blob or "provider.aws" in blob
    # evidence must not dump the full secret
    for f in fails:
        assert "ChangeMeNow-LabOnly!" not in f.evidence
        assert "examplesecretkeynotreal00000000000000" not in f.evidence


def test_findings_have_cis_and_location(insecure: ScanResult) -> None:
    fails = [f for f in insecure.findings if f.severity == "fail"]
    assert fails
    for f in fails:
        assert f.cis
        assert f.file.endswith(".tf")
        assert f.line >= 1
        assert f.resource
        assert f.remediation
        assert f.rule_id in RULE_IDS


def test_secure_has_no_fails(secure: ScanResult) -> None:
    fails = [f for f in secure.findings if f.severity == "fail"]
    assert fails == [], [f"{f.rule_id} {f.resource}: {f.evidence}" for f in fails]


def test_secure_emits_passes(secure: ScanResult) -> None:
    passed = {f.rule_id for f in secure.findings if f.severity == "pass"}
    # secrets rule is fail-only; the rest should show pass on the hardened tree
    expected = RULE_IDS - {"CG-SEC-001"}
    missing = expected - passed
    assert not missing, f"no PASS on secure fixtures for {sorted(missing)}"
