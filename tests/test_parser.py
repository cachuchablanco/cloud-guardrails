from __future__ import annotations

from cloud_guardrails.parser import parse_path
from tests.conftest import INSECURE, SECURE


def test_insecure_parses_expected_types() -> None:
    resources = parse_path(INSECURE)
    types = {r.type for r in resources if r.kind == "resource"}
    assert "aws_s3_bucket" in types
    assert "aws_security_group" in types
    assert "aws_iam_policy" in types
    assert "aws_db_instance" in types
    assert "aws_instance" in types
    assert "aws_vpc" in types
    assert any(r.kind == "provider" for r in resources)
    assert all(r.line >= 1 for r in resources)
    assert any(r.raw for r in resources)


def test_secure_parses_flow_log_and_pab() -> None:
    resources = parse_path(SECURE)
    types = {r.type for r in resources if r.kind == "resource"}
    assert "aws_flow_log" in types
    assert "aws_s3_bucket_public_access_block" in types
    assert "aws_s3_bucket_server_side_encryption_configuration" in types


def test_nested_ingress_blocks_are_lists() -> None:
    resources = parse_path(INSECURE)
    sg = next(r for r in resources if r.address == "aws_security_group.app")
    ingress = sg.nested("ingress")
    assert len(ingress) >= 3
    ports = {(b.get("from_port"), b.get("to_port")) for b in ingress}
    assert (22, 22) in ports
    assert (3389, 3389) in ports
