"""Helpers for IAM / S3 policy documents (JSON strings or jsonencode interpolations)."""

from __future__ import annotations

import json
import re
from typing import Any

from cloud_guardrails.models import as_str, as_str_list

_JSONENCODE_RE = re.compile(r"jsonencode\s*\(\s*\{(?P<body>.*)\}\s*\)", re.S)


def parse_policy(value: Any) -> dict[str, Any] | None:
    """Best-effort parse of a Terraform policy attribute into a dict."""
    if isinstance(value, dict):
        return value
    text = as_str(value)
    if not text:
        return None
    raw = str(value)
    try:
        loaded = json.loads(text)
        if isinstance(loaded, dict):
            return loaded
    except json.JSONDecodeError:
        pass
    if "jsonencode" in raw or "jsonencode" in text:
        return _from_jsonencode(text)
    return None


def statements(policy: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not policy:
        return []
    stmt = policy.get("Statement") or policy.get("statement") or []
    if isinstance(stmt, dict):
        return [stmt]
    if isinstance(stmt, list):
        return [s for s in stmt if isinstance(s, dict)]
    return []


def is_allow(stmt: dict[str, Any]) -> bool:
    effect = as_str(stmt.get("Effect") or stmt.get("effect") or "Allow")
    return (effect or "Allow").lower() == "allow"


def actions_of(stmt: dict[str, Any]) -> list[str]:
    return as_str_list(stmt.get("Action") or stmt.get("action") or stmt.get("actions"))


def resources_of(stmt: dict[str, Any]) -> list[str]:
    return as_str_list(stmt.get("Resource") or stmt.get("resource") or stmt.get("resources"))


def is_star_admin(stmt: dict[str, Any]) -> bool:
    if not is_allow(stmt):
        return False
    acts = actions_of(stmt)
    res = resources_of(stmt)
    return _is_star(acts) and _is_star(res)


def principal_is_public(stmt: dict[str, Any]) -> bool:
    principal = stmt.get("Principal") or stmt.get("principal")
    if principal is None:
        return False
    if principal == "*" or as_str(principal) == "*":
        return True
    if isinstance(principal, dict):
        for key in ("AWS", "aws", "*"):
            if key not in principal:
                continue
            vals = as_str_list(principal.get(key))
            if "*" in vals or as_str(principal.get(key)) == "*":
                return True
    return "*" in as_str_list(principal)


def _is_star(values: list[str]) -> bool:
    return any(v.strip() == "*" for v in values)


def _from_jsonencode(text: str) -> dict[str, Any] | None:
    """Pull Action/Resource/Effect/Principal out of a jsonencode({...}) blob."""
    match = _JSONENCODE_RE.search(text)
    body = match.group("body") if match else text
    stmt: dict[str, Any] = {}
    effect = _hcl_assign(body, "Effect") or _hcl_assign(body, "effect")
    action = _hcl_assign(body, "Action") or _hcl_assign(body, "actions")
    resource = _hcl_assign(body, "Resource") or _hcl_assign(body, "resources")
    principal = _hcl_assign(body, "Principal") or _hcl_assign(body, "principal")
    if effect:
        stmt["Effect"] = effect
    if action:
        stmt["Action"] = action
    if resource:
        stmt["Resource"] = resource
    if principal:
        stmt["Principal"] = principal
    if not stmt:
        return None
    return {"Statement": [stmt]}


def _hcl_assign(body: str, key: str) -> str | list[str] | None:
    # Action = "*"  or Action = ["*"]
    scalar = re.search(rf'{re.escape(key)}\s*=\s*"([^"]*)"', body)
    if scalar:
        return scalar.group(1)
    listed = re.search(rf"{re.escape(key)}\s*=\s*\[([^\]]*)\]", body)
    if listed:
        return re.findall(r'"([^"]*)"', listed.group(1))
    return None
