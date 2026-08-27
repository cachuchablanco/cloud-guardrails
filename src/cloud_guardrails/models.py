"""Shared data types for parsed Terraform and scan findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

Severity = Literal["fail", "warn", "pass"]

SEV_ORDER = {"fail": 0, "warn": 1, "pass": 2}

META_KEYS = frozenset(
    {"__is_block__", "__comments__", "__inline_comments__", "__start_line__", "__end_line__"}
)


@dataclass
class Resource:
    """One Terraform block: resource, data, provider, or variable."""

    kind: str
    type: str
    name: str
    file: Path
    line: int
    body: dict[str, Any]
    raw: str = ""

    @property
    def address(self) -> str:
        if self.kind == "data":
            return f"data.{self.type}.{self.name}"
        if self.kind == "provider":
            if self.name and self.name != "default":
                return f"provider.{self.type}.{self.name}"
            return f"provider.{self.type}"
        if self.kind == "variable":
            return f"var.{self.name}"
        return f"{self.type}.{self.name}"

    def attr(self, key: str, default: Any = None) -> Any:
        return self.body.get(key, default)

    def nested(self, key: str) -> list[dict[str, Any]]:
        return as_blocks(self.body.get(key))


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    cis: str
    file: str
    line: int
    resource: str
    evidence: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    resources: list[Resource] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts = {"fail": 0, "warn": 0, "pass": 0}
        for finding in self.findings:
            counts[finding.severity] += 1
        return {
            "fail": counts["fail"],
            "warn": counts["warn"],
            "pass": counts["pass"],
            "resources": len(self.resources),
            "files": len(self.files),
        }

    @property
    def has_fail(self) -> bool:
        return any(f.severity == "fail" for f in self.findings)


def as_blocks(value: Any) -> list[dict[str, Any]]:
    """Normalize a nested HCL block (single dict or list of dicts)."""
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def as_str(value: Any) -> str | None:
    if value is None or isinstance(value, dict):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        if len(value) == 1:
            return as_str(value[0])
        return None
    text = str(value)
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]
    if text.startswith("${") and text.endswith("}"):
        return text[2:-1]
    return text


def as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(as_str_list(item))
        return out
    text = as_str(value)
    return [text] if text is not None else []


def as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = as_str(value)
    if text is None:
        return None
    lowered = text.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


def looks_like_ref(value: Any) -> bool:
    """True if the value is a Terraform interpolation / resource reference, not a literal."""
    text = as_str(value)
    if not text:
        return False
    raw = str(value)
    if raw.startswith("${") or text.startswith("${"):
        return True
    prefixes = (
        "var.",
        "local.",
        "data.",
        "module.",
        "aws_",
        "random_",
        "file(",
        "jsonencode(",
        "sensitive(",
        "trimspace(",
        "aws_secretsmanager",
        "nonsensitive(",
    )
    return text.startswith(prefixes)


def line_of(resource: Resource, needle: str) -> int:
    """Best-effort line of an attribute inside a raw block."""
    if not needle:
        return resource.line
    snippet = needle.strip().splitlines()[0].strip()[:80]
    if not snippet:
        return resource.line
    for offset, line in enumerate(resource.raw.splitlines()):
        if snippet in line:
            return resource.line + offset
    # try a shorter token
    token = snippet.split("=")[0].strip().strip('"')
    if token and token != snippet:
        for offset, line in enumerate(resource.raw.splitlines()):
            if token in line:
                return resource.line + offset
    return resource.line


def excerpt(text: str, limit: int = 180) -> str:
    collapsed = " ".join(text.strip().split())
    if len(collapsed) > limit:
        return collapsed[: limit - 3] + "..."
    return collapsed
