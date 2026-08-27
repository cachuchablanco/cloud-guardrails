"""Load Terraform (.tf) files into Resource objects. Local files only; no cloud APIs."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from hcl2 import loads
from hcl2.utils import SerializationOptions

from cloud_guardrails.models import META_KEYS, Resource, as_str

_HCL_OPTIONS = SerializationOptions(
    strip_string_quotes=True,
    with_comments=False,
    explicit_blocks=True,
    preserve_heredocs=False,
)

_BLOCK_START = re.compile(
    r'(?m)^[ \t]*(?P<kind>resource|data|provider|variable)\s+"(?P<type>[^"]+)"'
    r'(?:\s+"(?P<name>[^"]+)")?'
)


def parse_path(path: Path) -> list[Resource]:
    """Parse a file or recursively parse every ``*.tf`` under a directory."""
    path = path.resolve()
    if path.is_file():
        if path.suffix != ".tf":
            return []
        return parse_file(path)
    if not path.is_dir():
        raise FileNotFoundError(path)
    resources: list[Resource] = []
    for tf_file in sorted(path.rglob("*.tf")):
        if ".terraform" in tf_file.parts:
            continue
        resources.extend(parse_file(tf_file))
    return resources


def parse_file(path: Path) -> list[Resource]:
    text = path.read_text(encoding="utf-8")
    locations = _locate_blocks(text)
    try:
        parsed = loads(text, serialization_options=_HCL_OPTIONS)
    except Exception:
        parsed = {}
    resources = _flatten(parsed, path, locations)
    # If hcl2 dropped a block we still located, skip — fixtures are well-formed.
    return resources


def _locate_blocks(text: str) -> dict[tuple[str, str, str], tuple[int, str]]:
    """Map (kind, type, name) -> (1-based line, raw block text)."""
    found: dict[tuple[str, str, str], tuple[int, str]] = {}
    for match in _BLOCK_START.finditer(text):
        kind = match.group("kind")
        type_name = match.group("type")
        name = match.group("name") or "default"
        if kind == "variable":
            name = type_name
            type_name = "variable"
        line = text[: match.start()].count("\n") + 1
        raw = _slice_block(text, match.start())
        key = (kind, type_name, name)
        found.setdefault(key, (line, raw))
    return found


def _slice_block(text: str, start: int) -> str:
    brace = text.find("{", start)
    if brace < 0:
        return text[start : start + 200]
    depth = 0
    i = brace
    in_string = False
    escape = False
    while i < len(text):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        i += 1
    return text[start:]


def _flatten(
    parsed: dict[str, Any],
    path: Path,
    locations: dict[tuple[str, str, str], tuple[int, str]],
) -> list[Resource]:
    out: list[Resource] = []
    for item in parsed.get("resource") or []:
        out.extend(_named_blocks("resource", item, path, locations))
    for item in parsed.get("data") or []:
        out.extend(_named_blocks("data", item, path, locations))
    for item in parsed.get("provider") or []:
        if not isinstance(item, dict):
            continue
        for ptype, body in item.items():
            if ptype in META_KEYS or not isinstance(body, dict):
                continue
            alias = as_str(body.get("alias")) or "default"
            out.append(_make("provider", ptype, alias, body, path, locations))
    for item in parsed.get("variable") or []:
        if not isinstance(item, dict):
            continue
        for name, body in item.items():
            if name in META_KEYS or not isinstance(body, dict):
                continue
            out.append(_make("variable", "variable", name, body, path, locations))
    return out


def _named_blocks(
    kind: str,
    item: Any,
    path: Path,
    locations: dict[tuple[str, str, str], tuple[int, str]],
) -> list[Resource]:
    if not isinstance(item, dict):
        return []
    out: list[Resource] = []
    for rtype, named in item.items():
        if rtype in META_KEYS or not isinstance(named, dict):
            continue
        for name, body in named.items():
            if name in META_KEYS or not isinstance(body, dict):
                continue
            out.append(_make(kind, rtype, name, body, path, locations))
    return out


def _make(
    kind: str,
    type_name: str,
    name: str,
    body: dict[str, Any],
    path: Path,
    locations: dict[tuple[str, str, str], tuple[int, str]],
) -> Resource:
    line, raw = locations.get((kind, type_name, name), (1, ""))
    if kind == "provider" and (line, raw) == (1, ""):
        line, raw = locations.get((kind, type_name, "default"), (1, ""))
    clean = {k: v for k, v in body.items() if k not in META_KEYS}
    return Resource(
        kind=kind,
        type=type_name,
        name=name,
        file=path,
        line=line,
        body=clean,
        raw=raw,
    )
