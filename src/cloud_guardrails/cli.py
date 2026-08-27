"""Command-line interface: `cloud-guardrails scan fixtures/`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cloud_guardrails import __version__
from cloud_guardrails.report import render_summary_line, render_table, write_json
from cloud_guardrails.scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-guardrails",
        description="Scan Terraform fixtures for common cloud misconfigurations (CIS-mapped).",
    )
    parser.add_argument("--version", action="version", version=f"cloud-guardrails {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a .tf file or directory of fixtures.")
    scan_p.add_argument("path", type=Path, help="Terraform file or directory (e.g. fixtures/insecure)")
    scan_p.add_argument(
        "--out",
        type=Path,
        default=Path("out"),
        help="Output directory for findings.json (default: out/)",
    )
    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    target: Path = args.path
    if not target.exists():
        print(f"error: path not found: {target}", file=sys.stderr)
        return 2
    result = scan(target)
    json_path = write_json(result, args.out)
    print(render_table(result), end="")
    print()
    print(render_summary_line(result, json_path))
    return 1 if result.has_fail else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
