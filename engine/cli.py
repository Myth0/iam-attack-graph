"""
CLI entrypoint for the IAM Attack Path Grapher engine.

Usage:
    python -m engine.cli path/to/iam_export.json

Runs the full pipeline (parse -> graph -> analyze) and prints
findings to stdout. This is the engine running standalone, with
no API or frontend involved.
"""

from __future__ import annotations
import argparse
import json
import sys

from engine.parser import parse_iam_export
from engine.graph_builder import build_graph
from engine.analyzer import analyze


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze an AWS IAM export for privilege escalation paths."
    )
    parser.add_argument(
        "export_path",
        help="Path to JSON output from 'aws iam get-account-authorization-details'",
    )
    args = parser.parse_args()

    try:
        with open(args.export_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: file not found: {args.export_path}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in {args.export_path}: {e}", file=sys.stderr)
        return 1

    principals = parse_iam_export(data)
    graph = build_graph(principals)
    findings = analyze(principals, graph)

    print(f"Analyzed {len(principals)} principals, {graph.number_of_edges()} relationships.")
    print(f"Found {len(findings)} privilege escalation finding(s).\n")

    for finding in findings:
        print(f"[{finding.severity.upper()}] {finding.principal_name} ({finding.technique_name})")
        print(f"  {finding.description}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
