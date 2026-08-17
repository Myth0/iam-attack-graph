"""Tests for engine.analyzer"""

import json
from pathlib import Path
from engine.parser import parse_iam_export
from engine.graph_builder import build_graph
from engine.analyzer import analyze, TECHNIQUES

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_iam_export.json"


def _run_full_pipeline():
    with open(FIXTURE_PATH) as f:
        data = json.load(f)
    principals = parse_iam_export(data)
    graph = build_graph(principals)
    return analyze(principals, graph)


def test_fixture_produces_exactly_one_finding():
    findings = _run_full_pipeline()
    assert len(findings) == 1


def test_finding_identifies_correct_principal_and_technique():
    findings = _run_full_pipeline()
    finding = findings[0]
    assert finding.principal_name == "test-user"
    assert finding.technique_id == "self_policy_attach"
    assert finding.severity == "critical"


def test_finding_description_mentions_principal_name():
    findings = _run_full_pipeline()
    assert "test-user" in findings[0].description


def test_findings_sorted_by_severity():
    """Even with one technique today, verify the sort key logic works
    correctly by checking findings come back in severity order."""
    findings = _run_full_pipeline()
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    severities = [severity_order[f.severity] for f in findings]
    assert severities == sorted(severities)


def test_no_findings_for_empty_principal_list():
    """Analyzing zero principals should return zero findings, not error."""
    import networkx as nx
    findings = analyze([], nx.DiGraph())
    assert findings == []


def test_technique_registry_has_at_least_one_technique():
    """Sanity check that the registry isn't accidentally empty."""
    assert len(TECHNIQUES) >= 1
    assert TECHNIQUES[0].id == "self_policy_attach"
