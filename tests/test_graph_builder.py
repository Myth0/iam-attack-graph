"""Tests for engine.graph_builder"""

import json
import pytest
from pathlib import Path
from engine.parser import parse_iam_export
from engine.graph_builder import build_graph, _trust_principal_arns

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_iam_export.json"


@pytest.fixture
def sample_graph():
    with open(FIXTURE_PATH) as f:
        data = json.load(f)
    principals = parse_iam_export(data)
    return build_graph(principals)


def test_all_principals_become_nodes(sample_graph):
    assert sample_graph.number_of_nodes() == 3


def test_user_member_of_group_edge_exists(sample_graph):
    user_arn = "arn:aws:iam::123456789012:user/test-user"
    group_arn = "arn:aws:iam::123456789012:group/developers"
    assert sample_graph.has_edge(user_arn, group_arn)
    assert sample_graph[user_arn][group_arn]["relationship"] == "member_of"


def test_service_principal_trust_does_not_create_edge(sample_graph):
    """A role trusted by a Service (e.g. lambda.amazonaws.com), not an
    account principal, should not produce a can_assume edge."""
    assert sample_graph.number_of_edges() == 1  # only the member_of edge


def test_trust_principal_arns_handles_single_string():
    result = _trust_principal_arns({"AWS": "arn:aws:iam::123456789012:user/foo"})
    assert result == ["arn:aws:iam::123456789012:user/foo"]


def test_trust_principal_arns_handles_list():
    result = _trust_principal_arns({"AWS": ["arn:1", "arn:2"]})
    assert result == ["arn:1", "arn:2"]


def test_trust_principal_arns_handles_service_principal():
    """Service principals (not AWS account principals) should yield no ARNs."""
    result = _trust_principal_arns({"Service": "lambda.amazonaws.com"})
    assert result == []


def test_trust_principal_arns_handles_none():
    assert _trust_principal_arns(None) == []


def test_unknown_trusted_arn_is_skipped():
    """If a trust policy trusts an ARN not present in our parsed principals
    (e.g. cross-account), no edge should be created for it (v1 limitation)."""
    from engine.models import Principal, PrincipalType, Policy, Statement

    role = Principal(
        name="external-trust-role",
        arn="arn:aws:iam::123456789012:role/external-trust-role",
        principal_type=PrincipalType.ROLE,
        trust_policy=Policy(
            name="trust-policy",
            is_inline=True,
            statements=[Statement(
                effect="Allow",
                principal={"AWS": "arn:aws:iam::999999999999:user/outsider"},
            )],
        ),
    )
    graph = build_graph([role])
    assert graph.number_of_edges() == 0  # outsider ARN unknown, so skipped
