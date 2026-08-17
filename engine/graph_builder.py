"""
Graph builder: list[Principal] -> networkx.DiGraph

Builds the structural skeleton of the attack graph:
  - User --member_of--> Group
  - Principal --can_assume--> Role  (from trust policy, when the
    trust principal is another principal in this account)

Privilege-escalation technique edges (e.g. "can attach admin
policy to self") are added separately in engine/analyzer.py,
which operates on the graph this module produces.
"""

from __future__ import annotations
import networkx as nx
from engine.models import Principal, PrincipalType


def _trust_principal_arns(principal_field: dict | None) -> list[str]:
    """
    Extract ARN(s) from a trust statement's Principal field.
    Handles the common shapes:
        {"AWS": "arn:aws:iam::123456789012:user/foo"}
        {"AWS": ["arn:...", "arn:..."]}
        {"Service": "lambda.amazonaws.com"}  -> not a principal in our
            account, so returns [] (nothing for us to graph an edge to)
    """
    if not principal_field:
        return []

    aws_principals = principal_field.get("AWS")
    if aws_principals is None:
        return []  # e.g. Service principal like lambda.amazonaws.com

    if isinstance(aws_principals, str):
        return [aws_principals]
    return list(aws_principals)


def build_graph(principals: list[Principal]) -> nx.DiGraph:
    """
    Build a directed graph from parsed principals.

    Each node is keyed by ARN and stores the Principal object
    itself under the 'principal' attribute, so downstream code
    can always get back the full object from a node id.
    """
    graph = nx.DiGraph()

    for p in principals:
        graph.add_node(p.arn, principal=p, name=p.name, type=p.principal_type.value)

    known_arns = {p.arn for p in principals}
    by_name = {p.name: p.arn for p in principals}

    for p in principals:
        if p.principal_type == PrincipalType.USER:
            for group_name in p.group_memberships:
                group_arn = by_name.get(group_name)
                if group_arn:
                    graph.add_edge(p.arn, group_arn, relationship="member_of")

        if p.principal_type == PrincipalType.ROLE and p.trust_policy:
            for stmt in p.trust_policy.statements:
                if stmt.effect != "Allow":
                    continue
                for trusted_arn in _trust_principal_arns(stmt.principal):
                    # Only add an edge if the trusted principal is one
                    # we actually parsed (i.e. it's in this account's
                    # IAM export) — external/unknown ARNs are skipped
                    # for now, v1 doesn't model cross-account trust.
                    if trusted_arn in known_arns:
                        graph.add_edge(trusted_arn, p.arn, relationship="can_assume")

    return graph
