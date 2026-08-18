"""
Technique: Create Policy Version (Managed Policy Modification)

If a principal has iam:CreatePolicyVersion on a customer-managed
policy that is ALSO attached to that same principal (directly, or
via group membership), it can create a new default version of that
policy granting itself arbitrary permissions — including full admin.

This is distinct from self_policy_attach: here the attacker needs
no permission on their own user/role ARN at all. They only need
permission to modify a POLICY DOCUMENT that happens to be attached
to them (directly or through a group they belong to).

Note: AWS-managed policies (e.g. arn:aws:iam::aws:policy/...) cannot
have new versions created by customers, so this technique only
applies to customer-managed policies.
"""

from __future__ import annotations
from engine.models import Principal

TECHNIQUE_ID = "create_policy_version"
TECHNIQUE_NAME = "Create Policy Version"

_ACTION = "iam:CreatePolicyVersion"


def _aws_managed(arn: str) -> bool:
    """AWS-managed policies live under the 'aws' account, not modifiable by customers."""
    return arn.startswith("arn:aws:iam::aws:policy/")


def _create_policy_version_resources(principal: Principal) -> list[str]:
    """Every resource pattern this principal has iam:CreatePolicyVersion on."""
    resources: list[str] = []
    for policy in principal.all_policies():
        for stmt in policy.statements:
            if stmt.effect != "Allow":
                continue
            if _ACTION in stmt.actions or "*" in stmt.actions:
                resources.extend(stmt.resources)
    return resources


def _attached_managed_policy_arns(principal: Principal) -> set[str]:
    """Customer-managed policy ARNs attached directly to this principal."""
    return {p.arn for p in principal.attached_policies if p.arn and not _aws_managed(p.arn)}


def _attached_via_groups(principal: Principal, graph) -> set[str]:
    """
    Customer-managed policy ARNs attached to any group this principal
    is a member of, discovered by walking the graph's member_of edges.
    """
    if graph is None or principal.arn not in graph:
        return set()

    arns: set[str] = set()
    for _, target, edge_data in graph.out_edges(principal.arn, data=True):
        if edge_data.get("relationship") != "member_of":
            continue
        group = graph.nodes[target].get("principal")
        if group is not None:
            arns |= _attached_managed_policy_arns(group)
    return arns


def check(principal: Principal, graph) -> bool:
    """
    Returns True if this principal can call iam:CreatePolicyVersion
    on at least one customer-managed policy that is attached to it,
    either directly or via group membership.
    """
    create_resources = _create_policy_version_resources(principal)
    if not create_resources:
        return False

    reachable_policy_arns = _attached_managed_policy_arns(principal) | _attached_via_groups(principal, graph)
    if not reachable_policy_arns:
        return False

    if "*" in create_resources:
        return True  # can modify ANY policy, and has at least one attached

    return any(arn in create_resources for arn in reachable_policy_arns)


def modifiable_attached_policy_arns(principal: Principal, graph) -> list[str]:
    """
    Which specific attached (direct or group-inherited) policies this
    principal could actually modify via this technique. Useful for
    finding descriptions.
    """
    create_resources = _create_policy_version_resources(principal)
    reachable = _attached_managed_policy_arns(principal) | _attached_via_groups(principal, graph)

    if "*" in create_resources:
        return list(reachable)
    return [arn for arn in reachable if arn in create_resources]
