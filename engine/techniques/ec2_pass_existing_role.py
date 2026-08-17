"""
Technique: EC2 PassRole to Existing Role

If a principal has both iam:PassRole (on a role, or '*') and
ec2:RunInstances, it can launch a new EC2 instance with an existing
IAM role attached via an instance profile. Once running, the
instance's metadata service hands out temporary credentials for
that role — meaning the principal has effectively become that role,
without ever calling sts:AssumeRole directly.

iam:PassRole is one of the most commonly over-granted permissions
in real AWS environments, making this a high-frequency real-world
escalation path.
"""

from __future__ import annotations
from engine.models import Principal

TECHNIQUE_ID = "ec2_pass_existing_role"
TECHNIQUE_NAME = "EC2 PassRole to Existing Role"

_PASS_ROLE_ACTION = "iam:PassRole"
_RUN_INSTANCES_ACTION = "ec2:RunInstances"


def _has_action(principal: Principal, target_action: str) -> bool:
    """Check if principal has any Allow statement granting this action (or '*')."""
    for policy in principal.all_policies():
        for stmt in policy.statements:
            if stmt.effect != "Allow":
                continue
            if target_action in stmt.actions or "*" in stmt.actions:
                return True
    return False


def _pass_role_resources(principal: Principal) -> list[str]:
    """Collect every resource pattern granted iam:PassRole permission."""
    resources: list[str] = []
    for policy in principal.all_policies():
        for stmt in policy.statements:
            if stmt.effect != "Allow":
                continue
            if _PASS_ROLE_ACTION in stmt.actions or "*" in stmt.actions:
                resources.extend(stmt.resources)
    return resources


def check(principal: Principal, graph) -> bool:
    """
    Returns True if this principal has BOTH iam:PassRole and
    ec2:RunInstances — the minimum combination needed for this
    escalation technique, regardless of which specific role(s)
    can be passed.
    """
    return _has_action(principal, _PASS_ROLE_ACTION) and _has_action(principal, _RUN_INSTANCES_ACTION)


def passable_role_arns(principal: Principal, all_role_arns: list[str]) -> list[str]:
    """
    Given the full list of role ARNs in the account, return which
    ones this principal could pass to a new EC2 instance.

    A wildcard '*' resource on the PassRole statement means every
    role in the account is passable. Otherwise, only explicitly
    named role ARNs count.
    """
    if not check(principal, None):
        return []

    granted_resources = _pass_role_resources(principal)

    if "*" in granted_resources:
        return list(all_role_arns)

    return [arn for arn in all_role_arns if arn in granted_resources]
