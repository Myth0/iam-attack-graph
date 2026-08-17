"""
Technique: Self Policy Attach

If a principal can call iam:AttachUserPolicy / iam:PutUserPolicy
(for Users) or iam:AttachRolePolicy / iam:PutRolePolicy (for Roles)
against its OWN arn, it can grant itself any permissions it wants
— including AdministratorAccess — with no further steps required.

This is one of the most direct, well-documented AWS IAM privilege
escalation techniques.
"""

from __future__ import annotations
from engine.models import Principal, PrincipalType

TECHNIQUE_ID = "self_policy_attach"
TECHNIQUE_NAME = "Self Policy Attach"

_USER_ACTIONS = {"iam:AttachUserPolicy", "iam:PutUserPolicy"}
_ROLE_ACTIONS = {"iam:AttachRolePolicy", "iam:PutRolePolicy"}


def _resource_matches_self(resources: list[str], own_arn: str) -> bool:
    """
    A statement's Resource grants self-modification if it's a
    wildcard ('*') or explicitly names this principal's own ARN.
    """
    for r in resources:
        if r == "*" or r == own_arn:
            return True
    return False


def check(principal: Principal) -> bool:
    """
    Returns True if this principal can attach/put a policy on itself,
    i.e. can trivially escalate to any permission level including admin.
    """
    if principal.principal_type == PrincipalType.USER:
        relevant_actions = _USER_ACTIONS
    elif principal.principal_type == PrincipalType.ROLE:
        relevant_actions = _ROLE_ACTIONS
    else:
        return False  # Groups can't have policies attached "to themselves" this way

    for policy in principal.all_policies():
        for stmt in policy.statements:
            if stmt.effect != "Allow":
                continue
            has_relevant_action = any(a in relevant_actions for a in stmt.actions) or "*" in stmt.actions
            if has_relevant_action and _resource_matches_self(stmt.resources, principal.arn):
                return True

    return False

