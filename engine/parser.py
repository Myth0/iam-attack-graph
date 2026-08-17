"""
Parser: raw AWS IAM export JSON -> list[Principal]

Input is the untrusted output of:
    aws iam get-account-authorization-details

This module is the ONLY place in the engine that touches raw AWS
JSON shape. Everything downstream works with the clean Principal
model from engine.models.
"""

from __future__ import annotations
from engine.models import Principal, Policy, Statement, PrincipalType


def _parse_statement(raw: dict) -> Statement:
    """
    Normalize a single statement, handling Action/Resource as either
    str or list. Also captures 'Principal' for trust policy statements
    (permission statements won't have this key, so it stays None).
    """
    actions = raw.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]

    resources = raw.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]

    return Statement(
        effect=raw.get("Effect", "Deny"),
        actions=actions,
        resources=resources,
        principal=raw.get("Principal"),
        condition=raw.get("Condition"),
    )


def _parse_policy_document(doc: dict) -> list[Statement]:
    """A policy document has a top-level Statement list (or single dict)."""
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    return [_parse_statement(s) for s in stmts]


def _parse_managed_policy_ref(raw: dict) -> Policy:
    """
    Managed policies as referenced on a principal only include name+arn,
    not the actual permissions (those live in the separate 'Policies' list).
    We capture the reference here; resolving full permissions happens
    in a later pass if needed.
    """
    return Policy(
        name=raw.get("PolicyName", "unknown"),
        arn=raw.get("PolicyArn"),
        statements=[],
        is_inline=False,
    )


def _parse_inline_policy(raw: dict) -> Policy:
    """Inline policies embed their full document directly."""
    doc = raw.get("PolicyDocument", {})
    return Policy(
        name=raw.get("PolicyName", "unknown"),
        arn=None,
        statements=_parse_policy_document(doc),
        is_inline=True,
    )


def _parse_trust_policy(raw: dict | None) -> Policy | None:
    """Roles have an AssumeRolePolicyDocument defining who can assume them."""
    if raw is None:
        return None
    return Policy(
        name="trust-policy",
        arn=None,
        statements=_parse_policy_document(raw),
        is_inline=True,
    )


def parse_iam_export(data: dict) -> list[Principal]:
    """
    Main entry point. Takes the full parsed JSON dict from
    `aws iam get-account-authorization-details` and returns a
    flat list of Principal objects (Users, Roles, Groups).
    """
    principals: list[Principal] = []

    for u in data.get("UserDetailList", []):
        principals.append(Principal(
            name=u["UserName"],
            arn=u["Arn"],
            principal_type=PrincipalType.USER,
            attached_policies=[_parse_managed_policy_ref(p) for p in u.get("AttachedManagedPolicies", [])],
            inline_policies=[_parse_inline_policy(p) for p in u.get("UserPolicyList", [])],
            group_memberships=u.get("GroupList", []),
        ))

    for r in data.get("RoleDetailList", []):
        principals.append(Principal(
            name=r["RoleName"],
            arn=r["Arn"],
            principal_type=PrincipalType.ROLE,
            attached_policies=[_parse_managed_policy_ref(p) for p in r.get("AttachedManagedPolicies", [])],
            inline_policies=[_parse_inline_policy(p) for p in r.get("RolePolicyList", [])],
            trust_policy=_parse_trust_policy(r.get("AssumeRolePolicyDocument")),
        ))

    for g in data.get("GroupDetailList", []):
        principals.append(Principal(
            name=g["GroupName"],
            arn=g["Arn"],
            principal_type=PrincipalType.GROUP,
            attached_policies=[_parse_managed_policy_ref(p) for p in g.get("AttachedManagedPolicies", [])],
            inline_policies=[_parse_inline_policy(p) for p in g.get("GroupPolicyList", [])],
        ))

    return principals
