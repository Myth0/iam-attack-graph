"""Tests for engine.techniques.self_policy_attach"""

import json
from pathlib import Path
from engine.parser import parse_iam_export
from engine.models import Principal, PrincipalType, Policy, Statement
from engine.techniques.self_policy_attach import check

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_iam_export.json"


def test_fixture_user_is_flagged_vulnerable():
    """test-user in our fixture has the classic self-attach privesc."""
    with open(FIXTURE_PATH) as f:
        data = json.load(f)
    principals = parse_iam_export(data)
    user = next(p for p in principals if p.name == "test-user")
    assert check(user) is True


def test_fixture_role_and_group_not_flagged():
    with open(FIXTURE_PATH) as f:
        data = json.load(f)
    principals = parse_iam_export(data)

    role = next(p for p in principals if p.name == "lambda-execution-role")
    group = next(p for p in principals if p.name == "developers")

    assert check(role) is False
    assert check(group) is False


def test_role_with_attach_role_policy_on_self_is_vulnerable():
    """A Role (not User) with iam:AttachRolePolicy on itself should also flag."""
    role = Principal(
        name="vuln-role",
        arn="arn:aws:iam::123456789012:role/vuln-role",
        principal_type=PrincipalType.ROLE,
        inline_policies=[Policy(
            name="danger",
            is_inline=True,
            statements=[Statement(
                effect="Allow",
                actions=["iam:AttachRolePolicy"],
                resources=["arn:aws:iam::123456789012:role/vuln-role"],
            )],
        )],
    )
    assert check(role) is True


def test_deny_effect_does_not_count():
    """A Deny statement, even with the right action/resource, must NOT flag as vulnerable."""
    user = Principal(
        name="safe-user",
        arn="arn:aws:iam::123456789012:user/safe-user",
        principal_type=PrincipalType.USER,
        inline_policies=[Policy(
            name="explicit-deny",
            is_inline=True,
            statements=[Statement(
                effect="Deny",
                actions=["iam:AttachUserPolicy"],
                resources=["arn:aws:iam::123456789012:user/safe-user"],
            )],
        )],
    )
    assert check(user) is False


def test_resource_pointing_elsewhere_does_not_count():
    """Permission to attach policies to a DIFFERENT principal is not self-escalation."""
    user = Principal(
        name="admin-helper",
        arn="arn:aws:iam::123456789012:user/admin-helper",
        principal_type=PrincipalType.USER,
        inline_policies=[Policy(
            name="manage-others",
            is_inline=True,
            statements=[Statement(
                effect="Allow",
                actions=["iam:AttachUserPolicy"],
                resources=["arn:aws:iam::123456789012:user/someone-else"],
            )],
        )],
    )
    assert check(user) is False


def test_wildcard_resource_counts_as_self():
    """A statement with Resource: '*' includes the principal's own ARN."""
    user = Principal(
        name="over-permissive",
        arn="arn:aws:iam::123456789012:user/over-permissive",
        principal_type=PrincipalType.USER,
        inline_policies=[Policy(
            name="wildcard",
            is_inline=True,
            statements=[Statement(
                effect="Allow",
                actions=["iam:PutUserPolicy"],
                resources=["*"],
            )],
        )],
    )
    assert check(user) is True


def test_group_is_never_flagged():
    """Groups don't have this attack surface in v1's model."""
    group = Principal(
        name="some-group",
        arn="arn:aws:iam::123456789012:group/some-group",
        principal_type=PrincipalType.GROUP,
    )
    assert check(group) is False
