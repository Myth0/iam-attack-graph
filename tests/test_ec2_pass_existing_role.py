"""Tests for engine.techniques.ec2_pass_existing_role"""

from engine.models import Principal, PrincipalType, Policy, Statement
from engine.techniques.ec2_pass_existing_role import check, passable_role_arns

ADMIN_ROLE = "arn:aws:iam::123456789012:role/admin-role"
OTHER_ROLE = "arn:aws:iam::123456789012:role/other-role"
ALL_ROLES = [ADMIN_ROLE, OTHER_ROLE]


def _principal_with_statements(statements: list[Statement]) -> Principal:
    return Principal(
        name="test-principal",
        arn="arn:aws:iam::123456789012:user/test-principal",
        principal_type=PrincipalType.USER,
        inline_policies=[Policy(name="test-policy", is_inline=True, statements=statements)],
    )


def test_wildcard_pass_role_and_run_instances_is_vulnerable():
    user = _principal_with_statements([
        Statement(effect="Allow", actions=["iam:PassRole"], resources=["*"]),
        Statement(effect="Allow", actions=["ec2:RunInstances"], resources=["*"]),
    ])
    assert check(user, None) is True
    assert set(passable_role_arns(user, ALL_ROLES)) == set(ALL_ROLES)


def test_explicit_role_arn_limits_passable_roles():
    """PassRole scoped to one specific ARN should only allow that role,
    not every role in the account."""
    user = _principal_with_statements([
        Statement(effect="Allow", actions=["iam:PassRole"], resources=[ADMIN_ROLE]),
        Statement(effect="Allow", actions=["ec2:RunInstances"], resources=["*"]),
    ])
    assert check(user, None) is True
    assert passable_role_arns(user, ALL_ROLES) == [ADMIN_ROLE]


def test_pass_role_without_run_instances_is_not_vulnerable():
    """Having PassRole alone isn't enough - RunInstances is required too."""
    user = _principal_with_statements([
        Statement(effect="Allow", actions=["iam:PassRole"], resources=["*"]),
    ])
    assert check(user, None) is False
    assert passable_role_arns(user, ALL_ROLES) == []


def test_run_instances_without_pass_role_is_not_vulnerable():
    user = _principal_with_statements([
        Statement(effect="Allow", actions=["ec2:RunInstances"], resources=["*"]),
    ])
    assert check(user, None) is False


def test_deny_pass_role_does_not_count():
    user = _principal_with_statements([
        Statement(effect="Deny", actions=["iam:PassRole"], resources=["*"]),
        Statement(effect="Allow", actions=["ec2:RunInstances"], resources=["*"]),
    ])
    assert check(user, None) is False


def test_no_relevant_permissions_is_not_vulnerable():
    user = _principal_with_statements([
        Statement(effect="Allow", actions=["s3:GetObject"], resources=["*"]),
    ])
    assert check(user, None) is False
    assert passable_role_arns(user, ALL_ROLES) == []
