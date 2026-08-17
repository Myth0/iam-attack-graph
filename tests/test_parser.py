"""Tests for engine.parser"""

import json
import pytest
from pathlib import Path
from engine.parser import parse_iam_export
from engine.models import PrincipalType

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_iam_export.json"


@pytest.fixture
def sample_data():
    with open(FIXTURE_PATH) as f:
        return json.load(f)


def test_parses_correct_number_of_principals(sample_data):
    principals = parse_iam_export(sample_data)
    assert len(principals) == 3  # 1 user, 1 role, 1 group


def test_parses_user_with_inline_policy(sample_data):
    principals = parse_iam_export(sample_data)
    user = next(p for p in principals if p.name == "test-user")

    assert user.principal_type == PrincipalType.USER
    assert user.group_memberships == ["developers"]
    assert len(user.inline_policies) == 1
    assert user.inline_policies[0].is_inline is True


def test_inline_policy_captures_privesc_actions(sample_data):
    """The self-attach privesc scenario should survive parsing intact."""
    principals = parse_iam_export(sample_data)
    user = next(p for p in principals if p.name == "test-user")

    stmt = user.inline_policies[0].statements[0]
    assert "iam:AttachUserPolicy" in stmt.actions
    assert "iam:PutUserPolicy" in stmt.actions
    assert stmt.effect == "Allow"


def test_parses_role_with_trust_policy(sample_data):
    principals = parse_iam_export(sample_data)
    role = next(p for p in principals if p.name == "lambda-execution-role")

    assert role.principal_type == PrincipalType.ROLE
    assert role.trust_policy is not None
    assert len(role.attached_policies) == 1
    assert role.attached_policies[0].name == "AdministratorAccess"


def test_parses_group_with_managed_policy(sample_data):
    principals = parse_iam_export(sample_data)
    group = next(p for p in principals if p.name == "developers")

    assert group.principal_type == PrincipalType.GROUP
    assert group.attached_policies[0].name == "PowerUserAccess"


def test_action_normalized_to_list_when_string():
    """AWS sometimes returns Action as a single string, not a list — must normalize."""
    from engine.parser import _parse_statement
    stmt = _parse_statement({"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"})
    assert stmt.actions == ["iam:PassRole"]
