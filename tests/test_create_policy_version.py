"""Tests for engine.techniques.create_policy_version"""

import networkx as nx
from engine.models import Principal, PrincipalType, Policy, Statement
from engine.techniques.create_policy_version import check, modifiable_attached_policy_arns

MANAGED_ARN = "arn:aws:iam::123456789012:policy/my-custom-policy"
AWS_MANAGED_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _user_with_create_perm_and_attached(attached_policies, resources):
    return Principal(
        name="policy-editor",
        arn="arn:aws:iam::123456789012:user/policy-editor",
        principal_type=PrincipalType.USER,
        attached_policies=attached_policies,
        inline_policies=[Policy(
            name="edit-perms",
            is_inline=True,
            statements=[Statement(effect="Allow", actions=["iam:CreatePolicyVersion"], resources=resources)],
        )],
    )


def test_direct_attachment_is_vulnerable():
    user = _user_with_create_perm_and_attached(
        attached_policies=[Policy(name="my-custom-policy", arn=MANAGED_ARN)],
        resources=[MANAGED_ARN],
    )
    assert check(user, None) is True
    assert modifiable_attached_policy_arns(user, None) == [MANAGED_ARN]


def test_no_create_permission_is_not_vulnerable():
    user = Principal(
        name="regular-user",
        arn="arn:aws:iam::123456789012:user/regular-user",
        principal_type=PrincipalType.USER,
        attached_policies=[Policy(name="my-custom-policy", arn=MANAGED_ARN)],
    )
    assert check(user, None) is False


def test_create_permission_on_unattached_policy_is_not_vulnerable():
    """Having CreatePolicyVersion on a policy NOT attached to you is useless for self-privesc."""
    other_policy_arn = "arn:aws:iam::123456789012:policy/some-other-policy"
    user = _user_with_create_perm_and_attached(
        attached_policies=[Policy(name="my-custom-policy", arn=MANAGED_ARN)],
        resources=[other_policy_arn],
    )
    assert check(user, None) is False


def test_aws_managed_policy_attachment_alone_is_not_vulnerable():
    """AWS-managed policies can't have versions created, even with wildcard permission."""
    user = _user_with_create_perm_and_attached(
        attached_policies=[Policy(name="AdministratorAccess", arn=AWS_MANAGED_ARN)],
        resources=["*"],
    )
    # Wildcard create-permission exists, but the ONLY attached policy is AWS-managed
    assert check(user, None) is False


def test_group_inherited_policy_is_vulnerable_via_graph():
    """A user with CreatePolicyVersion on a policy attached to their GROUP
    (not directly to them) should still be flagged, using graph traversal."""
    user_arn = "arn:aws:iam::123456789012:user/group-member"
    group_arn = "arn:aws:iam::123456789012:group/editors"

    user = Principal(
        name="group-member",
        arn=user_arn,
        principal_type=PrincipalType.USER,
        inline_policies=[Policy(
            name="edit-perms",
            is_inline=True,
            statements=[Statement(effect="Allow", actions=["iam:CreatePolicyVersion"], resources=[MANAGED_ARN])],
        )],
    )
    group = Principal(
        name="editors",
        arn=group_arn,
        principal_type=PrincipalType.GROUP,
        attached_policies=[Policy(name="my-custom-policy", arn=MANAGED_ARN)],
    )

    graph = nx.DiGraph()
    graph.add_node(user.arn, principal=user, name=user.name, type="User")
    graph.add_node(group.arn, principal=group, name=group.name, type="Group")
    graph.add_edge(user.arn, group.arn, relationship="member_of")

    assert check(user, graph) is True
    assert modifiable_attached_policy_arns(user, graph) == [MANAGED_ARN]


def test_wildcard_create_permission_with_attached_managed_policy():
    user = _user_with_create_perm_and_attached(
        attached_policies=[Policy(name="my-custom-policy", arn=MANAGED_ARN)],
        resources=["*"],
    )
    assert check(user, None) is True


def test_no_attached_policies_at_all_is_not_vulnerable():
    user = _user_with_create_perm_and_attached(attached_policies=[], resources=["*"])
    assert check(user, None) is False
