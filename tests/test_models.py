"""Tests for engine.models"""

import pytest
from pydantic import ValidationError
from engine.models import Principal, Policy, Statement, PrincipalType


def test_principal_construction_minimal():
    """A Principal can be built with just the required fields."""
    p = Principal(
        name="test-user",
        arn="arn:aws:iam::123456789012:user/test-user",
        principal_type=PrincipalType.USER,
    )
    assert p.name == "test-user"
    assert p.principal_type == PrincipalType.USER
    assert p.all_policies() == []


def test_all_policies_combines_attached_and_inline():
    """all_policies() should return attached + inline policies together."""
    attached = Policy(name="AdminPolicy", arn="arn:aws:iam::aws:policy/AdministratorAccess")
    inline = Policy(name="InlineDangerous", is_inline=True)

    p = Principal(
        name="test-role",
        arn="arn:aws:iam::123456789012:role/test-role",
        principal_type=PrincipalType.ROLE,
        attached_policies=[attached],
        inline_policies=[inline],
    )

    all_p = p.all_policies()
    assert len(all_p) == 2
    assert attached in all_p
    assert inline in all_p


def test_invalid_principal_type_rejected():
    """Pydantic should reject a principal_type that isn't User/Role/Group."""
    with pytest.raises(ValidationError):
        Principal(
            name="bad",
            arn="arn:aws:iam::123456789012:user/bad",
            principal_type="NotARealType",  # invalid on purpose
        )


def test_statement_defaults():
    """A Statement with no actions/resources should default to empty lists, not error."""
    s = Statement(effect="Allow")
    assert s.actions == []
    assert s.resources == []
