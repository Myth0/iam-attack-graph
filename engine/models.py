"""
Core data models for the IAM Attack Path Grapher.

These models represent AWS IAM entities as parsed from an
`aws iam get-account-authorization-details` export. All models
use pydantic for validation, since every uploaded file is
untrusted input (see THREAT_MODEL.md, T2).
"""

from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class PrincipalType(str, Enum):
    """The three IAM principal types we model in v1."""
    USER = "User"
    ROLE = "Role"
    GROUP = "Group"


class Statement(BaseModel):
    """
    A single statement within an IAM policy document.

    `resources` is used by permission policies (what can be acted on).
    `principal` is used by trust policies instead (who is allowed to
    assume the role) — AWS uses the same Statement shape for both,
    just with different keys populated.
    """
    effect: str = Field(..., description="'Allow' or 'Deny'")
    actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    principal: Optional[dict] = None  # e.g. {"AWS": "arn:..."} or {"Service": "..."}
    condition: Optional[dict] = None


class Policy(BaseModel):
    """
    A policy document — either a managed policy attached to a
    principal, or an inline policy embedded directly on it.
    """
    name: str
    arn: Optional[str] = None  # None for inline policies
    statements: list[Statement] = Field(default_factory=list)
    is_inline: bool = False


class Principal(BaseModel):
    """
    An IAM User, Role, or Group.

    `trust_policy` only applies to Roles (defines who can assume it).
    `group_memberships` only applies to Users.
    """
    name: str
    arn: str
    principal_type: PrincipalType
    attached_policies: list[Policy] = Field(default_factory=list)
    inline_policies: list[Policy] = Field(default_factory=list)
    trust_policy: Optional[Policy] = None
    group_memberships: list[str] = Field(default_factory=list)

    def all_policies(self) -> list[Policy]:
        """Convenience method: every policy attached to this principal."""
        return self.attached_policies + self.inline_policies
