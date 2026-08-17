"""
Analyzer: runs all registered privesc techniques against every
principal in the graph, producing a structured findings report.

Adding a new technique to the engine means:
  1. Write engine/techniques/your_technique.py with a
     check(principal, graph) -> bool function
  2. Register it in TECHNIQUES below with a name, severity, and
     description template
No other file needs to change.
"""

from __future__ import annotations
from dataclasses import dataclass
import networkx as nx
from engine.models import Principal
from engine.techniques import self_policy_attach


@dataclass
class TechniqueSpec:
    id: str
    name: str
    severity: str  # "critical" | "high" | "medium" | "low"
    check_fn: callable
    description_template: str  # {principal} gets substituted


TECHNIQUES: list[TechniqueSpec] = [
    TechniqueSpec(
        id=self_policy_attach.TECHNIQUE_ID,
        name=self_policy_attach.TECHNIQUE_NAME,
        severity="critical",
        check_fn=self_policy_attach.check,
        description_template=(
            "{principal} can attach or modify policies on itself, "
            "allowing immediate escalation to AdministratorAccess "
            "with no further steps required."
        ),
    ),
]


@dataclass
class Finding:
    principal_arn: str
    principal_name: str
    technique_id: str
    technique_name: str
    severity: str
    description: str


def analyze(principals: list[Principal], graph: nx.DiGraph) -> list[Finding]:
    """
    Run every registered technique against every principal.
    Returns findings sorted by severity (critical first).
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings: list[Finding] = []

    for principal in principals:
        for tech in TECHNIQUES:
            if tech.check_fn(principal, graph):
                findings.append(Finding(
                    principal_arn=principal.arn,
                    principal_name=principal.name,
                    technique_id=tech.id,
                    technique_name=tech.name,
                    severity=tech.severity,
                    description=tech.description_template.format(principal=principal.name),
                ))

    findings.sort(key=lambda f: severity_order.get(f.severity, 99))
    return findings
