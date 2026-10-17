"""Check results and the report they make up."""

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"  # not checked: not applicable, or an expected value or key was not supplied


@dataclass
class Finding:
    check_id: str
    status: Status
    title: str  # short label, e.g. "Assertion signature"
    summary: str  # one plain-English line saying what was found
    next_step: str = None  # what to check next (omitted for most PASS results)
    runbook: str = None  # identity-lab runbook name, when the finding matches a lab scenario
    details: dict = field(default_factory=dict)


@dataclass
class Report:
    kind: str  # "saml", "jwt" or "jwe"
    encoding: str
    container: str
    location: str
    now: object
    skew: int
    label: str = None  # e.g. "SAML Response", "ID token (JWT)"
    sections: list = field(default_factory=list)  # [(title, [(label, value), ...]), ...]
    findings: list = field(default_factory=list)
    other_tokens: int = 0
    redacted: bool = False

    def count(self, status):
        return sum(1 for f in self.findings if f.status == status)

    def finding(self, check_id):
        for f in self.findings:
            if f.check_id == check_id:
                return f
        return None

    @property
    def exit_code(self):
        return 1 if self.count(Status.FAIL) else 0
