"""Severities, detections, and the keys that match them across scans."""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal

Source = Literal["pentest", "code-vuln", "code-review"]


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, value: str | None) -> "Severity":
        """Returns the severity named by value, ignoring case.

        None and unrecognized names map to UNKNOWN.
        """
        if value is None:
            return cls.UNKNOWN
        try:
            return cls(value.upper())
        except ValueError:
            return cls.UNKNOWN

    @property
    def filed(self) -> bool:
        """Returns True for severities that get their own issue."""
        return self in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)

    @property
    def rank(self) -> int:
        """Returns a number that orders severities, higher being worse."""
        return _RANKS[self]


_RANKS = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 1,
    Severity.UNKNOWN: 0,
}


def pentest_severity(value: str | None) -> Severity:
    """Returns the severity of a pentest finding.

    UNKNOWN becomes MEDIUM so an unrated finding is filed rather than dropped.
    """
    severity = Severity.parse(value)
    return Severity.MEDIUM if severity is Severity.UNKNOWN else severity


def pentest_key(pentest: str, risk_type: str, name: str) -> str:
    """Returns a key that matches a pentest finding across scans.

    The name is compared without regard to case or runs of whitespace.
    """
    normalized = " ".join(name.lower().split())
    parts = (pentest, risk_type, normalized)
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]


def code_review_key(title: str, risk_type: str, name: str, file_path: str) -> str:
    """Returns a key that matches a code review finding across scans.

    The name is compared without regard to case or runs of whitespace.
    Line numbers are left out so a finding keeps its key when code moves.
    """
    normalized = " ".join(name.lower().split())
    parts = ("code-review", title, risk_type, normalized, file_path)
    return "cr:" + hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]


def code_vuln_key(environment_id: str, issue_id: str) -> str:
    """Returns the key of a code vulnerability issue."""
    return f"cv:{environment_id}/{issue_id}"


@dataclass(frozen=True)
class Detection:
    source: Source
    target: str
    repository: str
    key: str
    external_id: str
    name: str
    severity: Severity
    urgent: bool
    confidence: str
    detected_at: datetime
    site: str | None = None
    pentest_id: str | None = None
    location: str | None = None
    details: tuple[tuple[str, str], ...] = ()
    # Other finding IDs with the same key, such as a second alive finding of
    # one pentest job. external_id stays the representative.
    extra_finding_ids: tuple[str, ...] = ()

    @property
    def finding_ids(self) -> tuple[str, ...]:
        """Returns external_id followed by the extra finding IDs, without repeats."""
        return tuple(dict.fromkeys((self.external_id, *self.extra_finding_ids)))


@dataclass(frozen=True)
class CompletedScan:
    scan_id: str
    started_at: datetime
    found: Mapping[str, Detection]


@dataclass(frozen=True)
class TargetScan:
    source: Source
    target: str
    candidates: tuple[Detection, ...]
    withdrawn: frozenset[str]
    completed: CompletedScan | None
    latest_status: str
    completed_at: datetime | None


@dataclass(frozen=True)
class RevalidationResult:
    job_status: str
    validation_status: str | None
