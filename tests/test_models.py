"""Tests for severities, detections, and match keys."""

from continuum_scan.models import Severity
from continuum_scan.models import code_review_key
from continuum_scan.models import code_vuln_key
from continuum_scan.models import pentest_key
from continuum_scan.models import pentest_severity


def test_severity_parse_and_filed() -> None:
    assert Severity.parse("high") is Severity.HIGH
    assert Severity.parse(None) is Severity.UNKNOWN
    assert Severity.parse("FATAL") is Severity.UNKNOWN
    assert [s for s in Severity if s.filed] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
    ]
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank


def test_severity_rank_values() -> None:
    assert [s.rank for s in Severity] == [5, 4, 3, 2, 1, 0]


def test_pentest_severity_files_unknown_as_medium() -> None:
    assert pentest_severity("UNKNOWN") is Severity.MEDIUM
    assert pentest_severity(None) is Severity.MEDIUM
    assert pentest_severity("LOW") is Severity.LOW


def test_pentest_key_ignores_case_and_spacing_but_not_risk_type() -> None:
    a = pentest_key("weekly-x", "XSS", "Reflected  XSS in /search")
    assert a == pentest_key("weekly-x", "XSS", "reflected xss in /search")
    assert len(a) == 16
    assert a != pentest_key("weekly-x", "SQL_INJECTION", "Reflected XSS in /search")
    assert a != pentest_key("weekly-y", "XSS", "Reflected XSS in /search")


def test_code_vuln_key() -> None:
    assert code_vuln_key("env1", "iss9") == "cv:env1/iss9"


def test_code_review_key_ignores_case_and_spacing_but_not_the_file() -> None:
    a = code_review_key("weekly-actions", "XSS", "Reflected  XSS", "src/a.py")
    assert a.startswith("cr:") and len(a) == 19
    assert a == code_review_key("weekly-actions", "XSS", "reflected xss", "src/a.py")
    assert a != code_review_key("weekly-actions", "XSS", "reflected xss", "src/b.py")
    assert a != code_review_key("weekly-dotfiles", "XSS", "reflected xss", "src/a.py")
