"""Checks on the example targets, caller workflows, and CloudFormation templates."""

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from continuum_scan.config import load_targets

ROOT = Path(__file__).parent.parent
EXAMPLES = ROOT / "examples"
PINNED_USE = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"@[0-9a-f]{40}  # v(\d+\.\d+\.\d+|X\.Y\.Z)$")
JOB_PERMISSIONS = {"contents": "read", "id-token": "write", "issues": "write"}
CONCURRENCY = {"group": "continuum-github", "cancel-in-progress": False}


def _workflow(name: str) -> dict[Any, Any]:
    return yaml.safe_load((EXAMPLES / "workflows" / name).read_text())


def _triggers(workflow: dict[Any, Any]) -> dict[str, Any]:
    # PyYAML reads the bare key "on" as the boolean True.
    return workflow[True]


def _only_job(workflow: dict[str, Any]) -> dict[str, Any]:
    (job,) = workflow["jobs"].values()
    return job


def test_example_targets_load() -> None:
    targets = load_targets(EXAMPLES / "targets.toml")
    assert targets.owner == "example-org"
    assert any(r.private for r in targets.repositories)
    assert any(not r.private for r in targets.repositories)
    assert targets.sites
    assert all(s.domain.endswith("example.com") for s in targets.sites)


def test_example_workflows_call_both_actions_with_a_pinned_sha() -> None:
    for name, action, cron in (
        ("report.yml", "report", "35 21 * * 5"),
        ("sync.yml", "sync", "7 */2 * * *"),
    ):
        workflow = _workflow(name)
        assert workflow["permissions"] == {"contents": "read"}
        assert workflow["concurrency"] == CONCURRENCY
        assert _triggers(workflow)["schedule"] == [{"cron": cron}]
        assert "workflow_dispatch" in _triggers(workflow)
        job = _only_job(workflow)
        assert job["permissions"] == JOB_PERMISSIONS
        assert job["if"] == "github.ref == 'refs/heads/main'"
        uses = [s["uses"] for s in job["steps"] if "uses" in s]
        assert all(PINNED_USE.match(u) for u in uses), uses
        assert any(
            re.fullmatch(rf"rewse/continuum-github/{action}@[0-9a-f]{{40}}", u)
            for u in uses
        ), uses
        lines = [
            line
            for line in (EXAMPLES / "workflows" / name).read_text().splitlines()
            if "uses:" in line
        ]
        assert all(VERSION_COMMENT.search(line) for line in lines), lines


def test_example_templates_pass_cfn_lint() -> None:
    templates = sorted((EXAMPLES / "infra").glob("*.yaml"))
    assert [t.name for t in templates] == [
        "github-actions-role.yaml",
        "security-agent.yaml",
    ]
    cfn_lint = Path(sys.executable).parent / "cfn-lint"
    result = subprocess.run(
        [str(cfn_lint), *map(str, templates)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
