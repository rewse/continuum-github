"""Checks on the sync and report composite actions."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
ACTIONS = ("report", "sync")
PINNED_USE = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"@[0-9a-f]{40}  # v\d+\.\d+\.\d+$")
USE_LINE = re.compile(
    r"^\s*(?:- )?uses: (?P<action>[^@\s]+)@(?P<pin>[0-9a-f]{40}  # \S+)$",
    re.MULTILINE,
)


def _path(name: str) -> Path:
    return ROOT / name / "action.yml"


def _load(name: str) -> dict:
    return yaml.safe_load(_path(name).read_text())


def _steps(name: str) -> list[dict]:
    return _load(name)["runs"]["steps"]


def _step(name: str, step_name: str) -> dict:
    (step,) = [s for s in _steps(name) if s.get("name") == step_name]
    return step


def test_actions_declare_the_shared_inputs() -> None:
    for name in ACTIONS:
        inputs = _load(name)["inputs"]
        assert inputs["agent-space-id"]["required"] is True
        assert inputs["aws-region"]["default"] == "us-east-1"
        assert inputs["github-token"]["default"] == "${{ github.token }}"
        assert inputs["mention"]["default"] == ""
        assert inputs["report-repository"]["default"] == "${{ github.repository }}"
        assert inputs["targets"]["default"] == "targets.toml"
        assert inputs["bedrock-model-id"]["default"] == ""
        assert inputs["bedrock-region"]["default"] == ""
        assert "kiro" not in _path(name).read_text().lower()


def test_actions_are_composite_and_pin_every_use() -> None:
    for name in ACTIONS:
        action = _load(name)
        assert action["runs"]["using"] == "composite"
        uses = [s["uses"] for s in action["runs"]["steps"] if "uses" in s]
        assert uses
        assert all(PINNED_USE.match(u) for u in uses), uses
        lines = [
            line for line in _path(name).read_text().splitlines() if "uses:" in line
        ]
        assert all(VERSION_COMMENT.search(line) for line in lines), lines


def _pins(paths: list[Path]) -> dict[str, set[str]]:
    pins: dict[str, set[str]] = {}
    for path in paths:
        for match in USE_LINE.finditer(path.read_text()):
            pins.setdefault(match["action"], set()).add(match["pin"])
    return pins


def test_actions_pin_shared_uses_like_the_workflows() -> None:
    workflows = _pins(sorted((ROOT / ".github/workflows").glob("*.yml")))
    actions = _pins([_path(name) for name in ACTIONS])
    shared = actions.keys() & workflows.keys()
    assert shared
    for action in shared:
        assert actions[action] == workflows[action], action


def test_actions_keep_expressions_out_of_run_scripts() -> None:
    for name in ACTIONS:
        runs = [s for s in _steps(name) if "run" in s]
        assert runs
        for step in runs:
            assert "${{" not in step["run"], step["name"]
            assert step["shell"] == "bash"


def test_actions_run_the_cli_from_the_action_checkout() -> None:
    for name in ACTIONS:
        cli_steps = [s for s in _steps(name) if "continuum-scan" in s.get("run", "")]
        assert cli_steps
        for step in cli_steps:
            assert 'uv run --project "$GITHUB_ACTION_PATH/.." --no-sync' in step["run"]
            assert step["working-directory"] == "${{ github.workspace }}"
            env = step["env"]
            assert env["AWS_REGION"] == "${{ inputs.aws-region }}"
            assert env["AGENT_SPACE_ID"] == "${{ inputs.agent-space-id }}"
            assert env["GITHUB_TOKEN"] == "${{ inputs.github-token }}"
            assert env["MENTION"] == "${{ inputs.mention }}"
            assert env["REPORT_REPOSITORY"] == "${{ inputs.report-repository }}"
            if "publish" not in step["run"]:
                assert '--targets "$TARGETS"' in step["run"]
                assert env["TARGETS"] == "${{ inputs.targets }}"
        install = _step(name, "Install dependencies")["run"]
        assert install == (
            'uv sync --project "$GITHUB_ACTION_PATH/.." --locked --no-dev'
            " --safe-chain-skip-minimum-package-age"
        )


def test_sync_writes_sections_only_when_needed_and_enabled() -> None:
    sync = _step("sync", "Sync findings")
    assert sync["id"] == "sync"
    assert "continuum-scan sync" in sync["run"]
    assert "BEDROCK_MODEL_ID" not in sync["env"]
    sections = _step("sync", "Write issue sections")
    assert sections["if"] == (
        "steps.sync.outputs.needs-sections != '0' && inputs.bedrock-model-id != ''"
    )
    assert "continuum-scan sections" in sections["run"]
    assert sections["env"]["BEDROCK_MODEL_ID"] == "${{ inputs.bedrock-model-id }}"
    assert sections["env"]["BEDROCK_REGION"] == "${{ inputs.bedrock-region }}"


def test_report_builds_html_only_when_enabled() -> None:
    enabled = "inputs.bedrock-model-id != ''"
    for name in ("Set up Node.js", "Install npm dependencies", "Upload HTML report"):
        assert _step("report", name)["if"] == enabled
    build = _step("report", "Build report")
    assert "if" not in build
    assert build["env"]["BEDROCK_MODEL_ID"] == "${{ inputs.bedrock-model-id }}"
    assert build["env"]["BEDROCK_REGION"] == "${{ inputs.bedrock-region }}"


def test_report_uploads_an_unzipped_html_artifact() -> None:
    action = _load("report")
    assert action["outputs"]["html-url"]["value"] == (
        "${{ steps.upload.outputs.artifact-url }}"
    )
    node = _step("report", "Set up Node.js")
    assert node["with"]["node-version"] == 24
    npm = _step("report", "Install npm dependencies")
    assert npm["run"] == 'npm ci --prefix "$GITHUB_ACTION_PATH/.." --ignore-scripts'
    build = _step("report", "Build report")
    assert '--out "$RUNNER_TEMP/report"' in build["run"]
    assert "VISUAL_EXPLAINER_DIR=" in build["run"]
    assert (
        '"$GITHUB_ACTION_PATH/../node_modules/visual-explainer/plugins/'
        'visual-explainer"' in build["run"]
    )
    upload = _step("report", "Upload HTML report")
    assert upload["id"] == "upload"
    assert upload["with"] == {
        "path": "${{ runner.temp }}/report/report.ja.html",
        "archive": False,
        "retention-days": 400,
        "if-no-files-found": "warn",
    }
    publish = _step("report", "Publish report")
    assert '--dir "$RUNNER_TEMP/report" --html-url "$HTML_URL"' in publish["run"]
    assert publish["env"]["HTML_URL"] == "${{ steps.upload.outputs.artifact-url }}"
