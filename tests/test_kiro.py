"""Tests for the Kiro CLI wrapper and the summary sections it writes."""

import json
import stat
import subprocess
from datetime import UTC
from datetime import datetime
from pathlib import Path

from fakes import FakeKiro

from continuum_scan.kiro import Kiro
from continuum_scan.kiro import finding_sections
from continuum_scan.models import Detection
from continuum_scan.models import Severity
from continuum_scan.render import Sections

DETECTION = Detection(
    source="pentest",
    target="weekly-x",
    repository="ansible-playbooks",
    key="k1",
    external_id="f1",
    name="Reflected XSS",
    severity=Severity.HIGH,
    urgent=False,
    confidence="HIGH",
    detected_at=datetime(2026, 11, 1, tzinfo=UTC),
    site="x.example.com",
    pentest_id="pt-1",
    details=(("Description", "The q parameter is echoed."),),
)


def test_ask_runs_an_isolated_agent_and_extracts_the_answer(tmp_path) -> None:
    seen = {}

    def runner(args, **kwargs):
        home = Path(kwargs["env"]["KIRO_HOME"])
        seen["agent"] = json.loads((home / "agents" / "continuum.json").read_text())
        seen["mode"] = stat.S_IMODE(home.stat().st_mode)
        seen["args"], seen["cwd"], seen["input"] = args, kwargs["cwd"], kwargs["input"]
        seen["cwd_empty"] = not any(Path(kwargs["cwd"]).iterdir())
        return subprocess.CompletedProcess(
            args,
            0,
            stdout="\x1b[32mnoise\x1b[0m\n<<<CONTINUUM-BEGIN>>>\nhello\n<<<CONTINUUM-END>>>\n",
            stderr="",
        )

    resource = tmp_path / "r.md"
    resource.write_text("x")
    kiro = Kiro(Path("/bin/kiro-cli"), model="m1", runner=runner)
    assert kiro.ask("p", [resource]) == "hello"
    assert seen["args"] == [
        "/bin/kiro-cli",
        "chat",
        "--no-interactive",
        "--agent",
        "continuum",
        "--trust-tools=",
        "--model",
        "m1",
    ]
    assert seen["agent"]["tools"] == [] and "permissions" not in seen["agent"]
    assert seen["agent"]["resources"] == [f"file://{resource}"]
    assert seen["mode"] == 0o700 and seen["cwd_empty"] and seen["input"] == "p"
    assert not Path(seen["cwd"]).exists()


def test_ask_passes_only_the_needed_environment(monkeypatch) -> None:
    seen = {}

    def runner(args, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("HOME", "/home/runner")
    monkeypatch.setenv("KIRO_API_KEY", "k")
    monkeypatch.setenv("LANG", "C.UTF-8")
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    Kiro(Path("/bin/kiro-cli"), runner=runner).ask("p")
    env = seen["env"]
    assert set(env) == {"HOME", "KIRO_API_KEY", "KIRO_HOME", "LANG", "PATH"}
    assert (env["PATH"], env["HOME"], env["KIRO_API_KEY"]) == (
        "/usr/bin",
        "/home/runner",
        "k",
    )
    assert "continuum-kiro-home-" in env["KIRO_HOME"]
    assert seen["errors"] == "replace" and seen["text"] is True


def test_ask_returns_none_on_failure_or_missing_markers() -> None:
    def fail(args, **kw):
        return subprocess.CompletedProcess(
            args, 1, stdout="<<<CONTINUUM-BEGIN>>>x<<<CONTINUUM-END>>>", stderr=""
        )

    def bare(args, **kw):
        return subprocess.CompletedProcess(args, 0, stdout="x", stderr="")

    def slow(args, **kw):
        raise subprocess.TimeoutExpired(args, 1)

    for runner in (fail, bare, slow):
        assert Kiro(Path("k"), runner=runner).ask("p") is None


def test_ask_returns_none_when_the_cli_cannot_run() -> None:
    def missing(args, **kw):
        raise FileNotFoundError(args[0])

    assert Kiro(Path("k"), runner=missing).ask("p") is None


def test_ask_uses_the_last_begin_marker() -> None:
    def echo(args, **kw):
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=(
                "<<<CONTINUUM-BEGIN>>> and <<<CONTINUUM-END>>>\n"
                "<<<CONTINUUM-BEGIN>>>answer<<<CONTINUUM-END>>>"
            ),
            stderr="",
        )

    assert Kiro(Path("k"), runner=echo).ask("p") == "answer"


def test_finding_sections_parses_and_validates_json() -> None:
    ok = FakeKiro('{"summary": "S", "why": "W", "risk": "R"}')
    assert finding_sections(ok, DETECTION) == Sections("S", "W", "R")
    for answer in (
        "not json",
        '{"summary": "S", "why": "W"}',
        '{"summary": "", "why": "W", "risk": "R"}',
        '{"summary": "' + "a" * 1501 + '", "why": "W", "risk": "R"}',
        None,
    ):
        assert finding_sections(FakeKiro(answer), DETECTION) is None


def test_finding_sections_accepts_a_json_fence() -> None:
    fenced = FakeKiro('```json\n{"summary": "S", "why": "W", "risk": "R"}\n```')
    assert finding_sections(fenced, DETECTION) == Sections("S", "W", "R")


def test_finding_sections_prompt_carries_the_detection() -> None:
    kiro = FakeKiro(None)
    finding_sections(kiro, DETECTION)
    (prompt,) = kiro.prompts
    for text in ("Reflected XSS", "HIGH", "pentest", "weekly-x", "Description"):
        assert text in prompt
    assert "The q parameter is echoed." in prompt
