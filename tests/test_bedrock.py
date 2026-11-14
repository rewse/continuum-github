"""Tests for the Bedrock wrapper and the summary sections it writes."""

from datetime import UTC
from datetime import datetime
from typing import Any

from botocore.exceptions import ClientError
from botocore.exceptions import ReadTimeoutError
from fakes import FakeModel

from continuum_scan.bedrock import SYSTEM_PROMPT
from continuum_scan.bedrock import Bedrock
from continuum_scan.bedrock import bedrock_client
from continuum_scan.bedrock import finding_sections
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


class FakeClient:
    def __init__(
        self, response: dict[str, Any] | None = None, error: Exception | None = None
    ) -> None:
        self.response = response
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def converse(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        assert self.response is not None
        return self.response


def _response(text: str, stop: str = "end_turn") -> dict[str, Any]:
    return {"output": {"message": {"content": [{"text": text}]}}, "stopReason": stop}


def test_ask_calls_converse_without_tools_and_extracts_the_answer(tmp_path) -> None:
    skill = tmp_path / "SKILL.md"
    skill.write_text("skill body")
    client = FakeClient(
        _response("x <<<CONTINUUM-BEGIN>>>\nhello\n<<<CONTINUUM-END>>>")
    )
    assert Bedrock(client, "m1").ask("the question", "page", [skill]) == "hello"
    (call,) = client.calls
    assert call["modelId"] == "m1"
    assert call["system"] == [{"text": SYSTEM_PROMPT}]
    assert "toolConfig" not in call
    assert call["inferenceConfig"] == {"maxTokens": 32000}
    (message,) = call["messages"]
    assert message["role"] == "user"
    (block,) = message["content"]
    text = block["text"]
    resource = '<resource name="SKILL.md">\nskill body\n</resource>'
    assert text.index(resource) < text.index("the question")


def test_ask_logs_only_the_error_code_on_client_errors(capsys) -> None:
    error = ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "secret finding text"}},
        "Converse",
    )
    assert Bedrock(FakeClient(error=error), "m1").ask("p", "summary") is None
    assert capsys.readouterr().err == (
        "model_failed purpose=summary reason=ThrottlingException\n"
    )


def test_ask_logs_the_class_name_on_botocore_errors(capsys) -> None:
    error = ReadTimeoutError(endpoint_url="https://bedrock-runtime.example.com")
    assert Bedrock(FakeClient(error=error), "m1").ask("p", "page") is None
    assert capsys.readouterr().err == (
        "model_failed purpose=page reason=ReadTimeoutError\n"
    )


def test_ask_rejects_a_truncated_answer(capsys) -> None:
    text = "<<<CONTINUUM-BEGIN>>>a<<<CONTINUUM-END>>>"
    client = FakeClient(_response(text, "max_tokens"))
    assert Bedrock(client, "m1").ask("p", "sections") is None
    assert capsys.readouterr().err == (
        "model_failed purpose=sections reason=max_tokens\n"
    )


def test_ask_rejects_answers_without_text_or_markers(capsys) -> None:
    empty = {"output": {"message": {"content": []}}, "stopReason": "end_turn"}
    assert Bedrock(FakeClient(empty), "m1").ask("p", "sections") is None
    assert (
        Bedrock(FakeClient(_response("no markers")), "m1").ask("p", "sections") is None
    )
    assert capsys.readouterr().err.splitlines() == [
        "model_failed purpose=sections reason=no_text",
        "model_failed purpose=sections reason=no_markers",
    ]


def test_ask_uses_the_last_begin_marker() -> None:
    client = FakeClient(
        _response(
            "<<<CONTINUUM-BEGIN>>> and <<<CONTINUUM-END>>>\n"
            "<<<CONTINUUM-BEGIN>>>answer<<<CONTINUUM-END>>>"
        )
    )
    assert Bedrock(client, "m1").ask("p", "summary") == "answer"


def test_bedrock_client_sets_the_timeout_and_retries() -> None:
    config = bedrock_client("us-east-1").meta.config
    assert config.read_timeout == 600
    # total_max_attempts counts the first call, so this is 3 calls in all.
    assert config.retries == {"mode": "standard", "total_max_attempts": 3}
    page = bedrock_client("us-east-1", attempts=1).meta.config
    assert page.retries == {"mode": "standard", "total_max_attempts": 1}


def test_ask_sends_page_requests_to_the_page_client() -> None:
    answer = _response("<<<CONTINUUM-BEGIN>>>a<<<CONTINUUM-END>>>")
    client, page = FakeClient(answer), FakeClient(answer)
    model = Bedrock(client, "m1", page_client=page)
    assert model.ask("p", "page") == "a"
    assert model.ask("p", "summary") == "a"
    assert (len(page.calls), len(client.calls)) == (1, 1)


def test_finding_sections_parses_and_validates_json() -> None:
    ok = FakeModel('{"summary": "S", "why": "W", "risk": "R"}')
    assert finding_sections(ok, DETECTION) == Sections("S", "W", "R")
    for answer in (
        "not json",
        '{"summary": "S", "why": "W"}',
        '{"summary": "", "why": "W", "risk": "R"}',
        '{"summary": "' + "a" * 1501 + '", "why": "W", "risk": "R"}',
        None,
    ):
        assert finding_sections(FakeModel(answer), DETECTION) is None


def test_finding_sections_logs_an_invalid_answer(capsys) -> None:
    assert finding_sections(FakeModel("not json"), DETECTION) is None
    assert capsys.readouterr().err == (
        "model_failed purpose=sections reason=invalid_answer\n"
    )


def test_finding_sections_accepts_a_json_fence() -> None:
    fenced = FakeModel('```json\n{"summary": "S", "why": "W", "risk": "R"}\n```')
    assert finding_sections(fenced, DETECTION) == Sections("S", "W", "R")


def test_finding_sections_prompt_carries_the_detection() -> None:
    model = FakeModel(None)
    finding_sections(model, DETECTION)
    (prompt,) = model.prompts
    for text in ("Reflected XSS", "HIGH", "pentest", "weekly-x", "Description"):
        assert text in prompt
    assert "The q parameter is echoed." in prompt
    assert model.purposes == ["sections"]


def test_finding_sections_prompt_names_the_locale() -> None:
    model = FakeModel(None)
    finding_sections(model, DETECTION, "ja_JP")
    (prompt,) = model.prompts
    assert "in the language of the locale ja_JP" in prompt
    assert "English" not in prompt
