# パッケージ名と CLI 名の統一、global 推論プロファイルへの切り替え 実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** import 名を `continuum_github`、CLI 名を `continuum-github` に揃え、例と推奨のモデル ID を `global.anthropic.claude-sonnet-5-5` にし、security-findings の計画を v0.4.0 への直接の切り替えに直す。

**Architecture:** continuum-github では、worktree のブランチで `src/continuum_scan/` を `src/continuum_github/` に移し、エントリポイント、action、文書、例を新しい名前にする（Task 1）。続けてモデル ID を置き換える（Task 2）。security-findings では、まだ実行していない bedrock-rollout と WAF の計画を v0.4.0 とモデル ID に合わせて直す（Task 3）。最後に main へ merge し、その merge コミットで spec と plan をアーカイブする（Task 4）。v0.4.0 の発行と security-findings への展開はこの計画に含めない。

**Tech Stack:** Python 3.13、hatchling、uv、pytest、GitHub Actions の composite action

**Spec:** `docs/superpowers/specs/2026-11-15-package-rename-design.md`

## Global Constraints

- 新しい import 名は `continuum_github`、CLI 名は `continuum-github`。`continuum-scan` の別名は残さない。
- issue の状態マーカー `<!-- continuum-state: ... -->`、ラベル、環境変数（`CONTINUUM_LANGUAGE`、`BEDROCK_MODEL_ID` など）の名前は変えない。
- モデル ID は `global.anthropic.claude-sonnet-5-5`。`us.` 推論プロファイルについての説明は消し、代わりの説明は足さない。
- IAM のリソース指定（`inference-profile/*` と `bedrock:*::foundation-model/*`）は変えない。
- `docs/superpowers/archive/` の下と、security-findings の完了済みの spec と plan は書き換えない。
- CLI 名を変えるコミットは `refactor!:` にし、`BREAKING CHANGE:` フッターを付ける。
- push、タグ、リリース、リポジトリ変数の変更は所有者の確認を取ってから行う。v0.4.0 の発行は所有者の指示を待つ。
- 検証: `uv run pytest -q` と `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`。先に `.ruff_cache` と `__pycache__` を消し、新しいファイルは `git add` する。

## Review Focus

- 手元の `.venv` に古いエントリポイントが残り、`uv run continuum-github` が見つからない。名前を変えたあとは `uv sync` してから検証する（Task 1 の Step 4 と Step 5）。
- wheel に `continuum_github/` が入らず、リリースの資産が壊れる。`uv build` の wheel の中身を確かめる（Task 1 の Step 6）。
- `[project.scripts]` が指すモジュールと関数が実在しない。テストで import して確かめる（Task 1 の Step 1 の `test_entry_point_is_continuum_github`）。
- 状態マーカーの接頭辞が一括置換で変わり、既存の issue を読めなくなる。`continuum-state` は置換の対象の文字列を含まないが、Task 1 の Step 1 の `test_state_marker_keeps_its_name` で固定する。
- 古い名前が文書や例に残り、利用者が `continuum-scan` を打つ。tracked なファイル全体を走査するテストで防ぐ（Task 1 の Step 1 の `test_no_tracked_file_uses_the_old_names`）。

---

### Task 1: import 名と CLI 名を `continuum-github` 系にする

作業は `.worktrees/package-rename`（ブランチ `refactor/package-rename`、この plan をコミットした `main` から作る）で行う。

**Files:**
- Move: `src/continuum_scan/` → `src/continuum_github/`
- Modify: `src/continuum_github/*.py`、`tests/*.py`（`continuum_scan` の import をすべて `continuum_github` にする）
- Modify: `pyproject.toml`（`[project.scripts]`、`[tool.hatch.build.targets.wheel] packages`、`[tool.hatch.version] path`）
- Modify: `scripts/bump_version.sh`（`VERSION_FILE`）
- Modify: `sync/action.yml`、`report/action.yml`（`continuum-scan` の呼び出し 4 か所）
- Modify: `README.md`、`docs/setup.md`、`AGENTS.md`、`examples/infra/security-agent.yaml`（CLI 名と import 名）
- Modify: `examples/infra/github-actions-role.yaml`（`PolicyName: continuum-scan` → `continuum-github`）
- Create: `tests/test_names.py`
- Test: `tests/test_actions.py`、`tests/test_version.py`、`tests/test_bump_version.py`、`tests/test_smoke.py`、`tests/test_examples.py`

**Interfaces:**
- Produces: CLI `continuum-github`（サブコマンドは今と同じ `sync`、`sections`、`report build`、`report publish`、`setup ...`）、パッケージ `continuum_github`

- [ ] **Step 1: 新しい名前を求めるテストを書く**

`tests/test_names.py` を作る。古い名前はこのファイル自身に現れないよう、連結で組み立てる。

```python
"""Checks that the package and the CLI use the continuum-github names."""

import importlib
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).parent.parent
OLD_NAMES = ("continuum" + "-scan", "continuum" + "_scan")


def _tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout
    return [
        ROOT / name
        for name in out.splitlines()
        if not name.startswith("docs/superpowers/") and name != "uv.lock"
    ]


def test_entry_point_is_continuum_github() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["project"]["scripts"] == {
        "continuum-github": "continuum_github.cli:main"
    }
    module = importlib.import_module("continuum_github.cli")
    assert callable(module.main)


def test_no_tracked_file_uses_the_old_names() -> None:
    for path in _tracked_files():
        if path.is_file():
            text = path.read_text(errors="ignore")
            for old in OLD_NAMES:
                assert old not in text, f"{path.relative_to(ROOT)}: {old}"


def test_state_marker_keeps_its_name() -> None:
    from continuum_github import state

    assert state._PREFIX == "<!-- continuum-state: "  # pyright: ignore[reportPrivateUsage]
```

既存のテストも新しい名前を期待する形に直す。

- `tests/test_actions.py`: `"continuum-scan"` を `"continuum-github"` に、`"continuum-scan sync"` を `"continuum-github sync"` に、`"continuum-scan sections"` を `"continuum-github sections"` にする。
- `tests/test_version.py`: `import continuum_github`、`VERSION_FILE = ROOT / "src" / "continuum_github" / "__init__.py"`、`continuum_github.__version__`、hatch の path `"src/continuum_github/__init__.py"`。
- `tests/test_bump_version.py`: `VERSION_FILE = pathlib.Path("src") / "continuum_github" / "__init__.py"`。
- `tests/test_smoke.py`: `import continuum_github`。
- `tests/test_examples.py`: `test_example_role_invokes_bedrock_models` の `(policy,) = ...` のあとに `assert policy["PolicyName"] == "continuum-github"` を足す。
- ほかのテストの `from continuum_scan...` はすべて `from continuum_github...` にする。

- [ ] **Step 2: テストが失敗することを確かめる**

Run: `uv run pytest -q`
Expected: FAIL（`ModuleNotFoundError: No module named 'continuum_github'` で収集に失敗する）

- [ ] **Step 3: パッケージを移して名前を書き換える**

`git mv src/continuum_scan src/continuum_github` で移し、`src` の import を書き換える。`pyproject.toml` は `continuum-github = "continuum_github.cli:main"`、`packages = ["src/continuum_github"]`、`path = "src/continuum_github/__init__.py"` にし、名前が揃うので「The import package name differs from the project name.」のコメントを消す。`scripts/bump_version.sh` の `VERSION_FILE` を `src/continuum_github/__init__.py` にする。action の 4 か所の `continuum-scan` を `continuum-github` にする。`README.md`、`docs/setup.md`、`AGENTS.md`、`examples/infra/security-agent.yaml` の `continuum-scan` と `continuum_scan` を新しい名前にし、`examples/infra/github-actions-role.yaml` の `PolicyName` を `continuum-github` にする。

- [ ] **Step 4: 環境を作り直してテストを通す**

Run: `uv sync && uv run pytest -q`
Expected: PASS（379 件。今の 376 件に `tests/test_names.py` の 3 件が加わる）

- [ ] **Step 5: CLI が新しい名前で動くことを確かめる**

Run: `uv run continuum-github --help; uv run continuum-scan --help`
Expected: 1 つ目は終了コード 0 で `sync`、`sections`、`report`、`setup` が並ぶ。2 つ目は失敗する。

- [ ] **Step 6: wheel の中身を確かめる**

Run: `D=$(mktemp -d /tmp/package-rename.XXXXXX) && uv build --wheel --out-dir "$D" && unzip -l "$D"/*.whl && unzip -p "$D"/*.whl '*/entry_points.txt'`
Expected: `continuum_github/cli.py` があり、`continuum_scan/` がなく、`entry_points.txt` に `continuum-github = continuum_github.cli:main` がある

- [ ] **Step 7: 検証を通してコミットする**

Run: `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`
Expected: すべて Passed

```bash
git add src tests pyproject.toml scripts sync report README.md docs/setup.md AGENTS.md examples
git commit -m "refactor!: rename the package to continuum_github and the CLI to continuum-github" -m "BREAKING CHANGE: the CLI is now continuum-github; continuum-scan no longer exists."
```

### Task 2: モデル ID を `global.anthropic.claude-sonnet-5-5` にする

**Files:**
- Modify: `sync/action.yml`、`report/action.yml`（`bedrock-model-id` の説明）
- Modify: `README.md`（入力の表）
- Modify: `docs/setup.md`（`gh variable set BEDROCK_MODEL_ID` の行と推奨モデルの文。「A `us.` inference profile runs only in US Regions, ...」の文は消す）
- Test: `tests/test_docs.py`

**Interfaces:**
- Consumes: Task 1 のあとのファイル

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_docs.py` に足す。

```python
MODEL_ID = "global.anthropic.claude-sonnet-5-5"


def test_docs_recommend_the_global_inference_profile() -> None:
    names = ("README.md", "docs/setup.md", "sync/action.yml", "report/action.yml")
    for name in names:
        text = (ROOT / name).read_text()
        assert "us.anthropic" not in text, name
        assert MODEL_ID in text, name
    setup = (ROOT / "docs/setup.md").read_text()
    assert (
        f"gh variable set BEDROCK_MODEL_ID --repo example-org/security-findings --body {MODEL_ID}"
        in setup
    )
    assert "runs only in US Regions" not in setup
```

- [ ] **Step 2: テストが失敗することを確かめる**

Run: `uv run pytest tests/test_docs.py -q`
Expected: FAIL（`README.md` に `us.anthropic` がある）

- [ ] **Step 3: 4 つのファイルのモデル ID を置き換え、`docs/setup.md` の `us.` の文を消す**

- [ ] **Step 4: テストを通す**

Run: `uv run pytest -q`
Expected: PASS（380 件）

- [ ] **Step 5: 検証を通してコミットする**

Run: `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`
Expected: すべて Passed

```bash
git commit -am "docs: recommend the global Claude Sonnet 5.5 inference profile"
```

### Task 3: security-findings の計画を v0.4.0 とモデル ID に合わせる

作業は `/Volumes/ExternalHD/git/continuum` の `main` で行う（文書だけの変更）。`main` は origin より 1 コミット先にあるので、始める前に `git -P log --oneline origin/main..main` で中身を確かめる。continuum-github の spec と plan へのリンクは、Task 4 で移す先の `docs/superpowers/archive/specs/2026-11-15-package-rename-design.md` と `docs/superpowers/archive/plans/2026-11-15-package-rename.md` で書く。

**Files:**
- Modify: `docs/superpowers/specs/2026-11-14-bedrock-rollout-design.md`
- Modify: `docs/superpowers/plans/2026-11-14-bedrock-rollout.md`
- Modify: `docs/superpowers/plans/2026-11-14-waf-findings.md`

- [ ] **Step 1: bedrock-rollout の spec を直す**

- 50 行目を「security-findings は `v0.2.0` と `v0.3.0` を経由せず、CLI 名を `continuum-github` にした `v0.4.0` に一度で上げる（continuum-github の `docs/superpowers/archive/specs/2026-11-15-package-rename-design.md`）」にする。
- 52 行目と 60 行目のモデル ID を `global.anthropic.claude-sonnet-5-5` にする。
- 52 行目の 4 のコミットに、`README.md`、`AGENTS.md`、`docs/setup.md`、`infra/template.yaml` のコメントの CLI 名を `continuum-github` にする変更を含めると書き足す。
- 46 行目に、`GitHubActionsRole` のインラインポリシー名を同じデプロイで `continuum-scan` から `continuum-github` にすると書き足す。

- [ ] **Step 2: bedrock-rollout の plan を直す**

- Goal、Architecture、Task 2 の見出し、Interfaces、Step 1 の `v0.3.0` を `v0.4.0` にする。Step 1 の「`v0.2.0` のままの PR は merge せず、Dependabot が `v0.3.0` に更新するのを待つ」を「`v0.4.0` より前のピンの PR は merge せず、Dependabot が `v0.4.0` に更新するのを待つ」にする。
- 順番の 3 を「continuum-github の `docs/superpowers/archive/plans/2026-11-15-package-rename.md` と、`v0.4.0` のリリース」にする。
- Global Constraints のモデル ID を `global.anthropic.claude-sonnet-5-5` にし、「（設定済み）」を「（Task 2 で `us.anthropic.claude-sonnet-5-5` から変える）」にする。
- Task 1 の Files を「`GitHubActionsRole` のポリシーに文を 1 つ足し、`PolicyName` を `continuum-scan` から `continuum-github` にする」にする。Step 1 のテストに `assert [p["PolicyName"] for p in _resource("GitHubActionsRole")["Policies"]] == ["continuum-github"]` を足す。Step 6 の `--policy-name` を `continuum-github` にする。
- Task 2 の Files に `README.md`、`AGENTS.md`、`docs/setup.md`、`infra/template.yaml`（コメントだけ）、`tests/test_docs.py` を足す。Step 2 のテストに、`tests/test_docs.py` の `test_setup_runs_the_pinned_continuum_github` の `continuum-scan` を `continuum-github` にする変更と、`README.md`、`AGENTS.md`、`docs/setup.md`、`infra/template.yaml` に `continuum-scan` がないことを確かめるテストを足す。
- Task 2 の Step 4 の前に、所有者の確認を取って `gh variable set BEDROCK_MODEL_ID --repo rewse/security-findings --body global.anthropic.claude-sonnet-5-5` を実行するステップを足す。
- Task 3 の Files の `us.anthropic.claude-sonnet-5-5` を `global.anthropic.claude-sonnet-5-5` にする。

- [ ] **Step 3: WAF の plan を直す**

27 行目、264 行目、320 行目の `us.anthropic.claude-sonnet-5-5` を `global.anthropic.claude-sonnet-5-5` にする。

- [ ] **Step 4: 古い値が計画に残っていないことを確かめる**

Run: `rg -n "us\.anthropic|v0\.3\.0|policy-name continuum-scan" docs/superpowers/specs/2026-11-14-bedrock-rollout-design.md docs/superpowers/plans/2026-11-14-bedrock-rollout.md docs/superpowers/plans/2026-11-14-waf-findings.md`
Expected: `v0.3.0` を経由しないと書いた spec の 50 行目と、Task 2 で `us.anthropic.claude-sonnet-5-5` から変えると書いた行のほかは、何も出ない

- [ ] **Step 5: 検証を通してコミットする**

Run: `uv run pytest -q && uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`
Expected: PASS、すべて Passed

```bash
git commit -am "docs: roll out continuum-github v0.4.0 with the global inference profile"
```

### Task 4: continuum-github の main に merge する

- [ ] **Step 1: `main` で merge を始める**

Run: `git -C /Volumes/ExternalHD/git/continuum-github merge --no-ff --no-commit refactor/package-rename`
Expected: 衝突なしで、merge がコミット前で止まる

- [ ] **Step 2: spec と plan をアーカイブに移す**

Run: `git mv docs/superpowers/specs/2026-11-15-package-rename-design.md docs/superpowers/archive/specs/ && git mv docs/superpowers/plans/2026-11-15-package-rename.md docs/superpowers/archive/plans/`
Expected: どちらも成功する

- [ ] **Step 3: 検証して merge をコミットする**

Run: `uv sync && uv run pytest -q && uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`
Expected: PASS（380 件）、すべて Passed

```bash
git commit -m "Merge branch 'refactor/package-rename'"
```

- [ ] **Step 4: 所有者の確認を取り、continuum-github と security-findings の `main` を push し、continuum-github の CI（Lint、Test、Dependency Scan、Gitleaks）が通ることを確かめる**

- [ ] **Step 5: worktree とブランチを片付ける**

Run: `git worktree remove .worktrees/package-rename && git branch -d refactor/package-rename`
Expected: どちらも成功する
