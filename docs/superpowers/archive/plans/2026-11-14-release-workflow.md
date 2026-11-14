# リリースの仕組み 実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `make release-patch|minor|major` でバージョンを上げたコミットとタグを push し、タグの push で GitHub Release が作られるようにする。

**Architecture:** バージョンは `src/continuum_scan/__init__.py` の `__version__` に置き、hatch が読む。`scripts/bump_version.sh` がコミットとタグを作り、`release.yml` がビルド、git-cliff のリリースノート、GitHub Release を作る。PyPI には公開しない。

**Tech Stack:** bash、make、hatchling、uv、git-cliff、GitHub Actions、pytest

**Spec:** `docs/superpowers/archive/specs/2026-11-14-release-workflow-design.md`

参照元（読むだけ）: `~/git/enecoq-data-fetcher` の `Makefile`、`scripts/bump_version.sh`、`tests/test_bump_version.py`、`cliff.toml`、`.github/workflows/release.yml`。`~/git/actions/.github/workflows/release.yml`。

## Global Constraints

- PyPI に公開しない。`release.yml` のジョブは `contents: write` だけを持ち、`id-token` と `environment` を持たない。
- `uses:` はすべて 40 桁の SHA と `# vX.Y.Z` で固定する。既にこのリポジトリで使っている action は、`.github/workflows/` と同じ SHA にする（`tests/test_actions.py` の既存テストがこれを確かめる）。git-cliff は `orhun/git-cliff-action@a9a95522b26fe6403f7bb24031f21fb573d0f5ff  # v4.9.1`。
- パッケージをインストールする手順の前に `rewse/actions/setup-safe-chain` を入れる。
- バージョンの初期値は `0.1.1`。タグは `vX.Y.Z`。バージョン上げのコミットは `chore: bump version to X.Y.Z`。
- 所有者固有の値（アカウント ID、所有者のドメイン、実在のリポジトリ ID、ホスト名、非公開リポジトリ名）を入れない。
- 検証は `uv run pytest -q` と `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`（新しいファイルは先に stage する）。
- push、タグ、ルールセットの作成、GitHub Release の作成は、所有者の確認を取ってから controller が行う。

## Review Focus

- `make release-*` を main 以外のブランチ、未コミットの変更がある状態、origin より進んだ状態で実行すると、何も作らずに止まること（Task 2 のテスト）。
- 既にあるタグと同じバージョンを作ろうとすると止まること（Task 2）。
- `release.yml` がタグ以外（ブランチの push）で動かないこと（Task 3）。
- リリースノートが `chore: bump version` のコミットを含まないこと（Task 3 の `cliff.toml` のテスト）。
- `uv build` の成果物のバージョンがタグと一致すること（Task 1 で `__version__` を hatch が読むことを固定し、Task 4 で実物を確かめる）。

---

### Task 1: バージョンを `__version__` から読む

**Files:**
- Modify: `src/continuum_scan/__init__.py`（今は空。モジュールの docstring と `__version__ = "0.1.1"` を置く）
- Modify: `pyproject.toml`（`version = "0.1.0"` を消し、`dynamic = ["version"]` と `[tool.hatch.version] path = "src/continuum_scan/__init__.py"` を足す）、`uv.lock`
- Test: `tests/test_version.py`

**Interfaces:**
- Produces: `continuum_scan.__version__: str`。Task 2 のスクリプトは `src/continuum_scan/__init__.py` の `^__version__ = "X.Y.Z"$` の行を書き換える。

- [ ] **Step 1: 失敗するテストを書く**

```python
def test_package_version_comes_from_the_module() -> None:
    assert continuum_scan.__version__ == "0.1.1"
    assert importlib.metadata.version("continuum-github") == continuum_scan.__version__

def test_pyproject_reads_the_version_from_the_module() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "version" not in project["project"]
    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["hatch"]["version"] == {"path": "src/continuum_scan/__init__.py"}
```

- [ ] **Step 2: 失敗を確かめる**

Run: `uv run pytest tests/test_version.py -q`
Expected: FAIL（`__version__` が無い）

- [ ] **Step 3: `__init__.py` と `pyproject.toml` を変え、`uv lock` と `uv sync` を実行する**

`uv lock` は空の `XDG_CONFIG_HOME` で実行し、利用者の全体設定の項目が `uv.lock` に入らないようにする（`XDG_CONFIG_HOME=$(mktemp -d /tmp/uvcfg.XXXXXX) uv lock`）。`git diff uv.lock` で、このパッケージのバージョンの行だけが変わることを確かめる。

- [ ] **Step 4: テストを通す**

Run: `uv run pytest -q`
Expected: PASS

- [ ] **Step 5: コミット**

```bash
git add src/continuum_scan/__init__.py pyproject.toml uv.lock tests/test_version.py
git commit -m "build: read the package version from __version__"
```

### Task 2: バージョン上げのスクリプトと Makefile

**Files:**
- Create: `scripts/bump_version.sh`（参照元をコピーし、`VERSION_FILE="src/continuum_scan/__init__.py"` にする。ほかは変えない）、`Makefile`（参照元と同じ）
- Test: `tests/test_bump_version.py`（参照元をコピーし、`VERSION_FILE` を `src/continuum_scan/__init__.py` にする）

**Interfaces:**
- Consumes: Task 1 の `__version__` の行
- Produces: `scripts/bump_version.sh {major|minor|patch} [--push]`、`make release-patch|release-minor|release-major`

- [ ] **Step 1: 参照元のテストをコピーしてパスを直す**

テストは参照元の 8 件をそのまま持ってくる: `test_bump_patch_commits_and_tags`、`test_bump_minor_and_major_reset_lower_parts`、`test_bump_with_push_sends_branch_and_tag`、`test_bump_refuses_unclean_tree`、`test_bump_refuses_other_branch`、`test_bump_refuses_unpushed_commit`、`test_bump_refuses_existing_tag`、`test_bump_refuses_invalid_arguments`。

- [ ] **Step 2: 失敗を確かめる**

Run: `uv run pytest tests/test_bump_version.py -q`
Expected: FAIL（スクリプトが無い）

- [ ] **Step 3: スクリプトと Makefile を置き、`chmod +x scripts/bump_version.sh` する**

- [ ] **Step 4: テストと pre-commit（shellcheck を含む）を通す**

Run: `uv run pytest -q && git add scripts Makefile tests/test_bump_version.py && uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`
Expected: PASS

- [ ] **Step 5: コミット**

```bash
git commit -m "build: add the version bump script and make targets"
```

### Task 3: `release.yml`、`cliff.toml`、AGENTS.md

**Files:**
- Create: `.github/workflows/release.yml`、`cliff.toml`
- Modify: `AGENTS.md`（Releases の節を足し、Confidentiality の `tests/test_redaction.py` への言及を消す）
- Test: `tests/test_release.py`

**Interfaces:**
- Consumes: Task 2 のタグ `vX.Y.Z`

`release.yml` は参照元の enecoq-data-fetcher から、`environment`、`id-token: write`、`Publish to PyPI` のステップを除いたもの。setup-python は使わず、uv は `astral-sh/setup-uv`（`enable-cache: false`）で入れる。手順は checkout（`fetch-depth: 0`、`persist-credentials: false`）、setup-uv、Safe Chain、`uv build`、git-cliff（`args: --latest --strip header`）、`gh release create "$TAG_NAME" --title "$TAG_NAME" --notes "$RELEASE_NOTES" --verify-tag`、`gh release upload "$TAG_NAME" dist/* --clobber`。`cliff.toml` は参照元をコピーし、比較 URL を `https://github.com/rewse/continuum-github/compare/` にする。

AGENTS.md の Releases の節に書くこと: `make release-patch|minor|major` は main がクリーンで origin と同じときだけコミットとタグを作って push し、タグの push で `release.yml` が GitHub Release を作ること。頼まれたときだけ実行すること。PyPI には公開しないこと。`release.yml` の名前を変えないこと。タグはルールセット `Protect release tags` で守られ、admin ロールだけが例外であること。

- [ ] **Step 1: 失敗するテストを書く**

```python
def test_release_runs_only_on_version_tags() -> None:
    workflow = _load("release.yml")
    assert workflow[True] == {"push": {"tags": ["v*"]}}

def test_release_has_only_contents_write() -> None:
    (job,) = _load("release.yml")["jobs"].values()
    assert job["permissions"] == {"contents": "write"}
    assert "environment" not in job

def test_release_does_not_publish_to_pypi() -> None:
    assert "pypi" not in (WORKFLOWS / "release.yml").read_text().lower()

def test_release_verifies_the_tag_and_uploads_the_build() -> None:
    runs = "\n".join(s.get("run", "") for s in _steps("release.yml"))
    assert "uv build" in runs and "--verify-tag" in runs and "dist/*" in runs

def test_release_sets_up_safe_chain_before_building() -> None: ...
    # setup-safe-chain のステップが uv build のステップより前

def test_release_notes_skip_version_bumps() -> None:
    parsers = tomllib.loads((ROOT / "cliff.toml").read_text())["git"]["commit_parsers"]
    assert {"message": "^chore: bump version", "skip": True} in parsers
```

既存の SHA 固定のテストと、`run:` に `${{` を書かないテストが `release.yml` も対象にしていることを確かめ、していなければ対象に足す。

- [ ] **Step 2: 失敗を確かめる**

Run: `uv run pytest tests/test_release.py -q`
Expected: FAIL（ファイルが無い）

- [ ] **Step 3: `release.yml`、`cliff.toml`、AGENTS.md を書く**

- [ ] **Step 4: テストと pre-commit（actionlint、zizmor を含む）を通す**

Run: `uv run pytest -q && git add -A && uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`
Expected: PASS

- [ ] **Step 5: コミット**

```bash
git commit -m "ci: publish GitHub Releases from version tags"
```

### Task 4: 反映する（所有者の確認を取ってから controller が行う）

- [ ] **Step 1: main を push する**
- [ ] **Step 2: ルールセット `Protect release tags` を作る**

Run: `gh api repos/rewse/continuum-github/rulesets -X POST --input <JSON>`（`target: tag`、`enforcement: active`、`conditions.ref_name.include: ["refs/tags/v*"]`、`rules: creation, update, deletion`、`bypass_actors: [{actor_id: 5, actor_type: RepositoryRole, bypass_mode: always}]`。enecoq-data-fetcher のルールセットと同じ）
Expected: `gh api repos/rewse/continuum-github/rulesets --jq '.[].name'` が `Protect release tags` を返す

- [ ] **Step 3: `v0.1.0` と `v0.1.1` の GitHub Release を、成果物なしで後から作る**

それぞれ `git cliff --config cliff.toml <前のタグ>..<タグ> --strip header` でノートを作り（`v0.1.0` は最初のコミットから）、`gh release create <タグ> --verify-tag --title <タグ> --notes-file <ファイル> --latest=false`（`v0.1.1` は `--latest`）。
Expected: `gh release list --repo rewse/continuum-github` に 2 件

- [ ] **Step 4: `make release-patch` を実行して `v0.1.2` を出す**

Expected: `release.yml` の実行が成功し、`v0.1.2` の GitHub Release に `continuum_github-0.1.2-py3-none-any.whl` と `continuum_github-0.1.2.tar.gz` が付き、latest になる

- [ ] **Step 5: security-findings のピンを `v0.1.2` に上げる**

Dependabot の github-actions は workflow 2 つのピンだけを上げ、`pyproject.toml` の git 依存の SHA は上げないので、その PR は security-findings の「3 か所の SHA が一致する」テストで落ちる。Dependabot の PR は閉じ、security-findings で workflow 2 つと `pyproject.toml`、`uv.lock` を同じ SHA に上げるコミットを作って push する（`fix: use continuum-github v0.1.2`）。
Expected: security-findings の CI と、手動で動かした sync が成功する
