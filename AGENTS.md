# AGENTS.md

## Purpose

continuum-github is a public tool that tracks AWS Continuum and AWS Security Agent findings as GitHub issues and posts a weekly report. The composite actions `sync/` and `report/` run the Python package `continuum_github` from a workflow in the user's private repository. `examples/` holds a sample targets file, caller workflows, and CloudFormation templates. [README.md](README.md) describes the behavior, and [docs/setup.md](docs/setup.md) the setup.

## Confidentiality

The actions run in the user's private repository, and their logs are visible to everyone with access to it. Never print finding details (titles, descriptions, file paths, URLs, severities per finding) or the model's output to workflow logs; the `continuum-github` CLI prints counts and target names only. Never put real finding details, account IDs, domains, or user names in this repository. Tests and examples use `example.com` domains, the owner `example-org`, and the account `111122223333`.

## Releases

`make release-patch`, `make release-minor`, and `make release-major` run `scripts/bump_version.sh` with `--push`: they require a clean `main` in sync with origin, commit the new `__version__` in `src/continuum_github/__init__.py`, tag it `vX.Y.Z`, and push both, so run them only when asked. The tag push starts `release.yml`, which builds the package and creates the GitHub Release with notes that git-cliff builds from the Conventional Commits since the previous tag. Nothing is published to PyPI. Do not rename `release.yml`. The ruleset `Protect release tags` restricts creating, updating, and deleting `v*` tags to the repository admin role.

After a release, update the owner's report repository `rewse/security-findings` to it: set the commit SHA and the version comment of the `rewse/continuum-github/sync` and `rewse/continuum-github/report` references in its `.github/workflows/sync.yml` and `report.yml`, and follow that repository's `AGENTS.md` for validation. When an update is missed, the weekly Dependabot github-actions update in that repository raises it.

## Validation

Run these before committing, and stage new files first because `--all-files` skips untracked files:

- `uv run pytest -q`
- `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`

When `package-lock.json` changes, also run `npm ci --ignore-scripts`.

Fix lint and type findings instead of suppressing them. Suppress one only where the rule conflicts with a deliberate design or the cause lies outside the repository, and state the reason on the same line.
