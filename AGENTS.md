# AGENTS.md

## Purpose

continuum-github is a public tool that tracks AWS Continuum and AWS Security Agent findings as GitHub issues and posts a weekly report. The composite actions `sync/` and `report/` run the Python package `continuum_scan` from a workflow in the user's private repository. `examples/` holds a sample targets file, caller workflows, and CloudFormation templates. [README.md](README.md) describes the behavior, and [docs/setup.md](docs/setup.md) the setup.

## GitHub conventions

Follow the GitHub configuration rules in `~/git/AGENTS.md` for everything under `.github`, the composite actions, `.pre-commit-config.yaml`, and the tool configuration in `pyproject.toml`. Workflows and actions may install Kiro CLI with its official installer (`curl -fsSL https://cli.kiro.dev/install | bash`), the same exception that rewse/actions allows.

## Confidentiality

The actions run in the user's private repository, and their logs are visible to everyone with access to it. Never print finding details (titles, descriptions, file paths, URLs, severities per finding) or Kiro's output to workflow logs; the `continuum-scan` CLI prints counts and target names only. Never put real finding details, account IDs, domains, or user names in this repository. Tests and examples use `example.com` domains, the owner `example-org`, and the account `111122223333`; `tests/test_redaction.py` checks for known owner-specific values.

## Validation

Run these before committing, and stage new files first because `--all-files` skips untracked files:

- `uv run pytest -q`
- `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`

When `package-lock.json` changes, also run `npm ci --ignore-scripts`.
