# Contributing to Agentic OWASP Security Scanner

Thank you for your interest in contributing!

## Development Setup
- Python 3.11+
- Create venv, install with `pip install -e .[dev]`
- Install pre-commit hooks: `pre-commit install`

## Commit Guidelines
- Conventional commits preferred: feat, fix, docs, chore, refactor, test, ci
- Small, atomic commits with clear messages

## Pull Requests
- Include tests for new code
- Ensure CI passes
- Update docs when behavior changes

## Coding Standards
- Black, isort, mypy, flake8
- Prefer async IO for network code

## Security
- Do not include credentials in issues or PRs
- Report sensitive vulnerabilities privately
