# Contributing to local-llm-security-engine

Thank you for your interest in contributing. This document explains how to set up a development environment, run the test suites, and submit changes.

---

## Table of Contents

- [Getting started](#getting-started)
- [Development setup](#development-setup)
- [Running tests](#running-tests)
- [Code style](#code-style)
- [Submitting a pull request](#submitting-a-pull-request)
- [Reporting bugs](#reporting-bugs)
- [Feature requests](#feature-requests)

---

## Getting started

1. Fork this repository and clone your fork locally.
2. Create a new branch for your change:
   ```bash
   git switch -c fix/your-fix-description
   ```
3. Make your changes, run the tests, and open a pull request against `main`.

---

## Development setup

### Python engine (`llm-security-engine/`)

```bash
cd llm-security-engine
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Copy the example environment file and adjust as needed:

```bash
cp .env.example .env
```

You do **not** need a running Ollama instance to work on the engine — all tests use mocks.

### SOC Backend (`soc-backend/`)

```bash
cd soc-backend
npm install
```

---

## Running tests

Both test suites must pass before a pull request will be merged.

```bash
# Python engine — 126 unit tests
cd llm-security-engine
python -m pytest tests/ -v

# SOC Backend — 92 unit tests
cd soc-backend
npm run test
```

If you add a feature, add corresponding tests. If you fix a bug, add a regression test that would have caught it.

---

## Code style

### Python

- Follow [PEP 8](https://peps.python.org/pep-0008/).
- Use type annotations for all function signatures.
- Keep functions short and single-purpose.
- Write docstrings for public functions and classes.

### TypeScript

- Follow the existing ESM/import conventions in `soc-backend/src/`.
- Prefer `interface` over `type` for object shapes.
- Use strict TypeScript — do not use `any`.

### Documentation

- If your change affects a documented behaviour, update the relevant file in `llm-security-engine/docs/`.
- If you change a configuration variable, update both the code docstring and `llm-security-engine/README.md`.

---

## Submitting a pull request

1. Ensure all tests pass locally.
2. Write a clear, concise pull request title and description.
3. Reference any related issues using `Closes #N` or `Fixes #N`.
4. Keep pull requests focused — one logical change per PR.
5. Be responsive to review feedback.

---

## Reporting bugs

Open a [GitHub Issue](../../issues) with:

- A clear title and description of the problem.
- Steps to reproduce the issue.
- Expected behaviour vs. actual behaviour.
- Your environment (OS, Python version, Node.js version, Ollama model).

---

## Feature requests

Open a [GitHub Issue](../../issues) with the `enhancement` label. Describe what you want to accomplish and why. For security-related reports, see [SECURITY.md](SECURITY.md) instead of opening a public issue.
