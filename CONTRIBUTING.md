# Contributing

## Setup

Use a local virtual environment named `.venv`:

```bash
virtualenv .venv
.venv/bin/pip install -e '.[dev]'
```

Do not commit `.venv/`, router credentials, tokens, cookie values, public IP addresses, MAC addresses, SSIDs, or identifiable host names.

## Checks

Run before opening a pull request:

```bash
.venv/bin/python -m pytest
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy
.venv/bin/pip-audit
```

Use sanitized fixtures only. Add tests for behavior changes. Preserve stdout for successful CLI output and stderr for diagnostics.

## Scope

Support trusted LAN or VPN access only. Do not add direct WAN exposure guidance or disable TLS verification by default.
