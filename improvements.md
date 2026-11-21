# AsusRouterMonitor Improvement Plan

> Development-only planning document. Delete this file before merging the `development` branch into `master`.

## Goals

- Make failures explicit and actionable.
- Protect router credentials and session tokens.
- Separate HTTP transport, firmware parsing, domain logic, and CLI presentation.
- Provide stable, typed Python APIs and machine-readable CLI output.
- Preserve compatibility where practical and document intentional breaking changes.
- Improve packaging, testing, CI, and release hygiene.
- Keep direct WAN access out of scope. Support trusted LAN access and access through a VPN only.

## Current Baseline

- HTTP and LAN HTTPS supported, including custom ports and CA bundles.
- Request timeout configurable.
- Router status, traffic, settings, clients, and CPU temperature available.
- Connected-client counts available by wired, wireless, best-effort band, and radio ID.
- `RouterInfo` now lives in `asus_router_monitor`; public imports use `from asus_router_monitor import RouterInfo`.
- Public exception hierarchy added for configuration, authentication, connection, TLS, HTTP, response, and unsupported-firmware errors.
- 33 tests pass.
- Ruff reports no lint errors.
- No package metadata, CI, license, type checking, coverage reporting, or release process.

## Guiding Principles

1. Security defaults must be safe.
2. Library methods return Python values; serialization belongs at application boundaries.
3. Network, authentication, and parsing failures must not silently become `None`.
4. Firmware-specific parsing must be isolated and fixture-tested.
5. Existing users need a documented migration path.
6. CLI stdout remains clean for machine-readable output; diagnostics go to stderr.
7. Router administration must not be exposed directly to WAN.

---

## Phase 1: Security and Failure Clarity

### 1.1 Add explicit exception hierarchy — Complete

**Implemented**

- Added public exceptions in `asus_router_monitor.exceptions`:
  - `RouterError`
  - `RouterConfigurationError`
  - `RouterConnectionError`
  - `RouterTLSError`
  - `AuthenticationError`
  - `RouterHTTPError`
  - `RouterResponseError`
  - `UnsupportedFirmwareError`
- Exported exceptions from `asus_router_monitor`.
- Invalid router address raises `RouterConfigurationError`.
- Invalid credentials and invalid login JSON raise `AuthenticationError`.
- Login, hook, and CPU-temperature request failures raise typed connection, TLS, or HTTP exceptions.
- Request exceptions retain their original cause using `raise ... from error`.
- Added regression tests for package exports, authentication rejection, timeout, TLS, HTTP errors, and exception chaining.

**Completed follow-up**

- Added parser guards to firmware payload methods. `AttributeError`, `IndexError`, `KeyError`, `TypeError`, and `ValueError` from malformed payloads now raise `RouterResponseError` with failed-operation context and exception chaining.
- CPU-temperature responses without a recognized telemetry field now raise `UnsupportedFirmwareError` instead of silently returning `None`; `ShowRouterInfo.py` catches that specific expected capability error and displays `CPU Temperature : Not available`.
- Added regression coverage proving malformed client and metric payloads raise `RouterResponseError`, public exception messages omit passwords, `login_authorization`, `asus_token`, and cookies, and CLI displays unavailable CPU temperature without hiding other error types.

**Result**

- Configuration, authentication, network, TLS, HTTP, malformed-response, and unsupported-feature failures are represented by documented public exception types.
- Original exceptions remain chained where applicable.
- Public exception messages contain operation context only; they do not include secrets.

### 1.2 Secure credential input

Change CLI password handling:

- Password no longer required as positional argument.
- Prompt through `getpass()` when omitted.
- Optionally support `ASUS_ROUTER_PASSWORD` for automation.
- Keep positional password temporarily only if a compatibility period is needed, with deprecation warning.

**Acceptance criteria**

- Recommended invocation does not expose password in process list or shell history.
- Prompt works interactively.
- Non-interactive execution fails clearly when no credential source exists.
- README contains secure usage examples.

### 1.3 Warn on plaintext HTTP

Base64 credentials over HTTP are not encrypted.

**Acceptance criteria**

- CLI warns on HTTP unless explicitly acknowledged.
- Warning goes to stderr.
- HTTPS remains certificate-verified by default.
- `--insecure` retains strong warning and trusted-LAN-only wording.

### 1.4 Add stable CLI exit codes — Complete

**Implemented**

- `0`: status collected successfully.
- `1`: connection or authentication failure.
- `2`: invalid CLI argument or router configuration.
- `3`: unsupported metric or malformed firmware response.
- Router errors print concise diagnostics to stderr; successful status output remains on stdout.
- `--debug` re-raises router errors so Python displays a traceback.
- Added tests for each return code, stdout/stderr separation, and debug re-raise behavior.

`4` remains reserved for a future partial-snapshot mode; current CLI fails whole command rather than returning partial results.

---

## Phase 2: API Consistency and Parsing Reliability

### 2.1 Return Python values consistently

### 2.1 Return Python values consistently — Complete

**Implemented**

- `get_online_clients()` returns `list[dict]`.
- `get_traffic()` returns `dict` with `speed` and `total` mappings.
- `get_traffic_total()` returns a dictionary with numeric `sent` and `recv` values.
- Removed manual JSON construction and serialization from these library methods.
- Updated CLI helpers and tests to consume native values.
- Documented breaking return-type changes and caller-side JSON serialization in README.

This is an intentional next-major-version API break; no JSON-string compatibility layer is retained.

### 2.2 Extract pure response parsers — Complete

**Implemented**

- Added side-effect-free `asus_router_monitor.parsers` functions for uptime, memory, CPU, network counters, traffic totals, WAN status, client lists, DHCP leases, NVRAM values, and CPU temperature.
- `RouterInfo` now delegates firmware text decoding to this module; it retains transport and compatibility-facade responsibilities.
- Malformed data raises `RouterResponseError`; absent CPU telemetry raises `UnsupportedFirmwareError`.
- Added parser unit tests with sanitized fixture files. Fixtures contain no router credentials, tokens, public addresses, SSIDs, or identifying hostnames.

### 2.3 Add typed models — Complete

**Implemented**

- Added and publicly exported `TypedDict` contracts: `Uptime`, `MemoryUsage`, `CpuUsage`, `TrafficTotals`, `TrafficRate`, `Traffic`, `WanStatus`, `ClientInfo`, and `ClientCounts`.
- Added return annotations to primary `RouterInfo` metric methods.
- README documents imports and traffic units (megabits).

Type-checking automation belongs with pending package metadata and CI baseline work; contracts are ready for that integration. `RouterSnapshot` remains deferred to snapshot API work.

### 2.4 Correct traffic calculations — Complete

- Added configurable sampling with `time.monotonic()` elapsed-time measurement.
- ASUS `netdev` hexadecimal values are byte counters. Removed erroneous `/ 2`; totals convert bytes to Mbit and rates convert byte deltas to Mbit/s.
- Public traffic totals and rates round to one decimal place.
- Counter decreases caused by reboot or unknown rollover report zero rate, never negative throughput.
- CPU firmware jiffies normalize to percentages, preventing impossible values such as `6147417%`.
- Tests cover known counter conversion, measured sampling, rounding, and counter reset.

---

## Phase 3: Architecture Refactor

### 3.1 Introduce transport client — Complete

- Added `AsusRouterClient` for base URL normalization, authenticated `requests.Session` lifecycle, TLS verification, timeouts, hook calls, and CPU-temperature endpoint requests.
- Transport contains no firmware parser or domain calculations.
- Supports `close()` and context-manager use.
- Hook requests reauthenticate and retry at most once after HTTP 401/403.
- Constructor accepts an injectable session; transport tests mock that seam.

### 3.2 Introduce domain monitor/service — Complete

- Added `RouterMonitor` for uptime, resources, WAN, traffic, settings, clients, CPU temperature, and snapshots.
- Monitor combines transport responses with pure parsers; it makes no direct HTTP requests.
- `RouterInfo` now delegates to client and monitor as compatibility facade; documented public calls continue to work.

### 3.3 Add snapshot API — Complete

```python
snapshot = monitor.get_snapshot()
```

- Snapshot has a UTC timestamp and fetches each required source once.
- Unsupported CPU temperature is optional and represented as `None`.
- Transport, authentication, and malformed required responses abort collection rather than return ambiguous partial data.
- Added test asserting endpoint call count and optional-temperature policy.

### 3.4 Package layout — Complete for current flat package

```text
asus_router_monitor/
├── client.py
├── exceptions.py
├── models.py
├── monitor.py
├── parsers.py
└── router_info.py
```

Parser submodules and `src/` layout remain optional future packaging refinements; current separation is enforced by module responsibilities.

---

## Phase 4: CLI and Usability

### 4.1 Add subcommands

Proposed interface:

```bash
asus-router-monitor status
asus-router-monitor clients
asus-router-monitor traffic
asus-router-monitor settings
```

Optional field selection:

```bash
asus-router-monitor status --fields uptime,wan,temperature
```

**Acceptance criteria**

- Commands request only needed router data.
- Unsupported optional features do not break unrelated commands.
- Help includes examples.

### 4.2 Add output formats — Complete for status output

- `ShowRouterInfo.py --format text` remains default human-readable status output.
- Added `--format json` with a stable single status object: uptime, resources, temperature, traffic total, WAN, selected settings, LAN, client counts, and DHCP lease count.
- JSON stdout contains no labels or diagnostics; errors remain on stderr.
- Unsupported CPU temperature serializes as JSON `null`.
- Added schema and stdout/stderr regression tests.

Prometheus output and command-specific client-detail output remain future work under subcommands.

### 4.3 Improve human-readable output — Complete for status output

- Replaced ambiguous `Data` and `Online` labels with grouped Router status, Resources, Network, and Connected clients output.
- Text output displays uptime in seconds, memory in KiB, CPU use in percent, CPU temperature in °C, and traffic totals in Mbit.
- WAN state displays as `yes` or `no`.
- Missing CPU temperature displays as `unavailable`, never raw `None`.
- Added regression test for semantic labels and units.

Traffic-rate display is available through `get_traffic()`; status CLI currently shows totals only.

### 4.4 Configurable radio mapping

ASUS radio IDs vary by model. Allow model-specific mapping:

```python
radio_bands = {"1": "2.4 GHz", "2": "5 GHz", "3": "6 GHz"}
```

**Acceptance criteria**

- Exact radio counts remain authoritative.
- Best-effort defaults remain documented.
- Unknown radios are never discarded.

---

## Phase 5: Packaging and Project Health

### 5.1 Add packaging metadata

Create `pyproject.toml` containing:

- Project name and version
- Python version support
- `requests` dependency
- Development dependencies
- Console entry point
- Ruff, pytest, and type-checker configuration

Target installation:

```bash
pipx install asus-router-monitor
asus-router-monitor status
```

### 5.2 Add license and repository metadata

Decide and add a license before encouraging reuse. Also add:

- GitHub repository description
- Supported router/firmware notes
- Contributing guide
- Changelog
- Security policy

### 5.3 Add CI

GitHub Actions matrix for supported Python versions, initially 3.10–3.13.

Required checks:

```bash
pytest
ruff check
ruff format --check
mypy
pip-audit
```

Add coverage after installing `pytest-cov` and set a realistic threshold based on baseline.

### 5.4 Dependency maintenance

Enable Dependabot or Renovate. Test minimum and latest supported `requests` versions.

**Acceptance criteria**

- Fresh checkout installs reproducibly.
- All checks pass in CI.
- No reliance on ambient global packages.

---

## Testing Strategy

### Unit tests

- URL normalization
- Authentication outcomes
- Exception mapping
- Parser success/failure
- Unit conversions
- Client classification
- Radio mapping
- Secret redaction

### Fixture tests

Store sanitized responses by model/firmware:

```text
tests/fixtures/rt_ac68u/
tests/fixtures/zenwifi_xd4/
tests/fixtures/malformed/
```

Never commit credentials, tokens, public addresses, real MAC addresses, SSIDs, or identifiable hostnames.

### Integration tests

- Mock HTTP server for login, token expiry, retries, status codes, and timeouts.
- Optional real-router tests gated by environment variables and never run in public CI.

### CLI tests

- Secure password prompt
- Exit codes
- stderr/stdout separation
- JSON schema
- Human-readable output
- `--insecure` warning

---

## Security Requirements

- No direct WAN support.
- Recommend VPN for remote access.
- HTTPS verification enabled by default.
- No secrets in logs, exceptions, fixtures, command examples, or commits.
- HTTP emits warning because Base64 credentials are plaintext-equivalent.
- `--insecure` remains explicit and documented as vulnerable to man-in-the-middle attacks.
- Client MAC addresses, IPs, SSIDs, and names treated as sensitive inventory.
- Add a pre-commit or CI secret scan before releases.

---

## Compatibility and Release Strategy

### Suggested versions

- `1.x`: stabilization, explicit exceptions where non-breaking, packaging, CI.
- `2.0`: consistent native return types, new package layout, secure CLI, typed models.

### Migration support

- Keep `RouterInfo` facade for one deprecation cycle.
- Publish old-to-new method mapping.
- Emit `DeprecationWarning` for JSON-string return behavior.
- Document changed CLI credential handling and output formats.

---

## Recommended Execution Order

1. Add package metadata, CI, license decision, and baseline coverage.
2. Add exception hierarchy and explicit authentication failure.
3. Add secure password prompt and HTTP warning.
4. Extract pure parsers with sanitized fixtures.
5. Correct traffic units and elapsed-time calculation.
6. Introduce `requests.Session` transport.
7. Add typed models and native return types.
8. Add snapshot API.
9. Add CLI subcommands and JSON output.
10. Add optional monitoring/exporter integrations only after core API stabilizes.

## Definition of Done for Development-to-Master Merge

- Planned release scope complete and documented.
- All tests, linting, formatting, typing, and security checks pass.
- No credentials, tokens, private addresses, or identifying fixture data committed.
- README and changelog updated.
- Backward compatibility and breaking changes documented.
- `development` rebased or merged cleanly with current `master`.
- `improvements.md` deleted before final merge to `master`.
