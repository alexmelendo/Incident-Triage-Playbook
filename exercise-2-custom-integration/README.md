# Exercise 2 — Custom XSOAR Integration with REST API

## Overview

A custom XSOAR-style integration module that connects to a fictional threat intelligence REST API. Exposes three commands for IP reputation, domain reputation, and IOC search, with configurable connection settings, structured error handling, and XSOAR standard indicator field mapping.

## Design Decisions

### Architecture

- **XSOAR integration pattern**: Follows the standard XSOAR integration structure — a `Client` class handles HTTP transport, standalone functions implement each command, and `main()` dispatches based on `demisto.command()`. This is the exact pattern XSOAR generates from its integration boilerplate.
- **Separation of transport and logic**: The `Client` class owns all HTTP concerns (base URL, auth headers, retry logic). Command functions receive the client and return `CommandResults`. This makes commands testable without a real HTTP layer.
- **Mock server as a separate process**: `mock_server.py` runs a standalone Flask server that simulates the threat intel API. The integration connects to it via `base_url`. This mirrors a real deployment where the API is an external service.

### Indicator Field Mapping

Each command maps API responses to XSOAR's standard indicator fields:

| Command | XSOAR DBotScore fields | Indicator type |
|---|---|---|
| `ti-get-ip-reputation` | `ip`, `score`, `malicious`, `Vendor`, `Description` | `ip` |
| `ti-get-domain-reputation` | `domain`, `score`, `malicious`, `Vendor`, `Description` | `domain` |
| `ti-search-ioc` | Generic `IOC` table with score + metadata | N/A (search) |

DBotScore values: `0` = unknown, `1` = benign, `2` = suspicious, `3` = malicious.

### Error Handling

- HTTP errors (4xx/5xx) raise `DemistoException` with the status code and response body.
- Connection failures (DNS, timeout) are caught and surfaced as readable error messages.
- Malformed API responses (missing fields) fail gracefully with `raise_for_status()`.

### Retry Logic (Senior)

- Exponential backoff on failed requests: retries up to 3 times with delays of 1s, 2s, 4s.
- Only retries on transient errors (5xx, connection timeouts). 4xx errors are not retried.
- Implemented directly in the `Client._request()` method so all commands benefit.

### Test Module (Senior)

- `!test-module` makes a lightweight API call (`GET /health`) to verify:
  - The `base_url` is reachable
  - The `api_key` is valid
- Returns `"ok"` on success (XSOAR convention) or a descriptive error.

## Project Structure

```
exercise-2-custom-integration/
├── README.md
├── mock_server.py           # Flask mock API server
├── ti_integration.py        # XSOAR integration module
└── test_integration.py      # Unit tests
```

## Mock API Endpoints

| Method | Endpoint | Params | Description |
|---|---|---|---|
| `GET` | `/health` | — | Connectivity/auth check |
| `GET` | `/api/v1/ip/<ip>/reputation` | — | IP reputation lookup |
| `GET` | `/api/v1/domain/<domain>/reputation` | — | Domain reputation lookup |
| `GET` | `/api/v1/ioc/search` | `query`, `type`, `limit` | IOC search |
| `GET` | `/api/v1/iocs/bulk` | `limit`, `offset` | Bulk IOC retrieval |

All endpoints require header `Authorization: Bearer <api_key>`.

## Setup & Usage

### Prerequisites

- Python 3.9+
- `flask` and `requests` (`pip install flask requests`)

### Start the mock server

```bash
cd exercise-2-custom-integration
python mock_server.py
```

Server starts on `http://127.0.0.1:5000`.

### Run the integration

In a separate terminal:

```bash
python ti_integration.py
```

Runs all three commands against the mock server and prints results as JSON.

### Run tests

```bash
python -m pytest test_integration.py -v
```

## XSOAR Mapping

| Concept | XSOAR equivalent |
|---|---|
| `Client` class | Integration Client (handles HTTP) |
| `run_test_module()` | `test-module` command (Settings > Test) |
| `get_ip_reputation_command()` | `!ti-get-ip-reputation` command |
| `get_domain_reputation_command()` | `!ti-get-domain-reputation` command |
| `search_ioc_command()` | `!ti-search-ioc` command |
| `CommandResults` | Return value to war room / context |
| `DBotScore` | Standard indicator scoring in XSOAR |
| `base_url`, `api_key` | Integration parameters (Settings) |
| Retry with backoff | Resilience for unreliable API sources |
