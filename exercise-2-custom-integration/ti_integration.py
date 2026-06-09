"""
Exercise 2 — Custom XSOAR Integration with REST API

XSOAR-style integration that connects to a fictional threat intelligence API.
Commands:
  !test-module                    — verify connectivity + credentials
  !ti-get-ip-reputation ip=...   — IP reputation lookup
  !ti-get-domain-reputation domain=... — domain reputation lookup
  !ti-search-ioc query=... type=... limit=... — IOC search

Settings: base_url and api_key are configurable.

Senior features:
  - test-module connectivity check
  - Exponential backoff retry on failed requests (up to 3 retries)
"""

import json
import sys
import time
from typing import Any

import requests

# ─── XSOAR stubs ─────────────────────────────────────────────────────────
# In a real XSOAR instance these are provided by the demisto SDK.
# We stub them here so the module can run standalone.

try:
    import demistomock as demisto
    from CommonServerPython import (
        CommandResults,
        DBotScore,
        DemistoException,
        IndicatorType,
        return_error,
        return_results,
    )
    IS_XSOAR = True
except ImportError:
    IS_XSOAR = False

    class DemistoException(Exception):
        def __init__(self, message="", res=None):
            super().__init__(message)
            self.res = res

    class IndicatorType:
        IP = "ip"
        Domain = "domain"
        File = "file"

    class DBotScore:
        def __init__(self, indicator, indicator_type, vendor, score, malicious_description=None):
            self.indicator = indicator
            self.indicator_type = indicator_type
            self.vendor = vendor
            self.score = score
            self.malicious_description = malicious_description

        def to_context(self):
            return {
                "Indicator": self.indicator,
                "Type": self.indicator_type,
                "Vendor": self.vendor,
                "Score": self.score,
                "Reliability": "C - Fairly reliable",
            }

    class CommandResults:
        def __init__(self, outputs_prefix=None, outputs=None, raw_response=None,
                     readable_output=None, indicator=None, indicators=None):
            self.outputs_prefix = outputs_prefix
            self.outputs = outputs
            self.raw_response = raw_response
            self.readable_output = readable_output
            self.indicator = indicator
            self.indicators = indicators or []

    def return_error(message):
        print(f"ERROR: {message}", file=sys.stderr)
        sys.exit(1)

    def return_results(results):
        if isinstance(results, list):
            for r in results:
                _print_result(r)
        else:
            _print_result(results)

    def _print_result(r):
        if isinstance(r, CommandResults):
            output = {
                "outputs_prefix": r.outputs_prefix,
                "outputs": r.outputs,
                "readable_output": r.readable_output,
            }
            if r.indicators:
                output["indicators"] = [ind.to_context() if hasattr(ind, "to_context") else ind for ind in r.indicators]
            print(json.dumps(output, indent=2))

    class demisto:
        @staticmethod
        def params():
            return {"base_url": "http://127.0.0.1:5000", "api_key": "test-api-key-12345"}

        @staticmethod
        def args():
            return {}

        @staticmethod
        def command():
            return ""

        @staticmethod
        def results(result):
            pass


# ─── Client ──────────────────────────────────────────────────────────────

class Client:
    """
    HTTP client for the Threat Intelligence REST API.

    Handles authentication, request construction, and retry logic
    with exponential backoff for transient failures.
    """

    MAX_RETRIES = 3
    BACKOFF_BASE = 1  # seconds

    def __init__(self, base_url: str, api_key: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        })

    def _request(self, method: str, url_suffix: str, params: dict = None) -> dict:
        """
        Make an HTTP request with exponential backoff retry.

        Retries up to MAX_RETRIES times on:
          - 5xx server errors
          - Connection errors / timeouts

        Does NOT retry on 4xx client errors (bad input, auth failure).
        """
        url = f"{self.base_url}{url_suffix}"
        last_exception = None

        for attempt in range(self.MAX_RETRIES + 1):
            try:
                response = self.session.request(method, url, params=params, timeout=10)

                # Success
                if response.ok:
                    return response.json()

                # Client errors — don't retry
                if 400 <= response.status_code < 500:
                    raise DemistoException(
                        f"API error {response.status_code}: {response.text}",
                        res=response,
                    )

                # Server errors — retry
                last_exception = DemistoException(
                    f"Server error {response.status_code} (attempt {attempt + 1}/{self.MAX_RETRIES + 1})",
                    res=response,
                )

            except requests.exceptions.ConnectionError as e:
                last_exception = DemistoException(f"Connection failed: {e}")
            except requests.exceptions.Timeout as e:
                last_exception = DemistoException(f"Request timed out: {e}")
            except DemistoException:
                raise  # Don't retry client errors

            # Exponential backoff before next attempt
            if attempt < self.MAX_RETRIES:
                delay = self.BACKOFF_BASE * (2 ** attempt)
                time.sleep(delay)

        raise last_exception

    def test_connectivity(self) -> dict:
        """Test module: verify base_url is reachable and api_key is valid."""
        return self._request("GET", "/health")

    def get_ip_reputation(self, ip: str) -> dict:
        return self._request("GET", f"/api/v1/ip/{ip}/reputation")

    def get_domain_reputation(self, domain: str) -> dict:
        return self._request("GET", f"/api/v1/domain/{domain}/reputation")

    def search_ioc(self, query: str, ioc_type: str = "", limit: int = 10) -> dict:
        params = {"query": query, "limit": limit}
        if ioc_type:
            params["type"] = ioc_type
        return self._request("GET", "/api/v1/ioc/search", params=params)


# ─── Score mapping ───────────────────────────────────────────────────────

def _score_to_dbot(score: int) -> int:
    """Map 0-100 score to XSOAR DBotScore (0=unknown, 1=good, 2=suspicious, 3=bad)."""
    if score >= 70:
        return 3
    if score >= 40:
        return 2
    if score > 0:
        return 1
    return 0


def _format_markdown_table(headers: list, rows: list) -> str:
    """Build a simple markdown table."""
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)


# ─── Commands ────────────────────────────────────────────────────────────

def run_test_module(client: Client) -> str:
    """!test-module — verify connectivity and credentials."""
    result = client.test_connectivity()
    if result.get("status") == "ok":
        return "ok"
    return_error(f"Connectivity test failed: {result}")
    return ""


def get_ip_reputation_command(client: Client, args: dict) -> CommandResults:
    """!ti-get-ip-reputation ip=<value>"""
    ip = args.get("ip")
    if not ip:
        return_error("ip argument is required")

    result = client.get_ip_reputation(ip)
    dbot_score = _score_to_dbot(result["score"])

    dbot = DBotScore(
        indicator=ip,
        indicator_type=IndicatorType.IP,
        vendor="FakeTI",
        score=dbot_score,
        malicious_description="Flagged as malicious by FakeTI" if result["is_malicious"] else None,
    )

    readable = (
        f"## IP Reputation: {ip}\n"
        f"- **Score:** {result['score']}/100\n"
        f"- **Categories:** {', '.join(result.get('categories', []))}\n"
        f"- **Last seen:** {result.get('last_seen', 'N/A')}\n"
        f"- **Malicious:** {result['is_malicious']}\n"
        f"- **DBot score:** {dbot_score}\n"
    )

    return CommandResults(
        outputs_prefix="FakeTI.IP",
        outputs=result,
        raw_response=result,
        readable_output=readable,
        indicators=[dbot],
    )


def get_domain_reputation_command(client: Client, args: dict) -> CommandResults:
    """!ti-get-domain-reputation domain=<value>"""
    domain = args.get("domain")
    if not domain:
        return_error("domain argument is required")

    result = client.get_domain_reputation(domain)
    dbot_score = _score_to_dbot(result["score"])

    dbot = DBotScore(
        indicator=domain,
        indicator_type=IndicatorType.Domain,
        vendor="FakeTI",
        score=dbot_score,
        malicious_description="Flagged as malicious by FakeTI" if result["is_malicious"] else None,
    )

    readable = (
        f"## Domain Reputation: {domain}\n"
        f"- **Score:** {result['score']}/100\n"
        f"- **Registrar:** {result.get('registrar', 'N/A')}\n"
        f"- **Creation date:** {result.get('creation_date', 'N/A')}\n"
        f"- **Malicious:** {result['is_malicious']}\n"
        f"- **DBot score:** {dbot_score}\n"
    )

    return CommandResults(
        outputs_prefix="FakeTI.Domain",
        outputs=result,
        raw_response=result,
        readable_output=readable,
        indicators=[dbot],
    )


def search_ioc_command(client: Client, args: dict) -> CommandResults:
    """!ti-search-ioc query=<string> type=ip|domain|hash limit=<int>"""
    query = args.get("query")
    if not query:
        return_error("query argument is required")

    ioc_type = args.get("type", "")
    limit = int(args.get("limit", 10))

    result = client.search_ioc(query, ioc_type, limit)
    iocs = result.get("results", [])

    headers = ["Value", "Type", "Score", "Malicious"]
    rows = [
        [ioc.get("value", "N/A"), ioc.get("type", "N/A"),
         ioc.get("score", "N/A"), ioc.get("is_malicious", "N/A")]
        for ioc in iocs
    ]
    readable = (
        f"## IOC Search Results\n"
        f"**Query:** {query} | **Type filter:** {ioc_type or 'all'} | "
        f"**Results:** {result.get('total_results', 0)}\n\n"
        f"{_format_markdown_table(headers, rows) if rows else 'No results found.'}\n"
    )

    return CommandResults(
        outputs_prefix="FakeTI.SearchIOC",
        outputs=result,
        raw_response=result,
        readable_output=readable,
    )


# ─── Main dispatcher ────────────────────────────────────────────────────

def main():
    """XSOAR command dispatcher."""
    params = demisto.params()
    base_url = params.get("base_url", "")
    api_key = params.get("api_key", "")

    client = Client(base_url=base_url, api_key=api_key)

    command = demisto.command()

    try:
        if command == "test-module":
            result = run_test_module(client)
            if IS_XSOAR:
                demisto.results(result)
            else:
                print(f"Test module result: {result}")

        elif command == "ti-get-ip-reputation":
            return_results(get_ip_reputation_command(client, demisto.args()))

        elif command == "ti-get-domain-reputation":
            return_results(get_domain_reputation_command(client, demisto.args()))

        elif command == "ti-search-ioc":
            return_results(search_ioc_command(client, demisto.args()))

        else:
            return_error(f"Unknown command: {command}")

    except Exception as e:
        return_error(f"Command '{command}' failed: {e}")


# ─── Standalone demo ─────────────────────────────────────────────────────

if __name__ == "__main__":
    # When run directly, execute all commands as a demo
    params = demisto.params()
    client = Client(base_url=params["base_url"], api_key=params["api_key"])

    print("=" * 60)
    print("TEST MODULE")
    print("=" * 60)
    result = run_test_module(client)
    print(f"Result: {result}\n")

    print("=" * 60)
    print("IP REPUTATION: 185.220.101.1")
    print("=" * 60)
    return_results(get_ip_reputation_command(client, {"ip": "185.220.101.1"}))

    print("\n" + "=" * 60)
    print("DOMAIN REPUTATION: evil-phishing.xyz")
    print("=" * 60)
    return_results(get_domain_reputation_command(client, {"domain": "evil-phishing.xyz"}))

    print("\n" + "=" * 60)
    print("IOC SEARCH: query=evil type=domain")
    print("=" * 60)
    return_results(search_ioc_command(client, {"query": "evil", "type": "domain", "limit": 10}))
