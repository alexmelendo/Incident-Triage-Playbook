"""Unit tests for the XSOAR threat intelligence integration."""

import unittest
from unittest.mock import MagicMock, patch
from ti_integration import (
    Client,
    _score_to_dbot,
    get_ip_reputation_command,
    get_domain_reputation_command,
    search_ioc_command,
    run_test_module,
)


class TestScoreMapping(unittest.TestCase):
    """Validate score -> DBotScore mapping."""

    def test_score_above_70_is_malicious(self):
        self.assertEqual(_score_to_dbot(95), 3)
        self.assertEqual(_score_to_dbot(70), 3)

    def test_score_40_to_69_is_suspicious(self):
        self.assertEqual(_score_to_dbot(40), 2)
        self.assertEqual(_score_to_dbot(55), 2)
        self.assertEqual(_score_to_dbot(69), 2)

    def test_score_1_to_39_is_good(self):
        self.assertEqual(_score_to_dbot(1), 1)
        self.assertEqual(_score_to_dbot(25), 1)
        self.assertEqual(_score_to_dbot(39), 1)

    def test_score_0_is_unknown(self):
        self.assertEqual(_score_to_dbot(0), 0)


class TestIPReputationCommand(unittest.TestCase):

    def _make_client(self, response):
        client = Client.__new__(Client)
        client.base_url = "http://fake"
        client.api_key = "key"
        client.session = MagicMock()
        client._request = MagicMock(return_value=response)
        return client

    def test_malicious_ip_returns_dbot_3(self):
        client = self._make_client({
            "ip": "185.220.101.1", "score": 92,
            "categories": ["tor-exit-node"], "last_seen": "2026-06-09",
            "is_malicious": True,
        })
        result = get_ip_reputation_command(client, {"ip": "185.220.101.1"})
        self.assertEqual(result.outputs_prefix, "FakeTI.IP")
        self.assertTrue(result.outputs["is_malicious"])
        dbot = result.indicators[0]
        self.assertEqual(dbot.score, 3)
        self.assertEqual(dbot.indicator, "185.220.101.1")

    def test_clean_ip_returns_dbot_1(self):
        client = self._make_client({
            "ip": "8.8.8.8", "score": 5,
            "categories": ["dns"], "last_seen": "2026-06-08",
            "is_malicious": False,
        })
        result = get_ip_reputation_command(client, {"ip": "8.8.8.8"})
        dbot = result.indicators[0]
        self.assertEqual(dbot.score, 1)
        self.assertFalse(result.outputs["is_malicious"])

    def test_missing_ip_raises(self):
        client = self._make_client({})
        with self.assertRaises(SystemExit):
            get_ip_reputation_command(client, {})


class TestDomainReputationCommand(unittest.TestCase):

    def _make_client(self, response):
        client = Client.__new__(Client)
        client.base_url = "http://fake"
        client.api_key = "key"
        client._request = MagicMock(return_value=response)
        return client

    def test_malicious_domain(self):
        client = self._make_client({
            "domain": "evil-phishing.xyz", "score": 97,
            "registrar": "NameCheap", "creation_date": "2026-05-01",
            "is_malicious": True,
        })
        result = get_domain_reputation_command(client, {"domain": "evil-phishing.xyz"})
        self.assertEqual(result.outputs_prefix, "FakeTI.Domain")
        dbot = result.indicators[0]
        self.assertEqual(dbot.score, 3)
        self.assertEqual(dbot.indicator_type, "domain")

    def test_clean_domain(self):
        client = self._make_client({
            "domain": "google.com", "score": 5,
            "registrar": "MarkMonitor", "creation_date": "1997-09-15",
            "is_malicious": False,
        })
        result = get_domain_reputation_command(client, {"domain": "google.com"})
        dbot = result.indicators[0]
        self.assertEqual(dbot.score, 1)

    def test_missing_domain_raises(self):
        client = self._make_client({})
        with self.assertRaises(SystemExit):
            get_domain_reputation_command(client, {})


class TestSearchIOCCommand(unittest.TestCase):

    def _make_client(self, response):
        client = Client.__new__(Client)
        client.base_url = "http://fake"
        client.api_key = "key"
        client._request = MagicMock(return_value=response)
        return client

    def test_search_returns_results(self):
        mock_response = {
            "query": "evil",
            "type_filter": None,
            "total_results": 1,
            "results": [{"type": "domain", "value": "evil-phishing.xyz", "score": 97}],
        }
        client = self._make_client(mock_response)
        result = search_ioc_command(client, {"query": "evil"})
        self.assertEqual(result.outputs_prefix, "FakeTI.SearchIOC")
        self.assertEqual(len(result.outputs["results"]), 1)

    def test_search_passes_type_filter(self):
        mock_response = {"query": "test", "type_filter": "ip", "total_results": 0, "results": []}
        client = self._make_client(mock_response)
        result = search_ioc_command(client, {"query": "test", "type": "ip", "limit": 5})
        client._request.assert_called_once()

    def test_missing_query_raises(self):
        client = self._make_client({})
        with self.assertRaises(SystemExit):
            search_ioc_command(client, {})


class TestTestModule(unittest.TestCase):

    def test_success_returns_ok(self):
        client = Client.__new__(Client)
        client._request = MagicMock(return_value={"status": "ok", "version": "1.0.0"})
        result = run_test_module(client)
        self.assertEqual(result, "ok")

    def test_failure_exits(self):
        client = Client.__new__(Client)
        client._request = MagicMock(return_value={"status": "error"})
        with self.assertRaises(SystemExit):
            run_test_module(client)


class TestClientRetry(unittest.TestCase):
    """Validate retry + exponential backoff logic."""

    @patch("ti_integration.time.sleep")
    def test_retries_on_server_error(self, mock_sleep):
        """Client should retry on 5xx and succeed on 3rd attempt."""
        client = Client.__new__(Client)
        client.base_url = "http://fake"
        client.api_key = "key"
        client.session = MagicMock()

        # First two calls: 500, third: 200
        error_resp = MagicMock()
        error_resp.ok = False
        error_resp.status_code = 500
        error_resp.text = "Internal Server Error"

        success_resp = MagicMock()
        success_resp.ok = True
        success_resp.status_code = 200
        success_resp.json.return_value = {"status": "ok"}

        client.session.request.side_effect = [error_resp, error_resp, success_resp]

        result = client._request("GET", "/health")
        self.assertEqual(result, {"status": "ok"})
        self.assertEqual(client.session.request.call_count, 3)
        # Verify backoff: sleep(1), sleep(2)
        mock_sleep.assert_any_call(1)
        mock_sleep.assert_any_call(2)

    @patch("ti_integration.time.sleep")
    def test_no_retry_on_client_error(self, mock_sleep):
        """4xx errors should not be retried."""
        client = Client.__new__(Client)
        client.base_url = "http://fake"
        client.api_key = "key"
        client.session = MagicMock()

        error_resp = MagicMock()
        error_resp.ok = False
        error_resp.status_code = 403
        error_resp.text = "Forbidden"

        client.session.request.return_value = error_resp

        with self.assertRaises(Exception):
            client._request("GET", "/api/v1/ip/1.2.3.4/reputation")

        self.assertEqual(client.session.request.call_count, 1)
        mock_sleep.assert_not_called()

    @patch("ti_integration.time.sleep")
    def test_retries_on_connection_error(self, mock_sleep):
        """Connection errors should be retried."""
        import requests as req_lib
        client = Client.__new__(Client)
        client.base_url = "http://fake"
        client.api_key = "key"
        client.session = MagicMock()

        success_resp = MagicMock()
        success_resp.ok = True
        success_resp.status_code = 200
        success_resp.json.return_value = {"status": "ok"}

        client.session.request.side_effect = [
            req_lib.exceptions.ConnectionError("refused"),
            success_resp,
        ]

        result = client._request("GET", "/health")
        self.assertEqual(result, {"status": "ok"})
        self.assertEqual(client.session.request.call_count, 2)

    @patch("ti_integration.time.sleep")
    def test_raises_after_max_retries(self, mock_sleep):
        """Should raise after exhausting all retries."""
        client = Client.__new__(Client)
        client.base_url = "http://fake"
        client.api_key = "key"
        client.session = MagicMock()

        error_resp = MagicMock()
        error_resp.ok = False
        error_resp.status_code = 503
        error_resp.text = "Service Unavailable"

        client.session.request.return_value = error_resp

        with self.assertRaises(Exception):
            client._request("GET", "/health")

        # Initial attempt + 3 retries = 4 total calls
        self.assertEqual(client.session.request.call_count, 4)


if __name__ == "__main__":
    unittest.main()
