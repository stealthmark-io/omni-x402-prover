"""
Trust Grade SSRF regressions: the loopback bypass comes only from server config,
and rejected targets never echo resolver or exception detail to the client.

Offline: every fetch target is a canary HTTP server on 127.0.0.1 that records the
paths it receives, so a request that slips past the guard shows up as a hit.
"""

from __future__ import annotations

import json
import os
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, List, Tuple
from unittest import mock

from omni_x402_prover.http_server import create_http_server
from omni_x402_prover.prover_service import ProverService
from omni_x402_prover.x402_protocol import DeterministicMockFacilitator, ReplayNonceStore, X402Config
from omni_x402_prover.x402_trust_grade import INVALID_TARGET_MESSAGE
from tests.test_omni_x402_prover import SAMPLE_PAY_TO, http_json_request, make_test_payment_header

LOOPBACK_ENV = "X402_ALLOW_LOOPBACK_FOR_TESTS"
PREVIEW_ROUTE = "/x402/trust-grade/preview"
BADGE_ROUTE = "/x402/trust-grade/badge.svg"
DOSSIER_ROUTE = "/x402/verify-sar-ed25519-dossier"


class _Canary:
    """Loopback HTTP server that answers 404 and records every requested path."""

    def __init__(self) -> None:
        hits: List[str] = []
        self.hits = hits

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                hits.append(self.path)
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/x402/resource"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)


class TrustGradeSSRFTests(unittest.TestCase):
    def setUp(self) -> None:
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(LOOPBACK_ENV, None)

        self.canary = _Canary()
        self.addCleanup(self.canary.close)

        self.config = X402Config(pay_to_address=SAMPLE_PAY_TO)
        self.nonce_store = ReplayNonceStore(max_entries=100)
        self.facilitator = mock.Mock(wraps=DeterministicMockFacilitator(self.config))
        self.prover_service = ProverService(self.config)
        self.server = create_http_server(
            host="127.0.0.1",
            port=0,
            config=self.config,
            prover_service=self.prover_service,
            nonce_store=self.nonce_store,
            facilitator=self.facilitator,
        )
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2.0)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def _get(self, route: str, **query: str) -> Tuple[int, str]:
        url = f"{self.base_url}{route}?{urllib.parse.urlencode(query)}"
        try:
            with urllib.request.urlopen(url, timeout=10.0) as resp:
                return resp.status, resp.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode("utf-8")

    def _post_paid_dossier(self, payload: dict) -> Tuple[int, Any, dict]:
        header = make_test_payment_header(self.config, amount=self.config.price_sar_ed25519_atomic)
        return http_json_request(self.base_url, "POST", DOSSIER_ROUTE, data=payload, headers={"X-PAYMENT": header})

    def test_preview_ignores_allow_loopback_query(self) -> None:
        for flag in ("1", "true"):
            with self.subTest(allow_loopback=flag):
                status, body = self._get(PREVIEW_ROUTE, url=self.canary.url, allow_loopback=flag)
                self.assertEqual(status, 400, body)
                self.assertEqual(json.loads(body), {"error": INVALID_TARGET_MESSAGE})
        self.assertEqual(self.canary.hits, [])

    def test_badge_ignores_allow_loopback_query(self) -> None:
        status, body = self._get(BADGE_ROUTE, url=self.canary.url, allow_loopback="1")
        self.assertEqual(status, 400, body)
        self.assertEqual(json.loads(body), {"error": INVALID_TARGET_MESSAGE})

    def test_paid_dossier_ignores_allow_loopback_payload_and_stays_unpaid(self) -> None:
        status, body, _ = self._post_paid_dossier({"target_url": self.canary.url, "allow_loopback_for_tests": True})
        self.assertEqual(status, 400, body)
        self.assertEqual(body, {"error": INVALID_TARGET_MESSAGE})
        self.assertEqual(self.canary.hits, [])
        self.assertEqual(self.nonce_store.size(), 0)
        self.facilitator.settle.assert_not_called()

    def test_service_ignores_allow_loopback_payload(self) -> None:
        # Same entry point the MCP tool x402_verify_sar_ed25519_dossier calls.
        for key in ("target_url", "seller_url"):
            with self.subTest(key=key):
                with self.assertRaises(ValueError) as ctx:
                    self.prover_service.verify_sar_ed25519_dossier(
                        {key: self.canary.url, "allow_loopback_for_tests": True}
                    )
                self.assertEqual(str(ctx.exception), INVALID_TARGET_MESSAGE)
        self.assertEqual(self.canary.hits, [])

    def test_server_config_still_enables_loopback(self) -> None:
        # Positive control: the canary does record fetches, and the env var is still honored.
        os.environ[LOOPBACK_ENV] = "1"
        status, body = self._get(PREVIEW_ROUTE, url=self.canary.url)
        self.assertEqual(status, 200, body)
        self.assertIn("/.well-known/x402-bazaar.json", self.canary.hits)

        self.canary.hits.clear()
        result = self.prover_service.verify_sar_ed25519_dossier({"target_url": self.canary.url})
        self.assertEqual(result["check_type"], "x402_trust_grade_dossier")
        self.assertIn("/.well-known/x402-bazaar.json", self.canary.hits)

    def test_rejected_target_does_not_echo_resolution_detail(self) -> None:
        with self.assertLogs("omni_x402_prover.http", "INFO") as logs:
            status, body = self._get(PREVIEW_ROUTE, url="https://localhost/")
        self.assertEqual(status, 400, body)
        self.assertEqual(json.loads(body), {"error": INVALID_TARGET_MESSAGE})
        self.assertTrue(any("SSRF blocked" in line for line in logs.output), logs.output)

        status, body, _ = self._post_paid_dossier({"target_url": "https://localhost/"})
        self.assertEqual(status, 400, body)
        self.assertEqual(body, {"error": INVALID_TARGET_MESSAGE})

    def test_preview_internal_error_does_not_echo_exception(self) -> None:
        secret = "boom in /opt/omni-x402-prover/internal.py"
        with mock.patch(
            "omni_x402_prover.http_server.score_x402_seller", side_effect=RuntimeError(secret)
        ), self.assertLogs("omni_x402_prover.http", "ERROR") as logs:
            status, body = self._get(PREVIEW_ROUTE, url="https://example.com/")
        self.assertEqual(status, 500, body)
        self.assertEqual(json.loads(body), {"error": "Failed to compute trust grade preview"})
        self.assertTrue(any(secret in line for line in logs.output))

    def test_unknown_demo_keeps_its_message(self) -> None:
        status, body = self._get(PREVIEW_ROUTE, demo="nope")
        self.assertEqual(status, 400, body)
        self.assertIn("Unknown demo profile", json.loads(body)["error"])


if __name__ == "__main__":
    unittest.main()
