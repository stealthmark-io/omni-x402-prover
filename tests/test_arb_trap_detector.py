"""
Comprehensive Unit and Integration Tests for Arb Trap:
Polymarket <-> Kalshi Z3 Double-Loss Resolution Divergence Detector.

Tests:
1. Timezone cutoff trap (23:59 ET vs 23:59 UTC -> SAT double loss)
2. Boundary > vs >= trap (BTC > 100000 vs BTC at least 100000 -> SAT at 100000)
3. Intraday wick vs daily close trap (SAT)
4. Official publication lag vs preliminary announcement trap (SAT)
5. Identical aligned markets (UNSAT safe arb)
6. 1-Input Live Market Fetchers with strict domain allowlist + injectable http_get
7. Rule Spec Normalizer (NLP regex extraction + explicit overrides)
8. Loopback HTTP GET /x402/arb-trap/preview (Free lead magnet with redacted witness)
9. Loopback Paid POST /x402/verify-polymarket-basket with rule divergence
10. Preview hardening (offline): generic 500s, 503 + Retry-After when saturated, TTL cache by normalized params
"""

from __future__ import annotations

import json
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, Optional, Tuple
from unittest.mock import patch

from omni_x402_prover.arb_trap_detector import (
    MarketRuleSpec,
    extract_rule_spec,
    fetch_kalshi_market,
    fetch_polymarket_market,
    verify_arb_resolution_divergence,
)
from omni_x402_prover.http_server import (
    PREVIEW_CACHE_TTL_SECONDS,
    PREVIEW_RETRY_AFTER_SECONDS,
    PreviewGate,
    create_http_server,
)
from omni_x402_prover.prover_service import ProverService
from omni_x402_prover.x402_protocol import (
    DeterministicMockFacilitator,
    ReplayNonceStore,
    X402Config,
)
from tests.test_omni_x402_prover import SAMPLE_PAY_TO, make_test_payment_header


def _http_req(
    url: str,
    method: str = "GET",
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
    req_headers = {"User-Agent": "test-runner/1.0"}
    if headers:
        req_headers.update(headers)

    body_bytes = None
    if data is not None:
        body_bytes = json.dumps(data).encode("utf-8")
        req_headers["Content-Type"] = "application/json"
        req_headers["Content-Length"] = str(len(body_bytes))

    req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            status = resp.status
            resp_body = resp.read().decode("utf-8")
            resp_headers = {k: v for k, v in resp.headers.items()}
            parsed_json = json.loads(resp_body) if resp_body else {}
            return status, parsed_json, resp_headers
    except urllib.error.HTTPError as err:
        err_body = err.read().decode("utf-8")
        resp_headers = {k: v for k, v in err.headers.items()}
        try:
            parsed_json = json.loads(err_body)
        except Exception:
            parsed_json = {"raw": err_body}
        return err.code, parsed_json, resp_headers


class TestArbTrapDetectorCore(unittest.TestCase):
    """Z3 Formal SMT unit tests covering the core resolution divergence dimensions."""

    def test_01_timezone_cutoff_trap_sat(self) -> None:
        """
        Polymarket resolves at 23:59:59 UTC (1735689599).
        Kalshi resolves at 23:59:59 ET (1735707599, UTC-5 => 5 hours later).
        Event occurring in the 5-hour window resolves NO on Polymarket and YES on Kalshi.
        Direction: BUY_PM_YES_AND_KALSHI_NO suffers 100% wipeout ($0.00 on both legs).
        """
        pm_spec = MarketRuleSpec(
            platform="polymarket",
            title="Will Event X occur by Dec 31, 2024?",
            rules_text="Resolves according to UTC timestamp: 2024-12-31 23:59:59 UTC deadline.",
            cutoff_epoch_utc=1735689599,  # 2024-12-31 23:59:59 UTC
            requires_official_publication=False,
            includes_intraday_wick=False,
            strict_inequality=False,
            numeric_threshold=None,
            government_shutdown_postpones=False,
            yes_ask=0.48,
            no_ask=0.52,
        )
        kalshi_spec = MarketRuleSpec(
            platform="kalshi",
            title="Will Event X occur by Dec 31, 2024?",
            rules_text="Resolves according to Eastern Time: 2024-12-31 11:59:59 PM ET.",
            cutoff_epoch_utc=1735707599,  # 2024-12-31 23:59:59 EST (18,000s later)
            requires_official_publication=False,
            includes_intraday_wick=False,
            strict_inequality=False,
            numeric_threshold=None,
            government_shutdown_postpones=False,
            yes_ask=0.52,
            no_ask=0.48,
        )

        res = verify_arb_resolution_divergence(
            pm_spec=pm_spec,
            kalshi_spec=kalshi_spec,
            pm_yes_ask=0.48,
            kalshi_no_ask=0.48,
            fee_bps=100,
        )

        self.assertTrue(res["trap_detected"])
        self.assertEqual(res["status"], "VULNERABLE_DOUBLE_LOSS_TRAP")
        self.assertEqual(res["risk_grade"], "CRITICAL_WIPEOUT_RISK")
        self.assertEqual(res["max_wipeout_pct"], 100.0)
        self.assertIn("cutoff_epoch_utc", res["divergent_dimensions"])

        witness = res["witness"]
        self.assertIsNotNone(witness)
        self.assertEqual(witness["direction"], "BUY_PM_YES_AND_KALSHI_NO")
        # Counterexample timestamp must lie strictly in the divergence gap
        self.assertGreater(witness["event_occurred_epoch"], pm_spec.cutoff_epoch_utc)
        self.assertLessEqual(witness["event_occurred_epoch"], kalshi_spec.cutoff_epoch_utc)
        self.assertIn("EST", witness["event_occurred_et"])
        self.assertEqual(witness["total_arb_payout"], "$0.00")

        # Viral alert contains critical hashtags and warnings
        self.assertIn("🚨 ARB TRAP DETECTED", res["viral_x_alert"])
        self.assertIn("100% DOUBLE-LOSS WIPEOUT RISK", res["viral_x_alert"])
        self.assertIn("#Polymarket", res["viral_x_alert"])

    def test_02_boundary_strict_inequality_trap_sat(self) -> None:
        """
        Polymarket: 'Will BTC exceed $100,000?' (strict > 100000).
        Kalshi: 'Will BTC be at least $100,000?' (>= 100000).
        At exact price == 100,000, PM resolves NO, Kalshi resolves YES.
        Direction: BUY_PM_YES_AND_KALSHI_NO pays $0.00 on both legs.
        """
        pm_spec = extract_rule_spec(
            title="Will BTC exceed $100,000 in 2025?",
            rules_text="Resolves YES if BTC price is strictly greater than 100,000.",
            platform="polymarket",
            overrides={"strict_inequality": True, "numeric_threshold": 100000, "cutoff_epoch_utc": 1735689600},
        )
        kalshi_spec = extract_rule_spec(
            title="Will BTC be at least $100,000 in 2025?",
            rules_text="Resolves YES if BTC price is at least 100,000.",
            platform="kalshi",
            overrides={"strict_inequality": False, "numeric_threshold": 100000, "cutoff_epoch_utc": 1735689600},
        )

        res = verify_arb_resolution_divergence(
            pm_spec=pm_spec,
            kalshi_spec=kalshi_spec,
            pm_yes_ask=0.47,
            kalshi_no_ask=0.48,
        )

        self.assertTrue(res["trap_detected"])
        self.assertEqual(res["status"], "VULNERABLE_DOUBLE_LOSS_TRAP")
        self.assertIn("strict_inequality", res["divergent_dimensions"])

        witness = res["witness"]
        self.assertIsNotNone(witness)
        self.assertEqual(witness["intraday_peak"], 100000)
        self.assertEqual(witness["closing_val"], 100000)
        self.assertEqual(witness["direction"], "BUY_PM_YES_AND_KALSHI_NO")
        self.assertIn("Boundary collision at exact value 100000", witness["explanation"])

    def test_03_intraday_wick_vs_daily_close_trap_sat(self) -> None:
        """
        Polymarket: 'BTC hits $100,000 at any point' (includes intraday wick).
        Kalshi: 'BTC daily close at 4:00 PM is $100,000' (close only).
        Scenario: BTC peaks at $101,000 intraday, but closes at $99,000.
        Polymarket resolves YES. Kalshi resolves NO.
        Direction: BUY_PM_NO_AND_KALSHI_YES suffers 100% wipeout!
        """
        pm_spec = extract_rule_spec(
            title="Will Bitcoin hit $100,000?",
            rules_text="Resolves YES if the price touches or reaches $100,000 at any point during trading hours.",
            platform="polymarket",
            overrides={"includes_intraday_wick": True, "numeric_threshold": 100000, "cutoff_epoch_utc": 1735689600},
        )
        kalshi_spec = extract_rule_spec(
            title="Will Bitcoin close at $100,000?",
            rules_text="Resolves based on the 4:00 PM daily close settlement index.",
            platform="kalshi",
            overrides={"includes_intraday_wick": False, "numeric_threshold": 100000, "cutoff_epoch_utc": 1735689600},
        )

        res = verify_arb_resolution_divergence(
            pm_spec=pm_spec,
            kalshi_spec=kalshi_spec,
            pm_no_ask=0.45,
            kalshi_yes_ask=0.45,
        )

        self.assertTrue(res["trap_detected"])
        self.assertIn("includes_intraday_wick", res["divergent_dimensions"])

        witness = res["witness"]
        self.assertIsNotNone(witness)
        self.assertEqual(witness["direction"], "BUY_PM_NO_AND_KALSHI_YES")
        self.assertGreaterEqual(witness["intraday_peak"], 100000)
        self.assertLess(witness["closing_val"], 100000)
        self.assertIn("satisfies wick rule", witness["explanation"])

    def test_04_official_pub_lag_vs_prelim_announcement_trap_sat(self) -> None:
        """
        Polymarket: Resolves on preliminary media projection / AP consensus.
        Kalshi: Requires certified Federal Register / BLS release before deadline.
        Scenario: Preliminary news drops at 16:30 (before 17:00 deadline), but
        official publication is delayed until 18:00.
        Polymarket resolves YES. Kalshi resolves NO.
        Direction: BUY_PM_NO_AND_KALSHI_YES suffers 100% wipeout!
        """
        cutoff = 1735689600
        pm_spec = extract_rule_spec(
            title="CPI Inflation below 3.0%",
            rules_text="Resolves upon preliminary announcement and media consensus reports.",
            platform="polymarket",
            overrides={"requires_official_publication": False, "cutoff_epoch_utc": cutoff},
        )
        kalshi_spec = extract_rule_spec(
            title="CPI Inflation below 3.0%",
            rules_text="Resolves strictly based on the official BLS release and certified results.",
            platform="kalshi",
            overrides={"requires_official_publication": True, "cutoff_epoch_utc": cutoff},
        )

        res = verify_arb_resolution_divergence(
            pm_spec=pm_spec,
            kalshi_spec=kalshi_spec,
            pm_no_ask=0.48,
            kalshi_yes_ask=0.48,
        )

        self.assertTrue(res["trap_detected"])
        self.assertIn("requires_official_publication", res["divergent_dimensions"])

        witness = res["witness"]
        self.assertIsNotNone(witness)
        self.assertEqual(witness["direction"], "BUY_PM_NO_AND_KALSHI_YES")
        self.assertLessEqual(witness["event_occurred_epoch"], cutoff)
        self.assertGreater(witness["official_pub_epoch"], cutoff)
        self.assertIn("official government publication lagged", witness["explanation"])

    def test_05_identical_aligned_markets_unsat(self) -> None:
        """
        Markets with identical resolution cutoffs, identical publication criteria,
        and identical threshold rules guarantee no double loss in modeled dimensions.
        """
        cutoff = 1735689600
        pm_spec = MarketRuleSpec(
            platform="polymarket",
            title="Identical Market Test",
            rules_text="Standard terms",
            cutoff_epoch_utc=cutoff,
            requires_official_publication=True,
            includes_intraday_wick=False,
            strict_inequality=False,
            numeric_threshold=100000,
            government_shutdown_postpones=False,
        )
        kalshi_spec = MarketRuleSpec(
            platform="kalshi",
            title="Identical Market Test",
            rules_text="Standard terms",
            cutoff_epoch_utc=cutoff,
            requires_official_publication=True,
            includes_intraday_wick=False,
            strict_inequality=False,
            numeric_threshold=100000,
            government_shutdown_postpones=False,
        )

        res = verify_arb_resolution_divergence(
            pm_spec=pm_spec,
            kalshi_spec=kalshi_spec,
            pm_yes_ask=0.45,
            kalshi_no_ask=0.45,
            fee_bps=50,
        )

        self.assertFalse(res["trap_detected"])
        self.assertEqual(res["status"], "SAFE_UNSAT_NO_DOUBLE_LOSS")
        self.assertEqual(res["risk_grade"], "LOW_RISK")
        self.assertEqual(res["mathematical_guarantee"], "UNSAT_NO_DOUBLE_LOSS_IN_MODELED_DIMENSIONS")
        self.assertIsNone(res["witness"])
        self.assertIsNone(res["viral_x_alert"])
        self.assertEqual(res["divergent_dimensions_count"], 0)
        self.assertGreater(res["net_spread_bps"], 0)


class TestArbTrapLiveFetchersAndNLP(unittest.TestCase):
    """Unit tests for market data ingestion and rule spec normalization."""

    def test_06_live_fetcher_with_injected_offline_client(self) -> None:
        def mock_pm_client(url: str) -> str:
            self.assertIn("gamma-api.polymarket.com", url)
            return json.dumps([
                {
                    "question": "Will BTC touch $100,000?",
                    "description": "Resolves YES if BTC hits $100,000 before Dec 31 23:59 UTC.",
                    "endDate": "2024-12-31T23:59:59Z",
                    "outcomePrices": ["0.48", "0.52"],
                }
            ])

        pm_data = fetch_polymarket_market("btc-100k", http_get=mock_pm_client)
        self.assertEqual(pm_data["platform"], "polymarket")
        self.assertEqual(pm_data["title"], "Will BTC touch $100,000?")
        self.assertEqual(pm_data["yes_ask"], 0.48)
        self.assertEqual(pm_data["no_ask"], 0.52)

        def mock_kalshi_client(url: str) -> str:
            self.assertIn("api.elections.kalshi.com", url)
            return json.dumps({
                "market": {
                    "ticker": "KXBTCD-100000",
                    "title": "Will BTC reach $100,000?",
                    "rules_primary": "Official BLS settlement price.",
                    "rules_secondary": "Deadline is 11:59 PM ET.",
                    "close_time": "2024-12-31T23:59:59-05:00",
                    "yes_ask": 49,
                    "no_ask": 51,
                }
            })

        kalshi_data = fetch_kalshi_market("KXBTCD-100000", http_get=mock_kalshi_client)
        self.assertEqual(kalshi_data["platform"], "kalshi")
        self.assertEqual(kalshi_data["title"], "Will BTC reach $100,000?")
        self.assertEqual(kalshi_data["yes_ask"], 0.49)
        self.assertEqual(kalshi_data["no_ask"], 0.51)

    def test_07_strict_domain_allowlist_enforcement(self) -> None:
        with self.assertRaises(ValueError):
            fetch_polymarket_market("https://malicious-domain.com/markets", http_get=lambda url: "{}")
        with self.assertRaises(ValueError):
            fetch_kalshi_market("https://untrusted-api.org/markets", http_get=lambda url: "{}")

    def test_08_extract_rule_spec_heuristics(self) -> None:
        title = "Will Fed cut interest rates > 50 bps?"
        rules = "Resolves YES based on Federal Register official certification by 2025-06-30 at 23:59 ET. Government shutdown delay will extend."
        spec = extract_rule_spec(title, rules, platform="kalshi")

        self.assertTrue(spec.requires_official_publication)
        self.assertTrue(spec.strict_inequality)
        self.assertTrue(spec.government_shutdown_postpones)
        self.assertEqual(spec.timezone_name, "ET")


class TestArbTrapHTTPEndpoints(unittest.TestCase):
    """Integration loopback tests verifying the Free lead magnet route and the Paid endpoint."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = X402Config(pay_to_address=SAMPLE_PAY_TO)
        cls.prover_service = ProverService(cls.config)
        cls.nonce_store = ReplayNonceStore(max_entries=1000)
        cls.facilitator = DeterministicMockFacilitator(cls.config)

        cls.server = create_http_server(
            host="127.0.0.1",
            port=0,
            config=cls.config,
            prover_service=cls.prover_service,
            nonce_store=cls.nonce_store,
            facilitator=cls.facilitator,
        )
        _, cls.port = cls.server.server_address
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=1.0)

    def test_09_free_get_preview_route_lead_magnet(self) -> None:
        """
        GET /x402/arb-trap/preview is a FREE lead-magnet route (returns HTTP 200 without payment).
        Redacts the exact Z3 witness and provides a clear conversion funnel to the paid endpoint.
        """
        # Test divergent timezone parameters
        pm_rules = "Resolves at 2024-12-31 23:59:59 UTC"
        kalshi_rules = "Resolves at 2024-12-31 23:59:59 ET"
        url = f"{self.base_url}/x402/arb-trap/preview?pm_rules={urllib.parse.quote(pm_rules)}&kalshi_rules={urllib.parse.quote(kalshi_rules)}"

        status, body, headers = _http_req(url, method="GET")
        self.assertEqual(status, 200)
        self.assertTrue(body.get("trap_detected"))
        self.assertEqual(body.get("risk_grade"), "CRITICAL_WIPEOUT_RISK")
        self.assertEqual(body.get("unlock_full_witness_endpoint"), "/x402/verify-polymarket-basket")

        # Confirm redaction
        witness_redacted = body.get("witness_redacted", {})
        self.assertIn("[REDACTED", witness_redacted.get("event_occurred_utc", ""))
        self.assertIn("[REDACTED", witness_redacted.get("event_occurred_et", ""))

        # Test missing params
        bad_url = f"{self.base_url}/x402/arb-trap/preview"
        bad_status, bad_body, _ = _http_req(bad_url, method="GET")
        self.assertEqual(bad_status, 400)
        self.assertIn("error", bad_body)

    def test_10_paid_post_verify_polymarket_basket_with_arb_trap(self) -> None:
        """
        Paid POST /x402/verify-polymarket-basket with rule divergence inputs.
        With valid payment, returns HTTP 200 with the FULL unredacted witness and viral alert.
        """
        header_val = make_test_payment_header(
            self.config,
            amount=self.config.price_polymarket_atomic,
            nonce="0x" + uuid.uuid4().hex,
        )

        payload = {
            "outcome_ask_prices": [0.48, 0.48],
            "fee_bps": 100,
            "polymarket_rules": "Resolves strictly greater than 100000 on close.",
            "kalshi_rules": "Resolves at least 100000 on close.",
            "polymarket_overrides": {"strict_inequality": True, "numeric_threshold": 100000},
            "kalshi_overrides": {"strict_inequality": False, "numeric_threshold": 100000},
        }

        url = f"{self.base_url}/x402/verify-polymarket-basket"
        status, body, resp_headers = _http_req(
            url,
            method="POST",
            data=payload,
            headers={"X-PAYMENT": header_val},
        )

        self.assertEqual(status, 200)
        self.assertTrue(body.get("arb_trap_detected"))
        self.assertEqual(body.get("risk_grade"), "CRITICAL_WIPEOUT_RISK")

        # Full unredacted witness must be present
        witness = body.get("arb_trap_witness")
        self.assertIsNotNone(witness)
        self.assertEqual(witness["intraday_peak"], 100000)
        self.assertNotIn("[REDACTED", witness.get("explanation", ""))

        # Viral X alert ready for social amplification
        viral_alert = body.get("viral_x_alert")
        self.assertIsNotNone(viral_alert)
        self.assertIn("🚨 ARB TRAP DETECTED", viral_alert)
        self.assertIn("Formal Proof: z3-solver SAT", viral_alert)

        # Settlement receipt confirmation
        self.assertIn("settlementReceipt", body)
        self.assertTrue(body["settlementReceipt"].get("success"))


class TestPreviewGate(unittest.TestCase):
    """Unit tests for the concurrency cap and TTL/LRU cache that guard the free previews."""

    def test_11_slots_are_non_blocking_and_reusable(self) -> None:
        gate = PreviewGate(max_concurrent=2)
        self.assertTrue(gate.try_acquire())
        self.assertTrue(gate.try_acquire())
        self.assertFalse(gate.try_acquire())
        gate.release()
        self.assertTrue(gate.try_acquire())

    def test_12_cache_expires_after_ttl_and_evicts_least_recently_used(self) -> None:
        now = [1000.0]
        gate = PreviewGate(max_concurrent=1, cache_ttl_seconds=60.0, cache_max_entries=2, clock=lambda: now[0])
        gate.put("a", {"v": 1})
        gate.put("b", {"v": 2})
        self.assertEqual(gate.get("a"), {"v": 1})
        gate.put("c", {"v": 3})
        self.assertIsNone(gate.get("b"))
        self.assertEqual(gate.get("a"), {"v": 1})
        self.assertEqual(gate.get("c"), {"v": 3})

        now[0] += 59.9
        self.assertEqual(gate.get("a"), {"v": 1})
        now[0] += 0.1
        self.assertIsNone(gate.get("a"))
        self.assertIsNone(gate.get("c"))


class TestArbTrapPreviewHardening(unittest.TestCase):
    """Offline loopback tests: generic preview errors, concurrency cap with Retry-After, and the short cache."""

    PM_RULES = "Resolves at 2024-12-31 23:59:59 UTC"
    KALSHI_RULES = "Resolves at 2024-12-31 23:59:59 ET"
    SAFE_RESULT = {"trap_detected": False, "net_spread_bps": 0}

    @classmethod
    def setUpClass(cls) -> None:
        config = X402Config(pay_to_address=SAMPLE_PAY_TO)
        cls.server = create_http_server(
            host="127.0.0.1",
            port=0,
            config=config,
            prover_service=ProverService(config),
            nonce_store=ReplayNonceStore(max_entries=1000),
            facilitator=DeterministicMockFacilitator(config),
        )
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=1.0)

    def setUp(self) -> None:
        self.now = [1000.0]
        self.gate = PreviewGate(max_concurrent=1, clock=lambda: self.now[0])
        self.server.RequestHandlerClass.arb_trap_preview_gate = self.gate

    def _preview(self, **params: str) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        return _http_req(f"{self.base_url}/x402/arb-trap/preview?{urllib.parse.urlencode(params)}")

    def _assert_slot_free(self) -> None:
        self.assertTrue(self.gate.try_acquire())
        self.gate.release()

    def test_13_preview_error_is_generic_logged_and_not_cached(self) -> None:
        secret = "internal detail /opt/omni/private-path"
        with patch(
            "omni_x402_prover.http_server.verify_arb_resolution_divergence",
            side_effect=[RuntimeError(secret), self.SAFE_RESULT],
        ):
            with self.assertLogs("omni_x402_prover.http", level="ERROR") as logs:
                status, body, _ = self._preview(pm_rules=self.PM_RULES, kalshi_rules=self.KALSHI_RULES)
            self.assertEqual(status, 500)
            self.assertEqual(body, {"error": "Failed to compute arb trap preview"})
            self.assertEqual(str(logs.records[0].exc_info[1]), secret)
            self._assert_slot_free()

            status, body, _ = self._preview(pm_rules=self.PM_RULES, kalshi_rules=self.KALSHI_RULES)
            self.assertEqual(status, 200)
            self.assertFalse(body["trap_detected"])

    def test_14_saturated_preview_returns_503_with_retry_after(self) -> None:
        with patch(
            "omni_x402_prover.http_server.verify_arb_resolution_divergence", return_value=self.SAFE_RESULT
        ) as verify:
            self.assertTrue(self.gate.try_acquire())
            try:
                status, body, headers = self._preview(pm_rules=self.PM_RULES, kalshi_rules=self.KALSHI_RULES)
            finally:
                self.gate.release()
            self.assertEqual(status, 503)
            self.assertEqual(headers.get("Retry-After"), str(PREVIEW_RETRY_AFTER_SECONDS))
            self.assertIn("error", body)
            verify.assert_not_called()

            status, _, _ = self._preview(pm_rules=self.PM_RULES, kalshi_rules=self.KALSHI_RULES)
            self.assertEqual(status, 200)
            self._assert_slot_free()

    def test_15_cache_serves_repeats_by_normalized_params_until_ttl(self) -> None:
        market = {"title": "Will BTC close above $100,000?", "rules_text": self.KALSHI_RULES, "end_date_iso": None}
        with patch("omni_x402_prover.http_server.fetch_polymarket_market", return_value=market) as fetch_pm, patch(
            "omni_x402_prover.http_server.fetch_kalshi_market", return_value=market
        ) as fetch_kalshi, patch(
            "omni_x402_prover.http_server.verify_arb_resolution_divergence", return_value=self.SAFE_RESULT
        ) as verify:
            first = self._preview(pm="btc-100k", kalshi="KXBTCD-100000")
            repeat = self._preview(pm="btc-100k", kalshi="KXBTCD-100000", pm_title="unused without pm_rules")
            self.assertEqual(first[0], 200)
            self.assertEqual(repeat[:2], first[:2])
            self.assertEqual((fetch_pm.call_count, fetch_kalshi.call_count, verify.call_count), (1, 1, 1))

            self._preview(pm="btc-100k", kalshi="KXBTCD-200000")
            self.assertEqual(verify.call_count, 2)

            self._preview(pm_rules=self.PM_RULES, kalshi_rules=self.KALSHI_RULES, pm_title="Title A")
            self._preview(pm_rules=self.PM_RULES, kalshi_rules=self.KALSHI_RULES, pm_title="Title B")
            self.assertEqual(verify.call_count, 4)

            self.now[0] += PREVIEW_CACHE_TTL_SECONDS
            self._preview(pm="btc-100k", kalshi="KXBTCD-100000")
            self.assertEqual((fetch_pm.call_count, verify.call_count), (3, 5))


if __name__ == "__main__":
    unittest.main()
