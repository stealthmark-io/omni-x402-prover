"""
Test suite for Omni x402 Prover: Protocol, Facilitator, HTTP Server, and MCP Server.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
from pathlib import Path

# Ensure repo root is on sys.path for unittest discover
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import socket
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from unittest import mock
from typing import Any, Dict, Optional, Tuple
from unittest.mock import MagicMock, patch

from omni_x402_prover.http_server import create_http_server
from omni_x402_prover.mcp_server import get_mcp_tools, get_tools_registry, handle_jsonrpc_message
from omni_x402_prover.prover_service import ProverCapacityError, ProverService, _create_fallback_verifiers
import omni_x402_prover.prover_service as prover_service_module
from omni_x402_prover.x402_protocol import (
    COINBASE_CDP_FACILITATOR_URL,
    DEFAULT_BASE_PAY_TO,
    DEFAULT_FACILITATOR_URL,
    DeterministicMockFacilitator,
    ReplayNonceStore,
    RemoteHTTPFacilitatorClient,
    X402Config,
    build_payment_required_response,
    normalize_network_name,
    parse_raw_payment_header,
    verify_and_settle_payment,
    _load_cdp_private_key,
)

SAMPLE_PAY_TO = "0x0000000000000000000000000000000000000000"
SAMPLE_PAYER = "0x1111111111111111111111111111111111111111"


def make_test_payment_header(
    config: X402Config,
    amount: int = 20000,
    to_address: Optional[str] = None,
    valid_before_offset: int = 3600,
    nonce: Optional[str] = None,
    payer: str = SAMPLE_PAYER,
    signature: str = "0x" + "a" * 130,
    as_raw_json: bool = False,
) -> str:
    """Helper to build a valid EIP-3009 authorization payload for x402 tests."""
    payload = {
        "x402Version": 1,
        "scheme": "exact",
        "network": config.network,
        "payload": {
            "signature": signature,
            "authorization": {
                "from": payer,
                "to": to_address or config.pay_to_address,
                "value": str(amount),
                "validAfter": 0,
                "validBefore": int(time.time()) + valid_before_offset,
                "nonce": nonce or ("0x" + uuid.uuid4().hex),
            },
        },
    }
    dumped = json.dumps(payload)
    if as_raw_json:
        return dumped
    return base64.b64encode(dumped.encode("utf-8")).decode("utf-8")


class TestX402ConfigAndProtocol(unittest.TestCase):
    """Unit tests for configuration, replay protection store, and mock facilitator."""

    def setUp(self) -> None:
        self.config = X402Config(pay_to_address=SAMPLE_PAY_TO)
        self.nonce_store = ReplayNonceStore(max_entries=10)

    def test_01_config_defaults_and_validation(self) -> None:
        cfg = X402Config(pay_to_address=SAMPLE_PAY_TO)
        self.assertEqual(cfg.network, "base")
        self.assertEqual(cfg.price_vault_atomic, 20000)
        self.assertEqual(cfg.price_polymarket_atomic, 20000)
        self.assertEqual(cfg.price_zk_bitvec_atomic, 30000)
        self.assertEqual(cfg.price_differential_atomic, 50000)
        self.assertEqual(cfg.price_forensic_graph_atomic, 50000)
        self.assertEqual(cfg.price_blast_radius_atomic, 30000)

        # Invalid address test
        with self.assertRaises(ValueError):
            X402Config(pay_to_address="invalid_address")

        # Invalid network test
        with self.assertRaises(ValueError):
            X402Config(pay_to_address=SAMPLE_PAY_TO, network="solana")

    def test_02_config_from_env(self) -> None:
        old_env = os.environ.copy()
        try:
            os.environ["X402_PAY_TO_ADDRESS"] = "0x2222222222222222222222222222222222222222"
            os.environ["X402_NETWORK"] = "base-sepolia"
            os.environ["X402_PRICE_VAULT_ATOMIC"] = "25000"
            os.environ["X402_PRICE_FORENSIC_GRAPH_ATOMIC"] = "60000"
            os.environ["X402_PRICE_BLAST_RADIUS_ATOMIC"] = "40000"
            cfg = X402Config.from_env()
            self.assertEqual(cfg.pay_to_address, "0x2222222222222222222222222222222222222222")
            self.assertEqual(cfg.network, "base-sepolia")
            self.assertEqual(cfg.price_vault_atomic, 25000)
            self.assertEqual(cfg.price_forensic_graph_atomic, 60000)
            self.assertEqual(cfg.price_blast_radius_atomic, 40000)
        finally:
            os.environ.clear()
            os.environ.update(old_env)

    def test_03_replay_nonce_store_atomic_recording(self) -> None:
        store = ReplayNonceStore(max_entries=5)
        # First record succeeds
        self.assertTrue(store.record("nonce:abc"))
        self.assertTrue(store.is_consumed("nonce:abc"))
        # Second record is rejected as replay
        self.assertFalse(store.record("nonce:abc"))

    def test_04_replay_nonce_store_fifo_capacity(self) -> None:
        store = ReplayNonceStore(max_entries=3)
        store.record("n1")
        store.record("n2")
        store.record("n3")
        self.assertEqual(store.size(), 3)
        self.assertTrue(store.is_consumed("n1"))

        # 4th item evicts oldest (n1)
        store.record("n4")
        self.assertEqual(store.size(), 3)
        self.assertFalse(store.is_consumed("n1"))
        self.assertTrue(store.is_consumed("n4"))

    def test_05_deterministic_mock_facilitator_happy_path(self) -> None:
        facilitator = DeterministicMockFacilitator(self.config)
        raw_header = make_test_payment_header(self.config, amount=20000)
        req = {"maxAmountRequired": "20000"}

        valid, err, details = facilitator.verify(raw_header, req)
        self.assertTrue(valid, f"Verification failed: {err}")
        self.assertIsNone(err)
        self.assertIsNotNone(details)

        settled, tx_hash, err = facilitator.settle(raw_header, req)
        self.assertTrue(settled)
        self.assertTrue(tx_hash.startswith("0x"))

    def test_06_mock_facilitator_underpayment_rejected(self) -> None:
        facilitator = DeterministicMockFacilitator(self.config)
        # Providing 10,000 for a 20,000 requirement
        raw_header = make_test_payment_header(self.config, amount=10000)
        req = {"maxAmountRequired": "20000"}

        valid, err, _ = facilitator.verify(raw_header, req)
        self.assertFalse(valid)
        self.assertIn("Insufficient payment", err or "")

    def test_07_mock_facilitator_wrong_recipient_rejected(self) -> None:
        facilitator = DeterministicMockFacilitator(self.config)
        wrong_to = "0x9999999999999999999999999999999999999999"
        raw_header = make_test_payment_header(self.config, amount=20000, to_address=wrong_to)
        req = {"maxAmountRequired": "20000"}

        valid, err, _ = facilitator.verify(raw_header, req)
        self.assertFalse(valid)
        self.assertIn("Recipient mismatch", err or "")

    def test_08_mock_facilitator_expired_rejected(self) -> None:
        facilitator = DeterministicMockFacilitator(self.config)
        # ValidBefore in past (-10 seconds)
        raw_header = make_test_payment_header(self.config, amount=20000, valid_before_offset=-10)
        req = {"maxAmountRequired": "20000"}

        valid, err, _ = facilitator.verify(raw_header, req)
        self.assertFalse(valid)
        self.assertIn("expired", err or "")


class TestHTTPServerLoopback(unittest.TestCase):
    """End-to-end integration tests using an ephemeral live HTTP loopback server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = X402Config(pay_to_address=SAMPLE_PAY_TO)
        cls.prover_service = ProverService(cls.config)
        cls.nonce_store = ReplayNonceStore(max_entries=1000)
        cls.facilitator = DeterministicMockFacilitator(cls.config)

        # Bind to port 0 for an OS-assigned ephemeral free port
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
        # Brief pause to ensure loop is active
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2.0)

    def _http_request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        raw_bytes: Optional[bytes] = None,
        base_url: Optional[str] = None,
    ) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        url = f"{base_url or self.base_url}{path}"
        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)

        body_bytes: Optional[bytes] = None
        if raw_bytes is not None:
            body_bytes = raw_bytes
        elif data is not None:
            body_bytes = json.dumps(data).encode("utf-8")

        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                resp_headers = {k: v for k, v in resp.getheaders()}
                content = resp.read().decode("utf-8")
                try:
                    parsed = json.loads(content) if content else {}
                except Exception:
                    parsed = {"raw": content, "text": content}
                return resp.status, parsed, resp_headers
        except urllib.error.HTTPError as http_err:
            resp_headers = {k: v for k, v in http_err.headers.items()}
            err_content = http_err.read().decode("utf-8")
            try:
                parsed = json.loads(err_content)
            except Exception:
                parsed = {"raw": err_content}
            return http_err.code, parsed, resp_headers

    def test_09_get_health(self) -> None:
        status, body, _ = self._http_request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ok")
        self.assertEqual(body.get("x402Version"), 1)
        self.assertEqual(body.get("supportedVersions"), [1, 2])
        self.assertEqual(body.get("endpoints_count"), 16)
        self.assertIn("z3_native", body)
        self.assertEqual(body.get("payTo"), SAMPLE_PAY_TO)

    def test_10_get_bazaar_manifest(self) -> None:
        status, body, _ = self._http_request("GET", "/.well-known/x402-bazaar.json")
        self.assertEqual(status, 200)
        self.assertEqual(body.get("x402Version"), 1)
        self.assertEqual(body.get("supportedVersions"), [1, 2])
        self.assertEqual(body.get("name"), "omni-x402-prover")
        endpoints = body.get("endpoints", [])
        self.assertEqual(len(endpoints), 16)

    def test_11_unpaid_post_returns_402_challenge(self) -> None:
        status, body, _ = self._http_request("POST", "/x402/verify-vault-and-rounding", data={})
        self.assertEqual(status, 402)
        self.assertEqual(body.get("x402Version"), 1)
        self.assertIn("error", body)
        accepts = body.get("accepts", [])
        self.assertEqual(len(accepts), 1)
        self.assertEqual(accepts[0].get("scheme"), "exact")
        self.assertEqual(accepts[0].get("network"), "base")
        self.assertEqual(accepts[0].get("maxAmountRequired"), "20000")

    def test_12_paid_vault_safe_returns_verified(self) -> None:
        header_val = make_test_payment_header(self.config, amount=20000)
        dep_code = (
            "def preview_deposit(deposit: int, total_assets: int, total_shares: int) -> int:\n"
            "    return (deposit * total_shares) // total_assets"
        )
        red_code = (
            "def preview_redeem(shares: int, total_assets: int, total_shares: int) -> int:\n"
            "    return (shares * total_assets) // total_shares"
        )
        payload = {
            "deposit_fn_code": dep_code,
            "redeem_fn_code": red_code,
            "check_zero_share_mint": False,
        }
        status, body, resp_headers = self._http_request(
            "POST",
            "/x402/verify-vault-and-rounding",
            data=payload,
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status, 200)
        self.assertTrue(body.get("verified"))
        self.assertIn("X-PAYMENT-RESPONSE", resp_headers)
        self.assertIn("settlementReceipt", body)
        self.assertTrue(body["settlementReceipt"].get("success"))

    def test_13_paid_vault_vulnerable_returns_counterexample(self) -> None:
        header_val = make_test_payment_header(self.config, amount=20000)
        dep_code = (
            "def preview_deposit(deposit: int, total_assets: int, total_shares: int) -> int:\n"
            "    return (deposit * total_shares) // total_assets"
        )
        # Redeem rounds up (+1), enabling asset draining
        red_vuln_code = (
            "def preview_redeem(shares: int, total_assets: int, total_shares: int) -> int:\n"
            "    return ((shares * total_assets) // total_shares) + 1"
        )
        payload = {
            "deposit_fn_code": dep_code,
            "redeem_fn_code": red_vuln_code,
            "check_zero_share_mint": False,
        }
        status, body, resp_headers = self._http_request(
            "POST",
            "/x402/verify-vault-and-rounding",
            data=payload,
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status, 200)
        # Invariant violated: verified must be False!
        self.assertFalse(body.get("verified"))
        self.assertIsNotNone(body.get("counterexample"))
        self.assertEqual(body["counterexample"].get("check_type"), "vault_rounding")
        self.assertIn("X-PAYMENT-RESPONSE", resp_headers)

    def test_14_paid_polymarket_basket(self) -> None:
        header_val = make_test_payment_header(self.config, amount=20000)
        # Basket ask prices: [0.30, 0.40, 0.20] -> sum = 0.90 < 1.0 (Dutch-book edge exists!)
        payload = {
            "outcome_ask_prices": [0.30, 0.40, 0.20],
            "fee_bps": 100,  # 1% fee
            "payout_per_share": 1.0,
        }
        status, body, resp_headers = self._http_request(
            "POST",
            "/x402/verify-polymarket-basket",
            data=payload,
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status, 200)
        self.assertTrue(body.get("dutch_book_edge_detected"))
        self.assertTrue(body.get("verified"))
        self.assertGreater(body.get("arbitrage_edge_atomic", 0), 0)
        self.assertIn("X-PAYMENT-RESPONSE", resp_headers)

    def test_15_paid_zk_and_bitvec_overflow(self) -> None:
        header_val = make_test_payment_header(self.config, amount=30000)
        # Truncation check: a + b (u8 + u8) cast into u8 overflows at 256
        payload = {
            "mode": "bitvec",
            "expr": "a + b",
            "var_bitwidths": {"a": 8, "b": 8},
            "target_bitwidth": 8,
        }
        status, body, resp_headers = self._http_request(
            "POST",
            "/x402/verify-zk-and-bitvec",
            data=payload,
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status, 200)
        self.assertFalse(body.get("verified"))
        self.assertIsNotNone(body.get("counterexample"))
        self.assertIn("X-PAYMENT-RESPONSE", resp_headers)

    def test_16_paid_differential_spec_divergence(self) -> None:
        header_val = make_test_payment_header(self.config, amount=50000)
        code_a = "def compute(x: int) -> int:\n    return x * 2"
        code_b = "def compute(x: int) -> int:\n    return x + 1"
        payload = {
            "code_a": code_a,
            "code_b": code_b,
            "arg_names": ["x"],
        }
        status, body, resp_headers = self._http_request(
            "POST",
            "/x402/verify-differential-spec",
            data=payload,
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status, 200)
        # Implementations differ -> equivalent must be False
        self.assertFalse(body.get("equivalent"))
        self.assertIsNotNone(body.get("divergence"))
        self.assertIn("X-PAYMENT-RESPONSE", resp_headers)

    def test_17_security_replay_rejected(self) -> None:
        header_val = make_test_payment_header(self.config, amount=20000)
        payload = {
            "deposit_fn_code": "def preview_deposit(deposit: int, total_assets: int, total_shares: int) -> int:\n    return (deposit * total_shares) // total_assets",
            "redeem_fn_code": "def preview_redeem(shares: int, total_assets: int, total_shares: int) -> int:\n    return (shares * total_assets) // total_shares",
        }
        # First call succeeds
        status1, _, _ = self._http_request(
            "POST",
            "/x402/verify-vault-and-rounding",
            data=payload,
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status1, 200)

        # Immediate replay of the EXACT same header must be rejected with 402!
        status2, body2, _ = self._http_request(
            "POST",
            "/x402/verify-vault-and-rounding",
            data=payload,
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status2, 402)
        self.assertIn("replay", str(body2.get("error", "")).lower())

    def test_18_security_underpayment_rejected(self) -> None:
        # Endpoint requires 50,000; provide 20,000
        header_val = make_test_payment_header(self.config, amount=20000)
        payload = {
            "code_a": "def compute(x: int) -> int:\n    return x",
            "code_b": "def compute(x: int) -> int:\n    return x",
            "arg_names": ["x"],
        }
        status, body, _ = self._http_request(
            "POST",
            "/x402/verify-differential-spec",
            data=payload,
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status, 402)
        self.assertIn("Insufficient payment", str(body))

    def test_19_security_wrong_recipient_rejected(self) -> None:
        wrong_recipient = "0x8888888888888888888888888888888888888888"
        header_val = make_test_payment_header(self.config, amount=20000, to_address=wrong_recipient)
        status, body, _ = self._http_request(
            "POST",
            "/x402/verify-vault-and-rounding",
            data={"deposit_fn_code": "...", "redeem_fn_code": "..."},
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status, 402)
        self.assertIn("Recipient mismatch", str(body))

    def test_20_security_expired_authorization_rejected(self) -> None:
        header_val = make_test_payment_header(self.config, amount=20000, valid_before_offset=-60)
        status, body, _ = self._http_request(
            "POST",
            "/x402/verify-vault-and-rounding",
            data={"deposit_fn_code": "...", "redeem_fn_code": "..."},
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status, 402)
        self.assertIn("expired", str(body).lower())

    def test_21_security_oversized_payload_returns_413(self) -> None:
        header_val = make_test_payment_header(self.config, amount=20000)
        # Send 70 KB body (> 65536 max limit)
        huge_bytes = b"x" * 70000
        status, body, _ = self._http_request(
            "POST",
            "/x402/verify-vault-and-rounding",
            raw_bytes=huge_bytes,
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status, 413)
        self.assertIn("exceeds maximum limit", str(body.get("error", "")))

    def test_22_options_cors(self) -> None:
        status, _, headers = self._http_request("OPTIONS", "/x402/verify-vault-and-rounding")
        self.assertEqual(status, 204)
        self.assertIn("Access-Control-Allow-Origin", headers)

    def test_33_http_rejected_payload_is_not_charged(self) -> None:
        nonce = "0x" + uuid.uuid4().hex
        header_val = make_test_payment_header(self.config, amount=20000, nonce=nonce)
        status, body, resp_headers = self._http_request(
            "POST",
            "/x402/verify-vault-and-rounding",
            data={},
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status, 400)
        self.assertNotIn("x-payment-response", {k.lower() for k in resp_headers})
        self.assertNotIn("settlementReceipt", body)
        self.assertFalse(self.nonce_store.is_consumed(f"nonce:{nonce}"))

        # The untouched authorization still pays for a well-formed request
        payload = {
            "deposit_fn_code": (
                "def preview_deposit(deposit: int, total_assets: int, total_shares: int) -> int:\n"
                "    return (deposit * total_shares) // total_assets"
            ),
            "redeem_fn_code": (
                "def preview_redeem(shares: int, total_assets: int, total_shares: int) -> int:\n"
                "    return (shares * total_assets) // total_shares"
            ),
        }
        status, body, _ = self._http_request(
            "POST",
            "/x402/verify-vault-and-rounding",
            data=payload,
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status, 200)
        self.assertTrue(body.get("verified"))
        self.assertTrue(self.nonce_store.is_consumed(f"nonce:{nonce}"))

    def test_34_http_zk_without_z3_engine_is_503_and_unpaid(self) -> None:
        FallbackZ3Prover, _ = _create_fallback_verifiers()
        fallback_service = ProverService(self.config)
        fallback_service._prover = FallbackZ3Prover()
        store = ReplayNonceStore(max_entries=10)
        server = create_http_server(
            host="127.0.0.1",
            port=0,
            config=self.config,
            prover_service=fallback_service,
            nonce_store=store,
            facilitator=self.facilitator,
        )
        _, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            nonce = "0x" + uuid.uuid4().hex
            header_val = make_test_payment_header(self.config, amount=30000, nonce=nonce)
            status, body, resp_headers = self._http_request(
                "POST",
                "/x402/verify-zk-and-bitvec",
                data={
                    "mode": "zk",
                    "public_inputs": ["x"],
                    "witness_vars": ["w"],
                    "output_var": "w",
                    "constraints_exprs": ["w * w == x"],
                },
                headers={"X-PAYMENT": header_val},
                base_url=f"http://127.0.0.1:{port}",
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)
        self.assertEqual(status, 503)
        self.assertFalse(body.get("verified", False))
        self.assertNotIn("x-payment-response", {k.lower() for k in resp_headers})
        self.assertNotIn("settlementReceipt", body)
        self.assertEqual(store.size(), 0)
    def test_27_get_openapi_json(self) -> None:
        status, body, _ = self._http_request("GET", "/openapi.json")
        self.assertEqual(status, 200)
        self.assertEqual(body.get("openapi"), "3.1.0")
        self.assertIn("info", body)
        self.assertIn("paths", body)
        paths = body["paths"]
        # By default (include_meta=False), meta routes must NOT be in paths
        self.assertNotIn("/health", paths)
        self.assertNotIn("/.well-known/x402-bazaar.json", paths)
        # All 16 monetized endpoints must be in paths
        self.assertIn("/x402/verify-vault-and-rounding", paths)
        self.assertIn("/x402/verify-polymarket-basket", paths)
        self.assertIn("/x402/verify-zk-and-bitvec", paths)
        self.assertIn("/x402/verify-differential-spec", paths)
        self.assertIn("/x402/verify-forensic-graph", paths)
        self.assertIn("/x402/verify-ast-blast-radius", paths)
        self.assertIn("/x402/verify-erc4626-inflation-guard", paths)
        self.assertIn("/x402/verify-amm-constant-product", paths)
        self.assertIn("/x402/verify-crosschain-bridge-memo", paths)
        self.assertIn("/x402/verify-cardano-eutxo-conservation", paths)
        self.assertIn("/x402/verify-mev-sandwich-bound", paths)
        self.assertIn("/x402/verify-permit2-signature-scope", paths)
        self.assertIn("/x402/verify-liquidation-waterfall", paths)
        self.assertIn("/x402/verify-merkle-airdrop-claim", paths)
        self.assertIn("/x402/verify-fiat-crypto-otc-settlement", paths)
        self.assertIn("/x402/verify-sar-ed25519-dossier", paths)
        self.assertEqual(len(paths), 16)

        vault_post = paths["/x402/verify-vault-and-rounding"]["post"]
        self.assertIn("x-x402", vault_post)
        self.assertEqual(vault_post["x-x402"]["version"], 1)
        self.assertEqual(vault_post["x-x402"]["supportedVersions"], [1, 2])
        self.assertEqual(vault_post["x-x402"]["network"], "base")
        self.assertEqual(vault_post["x-x402"]["priceAtomic"], "20000")
        self.assertIn("402", vault_post["responses"])
        self.assertIn("PAYMENT-REQUIRED", vault_post["responses"]["402"]["headers"])
        self.assertIn("X-PAYMENT-REQUIRED", vault_post["responses"]["402"]["headers"])

        # With include_meta=1, /health and /.well-known/x402-bazaar.json are included
        status_meta, body_meta, _ = self._http_request("GET", "/openapi.json?include_meta=1")
        self.assertEqual(status_meta, 200)
        paths_meta = body_meta["paths"]
        self.assertIn("/health", paths_meta)
        self.assertIn("/.well-known/x402-bazaar.json", paths_meta)
        self.assertIn("/x402/verify-forensic-graph", paths_meta)
        self.assertIn("/x402/verify-ast-blast-radius", paths_meta)
        self.assertEqual(len(paths_meta), 18)

    def test_28_forwarded_proto_and_host_in_manifest_openapi_and_challenge(self) -> None:
        headers = {
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "prover.example.com",
        }
        # 1. Bazaar manifest with forwarded headers
        status, manifest, _ = self._http_request("GET", "/.well-known/x402-bazaar.json", headers=headers)
        self.assertEqual(status, 200)
        for ep in manifest.get("endpoints", []):
            self.assertTrue(ep["resource"].startswith("https://prover.example.com/x402/"))

        # 2. OpenAPI with forwarded headers
        status, spec, _ = self._http_request("GET", "/openapi.json", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(spec["servers"][0]["url"], "https://prover.example.com")

        # 3. 402 challenge with forwarded headers
        status, chal, _ = self._http_request("POST", "/x402/verify-vault-and-rounding", data={}, headers=headers)
        self.assertEqual(status, 402)
        accepts = chal.get("accepts", [])
        self.assertEqual(len(accepts), 1)
        self.assertEqual(accepts[0].get("resource"), "https://prover.example.com/x402/verify-vault-and-rounding")
        self.assertTrue(accepts[0].get("discoverable"))
        self.assertIn("outputSchema", accepts[0])
        self.assertIn("input", accepts[0]["outputSchema"])
        self.assertIn("output", accepts[0]["outputSchema"])

    def test_48_post_verify_forensic_graph_unpaid_402(self) -> None:
        status, body, headers = self._http_request("POST", "/x402/verify-forensic-graph", data={})
        self.assertEqual(status, 402)
        self.assertEqual(body.get("x402Version"), 1)
        accepts = body.get("accepts", [])
        self.assertEqual(len(accepts), 1)
        self.assertEqual(accepts[0].get("resource"), "/x402/verify-forensic-graph")
        self.assertEqual(accepts[0].get("maxAmountRequired"), "50000")
        self.assertIn("PAYMENT-REQUIRED", headers)

    def test_49_post_verify_forensic_graph_paid_200_direct_mode(self) -> None:
        header_val = make_test_payment_header(self.config, amount=50000)
        txs = [
            {"source": "Exploit_Root", "target": "Hop1", "asset": "USDC", "amount_usd": 1000000.0, "tx_type": "TRANSFER", "timestamp": 100},
            {"source": "Hop1", "target": "Hop2", "asset": "USDC", "amount_usd": 1000000.0, "tx_type": "TRANSFER", "timestamp": 110},
            {"source": "Hop2", "target": "Hop3", "asset": "USDC", "amount_usd": 1000000.0, "tx_type": "TRANSFER", "timestamp": 120},
            {"source": "Hop3", "target": "Hop1", "asset": "USDC", "amount_usd": 1000000.0, "tx_type": "TRANSFER", "timestamp": 130},
            {"source": "Hop3", "target": "Jupiter_Lend_Vault", "asset": "USDC", "amount_usd": 1000000.0, "tx_type": "DEPOSIT", "timestamp": 140, "receipt_id": "JUP-777"},
            {"source": "Hop3", "target": "Redeemer_Wallet", "asset": "USDC", "amount_usd": 1000000.0, "tx_type": "RECEIPT_HANDOVER", "timestamp": 150, "receipt_id": "JUP-777"},
            {"source": "Jupiter_Lend_Vault", "target": "Redeemer_Wallet", "asset": "USDC", "amount_usd": 1000000.0, "tx_type": "REDEEM", "timestamp": 160, "receipt_id": "JUP-777"},
            {"source": "Redeemer_Wallet", "target": "FixedFloat_Bridge", "asset": "USDC", "amount_usd": 500000.0, "tx_type": "TRANSFER", "timestamp": 170},
            {"source": "FixedFloat_Bridge", "target": "Bridge_Exit_Wallet", "asset": "USDC", "amount_usd": 495000.0, "tx_type": "TRANSFER", "timestamp": 200},
            {"source": "Redeemer_Wallet", "target": "THORChain_Bridge", "asset": "USDC", "amount_usd": 500000.0, "tx_type": "TRANSFER", "timestamp": 180},
        ]
        payload = {
            "transactions": txs,
            "tainted_sources": ["Exploit_Root"],
            "protocol_nodes": ["Jupiter_Lend_Vault", "THORChain_Bridge"],
            "bridge_nodes": ["FixedFloat_Bridge"],
            "max_window_seconds": 259200,
            "amount_tolerance": 0.05,
            "bridge_max_window_seconds": 7200,
            "bridge_fee_tolerance": 0.05,
        }
        status, body, resp_headers = self._http_request(
            "POST",
            "/x402/verify-forensic-graph",
            data=payload,
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status, 200)
        self.assertTrue(body.get("verified"))
        self.assertEqual(body.get("mode"), "forensic_dag")
        self.assertEqual(body.get("receipt_links_resolved"), 1)
        self.assertEqual(body.get("privacy_bridge_links_resolved"), 1)
        self.assertTrue(len(body.get("cyclic_clusters", [])) >= 1)
        taint_scores = body.get("taint_scores", {})
        self.assertEqual(taint_scores.get("Exploit_Root"), 1.0)
        self.assertGreaterEqual(taint_scores.get("THORChain_Bridge", 0.0), 0.15)
        high_risk = body.get("high_risk_protocol_exits", [])
        high_risk_nodes = [item["node"] for item in high_risk]
        self.assertIn("THORChain_Bridge", high_risk_nodes)
        self.assertIn("settlementReceipt", body)
        self.assertTrue(body["settlementReceipt"].get("success"))

    def test_50_post_verify_forensic_graph_paid_200_task_mode(self) -> None:
        header_val = make_test_payment_header(self.config, amount=50000)
        task_payload = {
            "task": {
                "task_id": "task_forensic_test_01",
                "swarm_id": "swm_forensic_test_01",
                "trace_id": "trc_forensic_test_01",
                "scope_grant": {
                    "allowed_assets_or_chains": ["USDC", "base", "ethereum"],
                    "valid_until": int(time.time()) + 3600,
                },
                "budget": {"max_seconds": 30.0, "max_cost_usd": 0.5, "max_depth": 5},
                "input": {
                    "chain": "base",
                    "transactions": [
                        {"source": "W1", "target": "W2", "asset": "USDC", "amount_usd": 500.0, "tx_type": "TRANSFER", "timestamp": 100},
                        {"source": "W2", "target": "W3", "asset": "USDC", "amount_usd": 500.0, "tx_type": "TRANSFER", "timestamp": 110},
                    ],
                    "tainted_sources": ["W1"],
                },
            }
        }
        status, body, resp_headers = self._http_request(
            "POST",
            "/x402/verify-forensic-graph",
            data=task_payload,
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status, 200)
        self.assertTrue(body.get("verified"))
        self.assertEqual(body.get("mode"), "swarm_task_v2")
        self.assertIn("result", body)
        self.assertEqual(body["result"].get("status"), "ok")
        self.assertIn("audit_event", body)
        self.assertIn("settlementReceipt", body)

    def test_51_post_verify_ast_blast_radius_unpaid_402(self) -> None:
        status, body, headers = self._http_request("POST", "/x402/verify-ast-blast-radius", data={})
        self.assertEqual(status, 402)
        self.assertEqual(body.get("x402Version"), 1)
        accepts = body.get("accepts", [])
        self.assertEqual(len(accepts), 1)
        self.assertEqual(accepts[0].get("resource"), "/x402/verify-ast-blast-radius")
        self.assertEqual(accepts[0].get("maxAmountRequired"), "30000")
        self.assertIn("PAYMENT-REQUIRED", headers)

    def test_52_post_verify_ast_blast_radius_paid_200_callgraph_and_patchgap(self) -> None:
        header_val = make_test_payment_header(self.config, amount=30000)
        source_code = (
            "def leaf_helper():\n"
            "    return 42\n\n"
            "def target_func():\n"
            "    return leaf_helper()\n\n"
            "def caller_one():\n"
            "    return target_func()\n\n"
            "def caller_two():\n"
            "    return caller_one()\n"
        )
        fork_code = (
            "def target_func():\n"
            "    assert total_assets > 0, 'zero assets'\n"
            "    return leaf_helper()\n"
        )
        upstream_patch_spec = {
            "target_name": "target_func",
            "required_guards": ["assert total_assets > 0"],
            "vulnerable_patterns": [],
            "authorized_bounty_scope": True,
        }
        payload = {
            "source_code": source_code,
            "modified_symbols": ["target_func"],
            "fork_code": fork_code,
            "upstream_patch_spec": upstream_patch_spec,
        }
        status, body, resp_headers = self._http_request(
            "POST",
            "/x402/verify-ast-blast-radius",
            data=payload,
            headers={"X-PAYMENT": header_val},
        )
        self.assertEqual(status, 200)
        self.assertTrue(body.get("verified"))
        self.assertEqual(body.get("modified_symbols"), ["target_func"])
        self.assertEqual(body.get("one_hop_callers"), ["caller_one"])
        self.assertEqual(body.get("one_hop_callees"), ["leaf_helper"])
        self.assertEqual(body.get("two_hop_callers"), ["caller_two"])
        self.assertEqual(body.get("two_hop_callees"), [])
        self.assertEqual(body.get("blast_radius_score"), 3)
        self.assertIsNotNone(body.get("patch_gap_report"))
        self.assertTrue(body["patch_gap_report"].get("is_patched"))
        self.assertIn("settlementReceipt", body)
        self.assertTrue(body["settlementReceipt"].get("success"))

    def test_53_get_challenge_on_all_monetized_routes(self) -> None:
        for route, amt in [
            ("/x402/verify-vault-and-rounding", "20000"),
            ("/x402/verify-polymarket-basket", "20000"),
            ("/x402/verify-zk-and-bitvec", "30000"),
            ("/x402/verify-differential-spec", "50000"),
            ("/x402/verify-forensic-graph", "50000"),
            ("/x402/verify-ast-blast-radius", "30000"),
            ("/x402/verify-erc4626-inflation-guard", "30000"),
            ("/x402/verify-amm-constant-product", "30000"),
            ("/x402/verify-crosschain-bridge-memo", "20000"),
            ("/x402/verify-cardano-eutxo-conservation", "30000"),
            ("/x402/verify-mev-sandwich-bound", "20000"),
            ("/x402/verify-permit2-signature-scope", "20000"),
            ("/x402/verify-liquidation-waterfall", "40000"),
            ("/x402/verify-merkle-airdrop-claim", "20000"),
            ("/x402/verify-fiat-crypto-otc-settlement", "50000"),
            ("/x402/verify-sar-ed25519-dossier", "50000"),
        ]:
            status, body, headers = self._http_request("GET", route)
            self.assertEqual(status, 402, f"Expected 402 on GET {route}, got {status}")
            self.assertIn("PAYMENT-REQUIRED", headers)
            accepts = body.get("accepts", [])
            self.assertEqual(len(accepts), 1)
            self.assertEqual(accepts[0].get("resource"), route)
            self.assertEqual(accepts[0].get("maxAmountRequired"), amt)

    def test_54_network_alias_base_mainnet_and_eip155(self) -> None:
        self.assertEqual(normalize_network_name("base"), "base")
        self.assertEqual(normalize_network_name("base-mainnet"), "base")
        self.assertEqual(normalize_network_name("eip155:8453"), "base")
        self.assertEqual(normalize_network_name("base-sepolia"), "base-sepolia")
        self.assertEqual(normalize_network_name("eip155:84532"), "base-sepolia")

        cfg_main = X402Config(pay_to_address=SAMPLE_PAY_TO, network="base-mainnet")
        self.assertEqual(cfg_main.network, "base")

        cfg_caip = X402Config(pay_to_address=SAMPLE_PAY_TO, network="eip155:8453")
        self.assertEqual(cfg_caip.network, "base")

        cfg_sep_caip = X402Config(pay_to_address=SAMPLE_PAY_TO, network="eip155:84532")
        self.assertEqual(cfg_sep_caip.network, "base-sepolia")

        mock_fac = DeterministicMockFacilitator(cfg_main)
        header_val = make_test_payment_header(cfg_main, amount=20000)
        decoded, _ = parse_raw_payment_header(header_val)
        decoded["network"] = "base-mainnet"
        mod_header = base64.b64encode(json.dumps(decoded).encode("utf-8")).decode("utf-8")
        req = {"maxAmountRequired": "20000", "payTo": SAMPLE_PAY_TO}
        valid, err, _ = mock_fac.verify(mod_header, req)
        self.assertTrue(valid, f"Verification failed with base-mainnet alias: {err}")


class TestMCPServer(unittest.TestCase):
    """Unit tests for the stdio JSON-RPC 2.0 Model Context Protocol server."""

    def setUp(self) -> None:
        self.config = X402Config(pay_to_address=SAMPLE_PAY_TO)
        self.prover_service = ProverService(self.config)
        self.nonce_store = ReplayNonceStore(max_entries=100)
        self.facilitator = DeterministicMockFacilitator(self.config)

    def _call_mcp(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return handle_jsonrpc_message(
            req=req,
            config=self.config,
            prover_service=self.prover_service,
            nonce_store=self.nonce_store,
            facilitator=self.facilitator,
        )

    def test_23_mcp_initialize_and_tools_list(self) -> None:
        init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        init_res = self._call_mcp(init_req)
        self.assertIsNotNone(init_res)
        self.assertEqual(init_res["result"]["serverInfo"]["name"], "omni-x402-prover")

        list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        list_res = self._call_mcp(list_req)
        self.assertIsNotNone(list_res)
        tools = list_res["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        self.assertIn("x402_bazaar_catalog", tool_names)
        self.assertIn("x402_verify_vault_rounding", tool_names)
        self.assertIn("x402_verify_polymarket_basket", tool_names)
        self.assertIn("x402_verify_zk_or_bitvec", tool_names)
        self.assertIn("x402_verify_differential_spec", tool_names)
        self.assertIn("x402_verify_forensic_graph", tool_names)
        self.assertIn("x402_verify_ast_blast_radius", tool_names)
        self.assertIn("x402_verify_erc4626_inflation_guard", tool_names)
        self.assertIn("x402_verify_amm_constant_product", tool_names)
        self.assertIn("x402_verify_crosschain_bridge_memo", tool_names)
        self.assertIn("x402_verify_cardano_eutxo_conservation", tool_names)
        self.assertIn("x402_verify_mev_sandwich_bound", tool_names)
        self.assertIn("x402_verify_permit2_signature_scope", tool_names)
        self.assertIn("x402_verify_liquidation_waterfall", tool_names)
        self.assertIn("x402_verify_merkle_airdrop_claim", tool_names)
        self.assertIn("x402_verify_fiat_crypto_otc_settlement", tool_names)
        self.assertIn("x402_verify_sar_ed25519_dossier", tool_names)
        self.assertEqual(len(tool_names), 17)

    def test_24_mcp_free_catalog_call(self) -> None:
        call_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "x402_bazaar_catalog", "arguments": {}},
        }
        res = self._call_mcp(call_req)
        self.assertIsNotNone(res)
        self.assertFalse(res["result"]["isError"])
        content = json.loads(res["result"]["content"][0]["text"])
        self.assertEqual(content["name"], "omni-x402-prover")

    def test_25_mcp_unpaid_tool_returns_payment_challenge(self) -> None:
        call_req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "x402_verify_vault_rounding",
                "arguments": {
                    "deposit_fn_code": "def preview_deposit(deposit: int, total_assets: int, total_shares: int) -> int:\n    return (deposit * total_shares) // total_assets",
                    "redeem_fn_code": "def preview_redeem(shares: int, total_assets: int, total_shares: int) -> int:\n    return (shares * total_assets) // total_shares",
                },
            },
        }
        res = self._call_mcp(call_req)
        self.assertIsNotNone(res)
        self.assertTrue(res["result"]["isError"])
        meta = res["result"].get("_meta", {})
        self.assertIn("x402", meta)
        self.assertEqual(meta["x402"]["x402Version"], 1)

    def test_26_mcp_paid_tool_call_settles_and_proves(self) -> None:
        payment_header = make_test_payment_header(self.config, amount=20000)
        call_req = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "x402_verify_vault_rounding",
                "arguments": {
                    "deposit_fn_code": "def preview_deposit(deposit: int, total_assets: int, total_shares: int) -> int:\n    return (deposit * total_shares) // total_assets",
                    "redeem_fn_code": "def preview_redeem(shares: int, total_assets: int, total_shares: int) -> int:\n    return (shares * total_assets) // total_shares",
                    "paymentHeader": payment_header,
                },
            },
        }
        res = self._call_mcp(call_req)
        self.assertIsNotNone(res)
        self.assertFalse(res["result"]["isError"])
        proof = json.loads(res["result"]["content"][0]["text"])
        self.assertTrue(proof["verified"])
        self.assertIn("x402PaymentResponse", res["result"]["_meta"])
        self.assertTrue(res["result"]["_meta"]["settlement"]["success"])

    def test_35_mcp_rejected_arguments_are_not_charged(self) -> None:
        nonce = "0x" + uuid.uuid4().hex
        payment_header = make_test_payment_header(self.config, amount=20000, nonce=nonce)
        call_req = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "x402_verify_vault_rounding",
                "arguments": {"paymentHeader": payment_header},
            },
        }
        res = self._call_mcp(call_req)
        self.assertIsNotNone(res)
        self.assertTrue(res["result"]["isError"])
        meta = res["result"].get("_meta", {})
        self.assertNotIn("settlement", meta)
        self.assertNotIn("x402PaymentResponse", meta)
        self.assertFalse(self.nonce_store.is_consumed(f"nonce:{nonce}"))

    def test_55_mcp_new_tools_in_registry(self) -> None:
        tools = get_tools_registry(self.config)
        tool_names = [t["name"] for t in tools]
        self.assertIn("x402_verify_forensic_graph", tool_names)
        self.assertIn("x402_verify_ast_blast_radius", tool_names)
        self.assertIn("x402_verify_erc4626_inflation_guard", tool_names)
        self.assertIn("x402_verify_amm_constant_product", tool_names)
        self.assertIn("x402_verify_crosschain_bridge_memo", tool_names)
        self.assertIn("x402_verify_cardano_eutxo_conservation", tool_names)
        self.assertIn("x402_verify_mev_sandwich_bound", tool_names)
        self.assertIn("x402_verify_permit2_signature_scope", tool_names)
        self.assertIn("x402_verify_liquidation_waterfall", tool_names)
        self.assertIn("x402_verify_merkle_airdrop_claim", tool_names)
        self.assertIn("x402_verify_fiat_crypto_otc_settlement", tool_names)
        self.assertIn("x402_verify_sar_ed25519_dossier", tool_names)
        self.assertEqual(len(tools), 17)
        self.assertEqual(get_mcp_tools, get_tools_registry)

    def test_56_mcp_unpaid_new_tools_return_payment_challenge(self) -> None:
        req_fg = {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "x402_verify_forensic_graph",
                "arguments": {
                    "transactions": [
                        {"source": "A", "target": "B", "amount_usd": 100.0, "tx_type": "TRANSFER", "timestamp": 1},
                    ],
                    "tainted_sources": ["A"],
                },
            },
        }
        res_fg = self._call_mcp(req_fg)
        self.assertIsNotNone(res_fg)
        self.assertTrue(res_fg["result"]["isError"])
        self.assertEqual(res_fg["result"]["_meta"]["x402"]["accepts"][0]["maxAmountRequired"], "50000")

        req_ast = {
            "jsonrpc": "2.0",
            "id": 102,
            "method": "tools/call",
            "params": {
                "name": "x402_verify_ast_blast_radius",
                "arguments": {
                    "modified_symbols": ["test_func"],
                },
            },
        }
        res_ast = self._call_mcp(req_ast)
        self.assertIsNotNone(res_ast)
        self.assertTrue(res_ast["result"]["isError"])
        self.assertEqual(res_ast["result"]["_meta"]["x402"]["accepts"][0]["maxAmountRequired"], "30000")

    def test_57_mcp_paid_new_tools_settle_and_verify(self) -> None:
        payment_fg = make_test_payment_header(self.config, amount=50000)
        req_fg = {
            "jsonrpc": "2.0",
            "id": 103,
            "method": "tools/call",
            "params": {
                "name": "x402_verify_forensic_graph",
                "arguments": {
                    "transactions": [
                        {"source": "X", "target": "Y", "amount_usd": 1000.0, "tx_type": "TRANSFER", "timestamp": 10},
                    ],
                    "tainted_sources": ["X"],
                    "paymentHeader": payment_fg,
                },
            },
        }
        res_fg = self._call_mcp(req_fg)
        self.assertIsNotNone(res_fg)
        self.assertFalse(res_fg["result"]["isError"])
        proof_fg = json.loads(res_fg["result"]["content"][0]["text"])
        self.assertTrue(proof_fg["verified"])
        self.assertEqual(proof_fg["mode"], "forensic_dag")
        self.assertTrue(res_fg["result"]["_meta"]["settlement"]["success"])

        payment_ast = make_test_payment_header(self.config, amount=30000)
        req_ast = {
            "jsonrpc": "2.0",
            "id": 104,
            "method": "tools/call",
            "params": {
                "name": "x402_verify_ast_blast_radius",
                "arguments": {
                    "source_code": "def callee(): return 1\ndef caller(): return callee()",
                    "modified_symbols": ["callee"],
                    "paymentHeader": payment_ast,
                },
            },
        }
        res_ast = self._call_mcp(req_ast)
        self.assertIsNotNone(res_ast)
        self.assertFalse(res_ast["result"]["isError"])
        proof_ast = json.loads(res_ast["result"]["content"][0]["text"])
        self.assertTrue(proof_ast["verified"])
        self.assertEqual(proof_ast["one_hop_callers"], ["caller"])
        self.assertTrue(res_ast["result"]["_meta"]["settlement"]["success"])


class TestFallbackEngineSandbox(unittest.TestCase):
    """The zero-dependency fallback must never run untrusted code with real builtins nor sell vacuous proofs."""

    VAULT_DEPOSIT = (
        "def preview_deposit(deposit: int, total_assets: int, total_shares: int) -> int:\n"
        "    return (deposit * total_shares) // total_assets"
    )
    VAULT_REDEEM = (
        "def preview_redeem(shares: int, total_assets: int, total_shares: int) -> int:\n"
        "    r = (shares * total_assets) // total_shares\n"
        "    return r if r > 0 else 0"
    )

    def setUp(self) -> None:
        self.FallbackZ3Prover, self.FallbackDiffVerifier = _create_fallback_verifiers()

    def test_27_fallback_vault_rejects_import_in_client_code(self) -> None:
        hostile_deposit = (
            "import os\n"
            "def preview_deposit(deposit: int, total_assets: int, total_shares: int) -> int:\n"
            "    return os.getpid()"
        )
        with self.assertRaises(ValueError):
            self.FallbackZ3Prover().check_vault_share_rounding_conservation(
                hostile_deposit, self.VAULT_REDEEM
            )

    def test_28_fallback_polymarket_rejects_builtins_in_custom_formula(self) -> None:
        hostile_formula = (
            "def calc_released(m: int, amt: int, fee: int) -> int:\n"
            "    return __import__('os').getpid()"
        )
        with self.assertRaises(ValueError):
            self.FallbackZ3Prover().check_conditional_token_conservation(
                num_outcomes=3,
                convert_no_subset_size=3,
                fee_bps=0,
                custom_conversion_formula=hostile_formula,
            )

    def test_29_fallback_bitvec_rejects_builtins_in_expr(self) -> None:
        with self.assertRaises(ValueError):
            self.FallbackZ3Prover().check_bitvec_overflow_and_cast_safety(
                expr="__import__('os').getpid() + a",
                var_bitwidths={"a": 8},
                target_bitwidth=64,
            )

    def test_30_fallback_differential_rejects_attribute_escape(self) -> None:
        hostile_a = (
            "def f(x: int) -> int:\n"
            "    return len(().__class__.__base__.__subclasses__())"
        )
        benign_b = "def g(x: int) -> int:\n    return x"
        with self.assertRaises(ValueError):
            self.FallbackDiffVerifier().verify_differential_consensus(
                hostile_a, benign_b, arg_names=["x"]
            )

    def test_31_fallback_still_accepts_plain_arithmetic(self) -> None:
        res = self.FallbackZ3Prover().check_vault_share_rounding_conservation(
            self.VAULT_DEPOSIT, self.VAULT_REDEEM
        )
        self.assertTrue(res.verified)
        self.assertEqual(res.solver_mode, "fallback_bounded")

    def test_32_fallback_zk_fails_closed_instead_of_vacuous_proof(self) -> None:
        with self.assertRaises(ProverCapacityError):
            self.FallbackZ3Prover().check_zk_underconstrained_circuit(
                public_inputs=["x"],
                witness_vars=["w"],
                output_var="w",
                constraints_exprs=["w * w == x"],
            )
        with self.assertRaises(ValueError):
            self.FallbackZ3Prover().check_zk_underconstrained_circuit(
                public_inputs=[], witness_vars=["w"], output_var="w", constraints_exprs=[]
            )

    def test_32b_fallback_zk_bounded_search_finds_two_witnesses(self) -> None:
        res = self.FallbackZ3Prover().check_zk_underconstrained_circuit(
            public_inputs=["x"],
            witness_vars=["w"],
            output_var="w",
            constraints_exprs=["w * 0 == 0"],
            domain_bounds=(0, 7),
        )
        self.assertFalse(res.verified)
        self.assertEqual(res.solver_mode, "fallback_bounded")
        self.assertNotEqual(res.counterexample.witness_1["w"], res.counterexample.witness_2["w"])

        sound = self.FallbackZ3Prover().check_zk_underconstrained_circuit(
            public_inputs=["x"],
            witness_vars=["w"],
            output_var="w",
            constraints_exprs=["w == x + 1"],
            domain_bounds=(0, 7),
        )
        self.assertTrue(sound.verified)


def http_json_request(
    base_url: str,
    method: str,
    path: str,
    data: Optional[Any] = None,
    headers: Optional[Dict[str, str]] = None,
    raw_bytes: Optional[bytes] = None,
) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
    """Module-level loopback helper (the class helper above is bound to TestHTTPServerLoopback)."""
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    body_bytes: Optional[bytes] = None
    if raw_bytes is not None:
        body_bytes = raw_bytes
    elif data is not None:
        body_bytes = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(f"{base_url}{path}", data=body_bytes, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            content = resp.read().decode("utf-8")
            return resp.status, (json.loads(content) if content else {}), dict(resp.getheaders())
    except urllib.error.HTTPError as http_err:
        err_content = http_err.read().decode("utf-8")
        try:
            parsed = json.loads(err_content)
        except Exception:
            parsed = {"raw": err_content}
        return http_err.code, parsed, dict(http_err.headers.items())


VALID_VAULT_PAYLOAD = {
    "deposit_fn_code": (
        "def preview_deposit(deposit: int, total_assets: int, total_shares: int) -> int:\n"
        "    return (deposit * total_shares) // total_assets"
    ),
    "redeem_fn_code": (
        "def preview_redeem(shares: int, total_assets: int, total_shares: int) -> int:\n"
        "    return (shares * total_assets) // total_shares"
    ),
}

_VAULT_SIG = "def preview_deposit(deposit: int, total_assets: int, total_shares: int) -> int:\n"
HOSTILE_VAULT_SNIPPETS = [
    ("import_system", _VAULT_SIG + "    return __import__('os').system('id')"),
    ("subclasses_escape", _VAULT_SIG + "    return ().__class__.__base__.__subclasses__()"),
    ("shift_bomb", _VAULT_SIG + "    return 1 << 100000000"),
    ("pow_bomb", _VAULT_SIG + "    return 2 ** 10000"),
    ("while_true", _VAULT_SIG + "    while True:\n        pass\n    return deposit"),
    ("for_loop", _VAULT_SIG + "    for i in range(10):\n        deposit = deposit + 1\n    return deposit"),
    ("dunder_name", _VAULT_SIG + "    return __builtins__"),
    ("lambda", _VAULT_SIG + "    return (lambda: 1)()"),
    ("subscript", _VAULT_SIG + "    return [deposit][0]"),
    ("comprehension", _VAULT_SIG + "    return [d for d in (deposit,)][0]"),
    ("try_with", _VAULT_SIG + "    try:\n        return deposit\n    except Exception:\n        return 0"),
    ("string_constant", _VAULT_SIG + "    return 'x' * deposit"),
    ("oversized", _VAULT_SIG + "    return deposit" + " + 1" * 2000),
]


class SlowVerifyFacilitator(DeterministicMockFacilitator):
    """Verification takes long enough for two same-nonce requests to overlap."""

    def verify(self, raw_header: str, requirement: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
        time.sleep(0.25)
        return super().verify(raw_header, requirement)


class TestTwoPhaseBillingHardening(unittest.TestCase):
    """Zero exec/eval, fail-closed ZK fallback and verify -> handler -> settle billing over HTTP."""

    @classmethod
    def _start_server(cls, prover_service: ProverService, facilitator: Any) -> Tuple[Any, threading.Thread, str, ReplayNonceStore]:
        store = ReplayNonceStore(max_entries=1000)
        server = create_http_server(
            host="127.0.0.1",
            port=0,
            config=cls.config,
            prover_service=prover_service,
            nonce_store=store,
            facilitator=facilitator,
        )
        _, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, f"http://127.0.0.1:{port}", store

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = X402Config(pay_to_address=SAMPLE_PAY_TO)
        cls.real_service = ProverService(cls.config)
        FallbackZ3Prover, _ = _create_fallback_verifiers()
        cls.fallback_service = ProverService(cls.config)
        cls.fallback_service._prover = FallbackZ3Prover()

        cls.facilitator = mock.Mock(wraps=DeterministicMockFacilitator(cls.config))
        cls.fallback_facilitator = mock.Mock(wraps=DeterministicMockFacilitator(cls.config))
        cls.slow_facilitator = mock.Mock(wraps=SlowVerifyFacilitator(cls.config))

        cls.server, cls.thread, cls.base_url, cls.store = cls._start_server(cls.real_service, cls.facilitator)
        cls.fb_server, cls.fb_thread, cls.fb_base_url, cls.fb_store = cls._start_server(
            cls.fallback_service, cls.fallback_facilitator
        )
        cls.slow_server, cls.slow_thread, cls.slow_base_url, cls.slow_store = cls._start_server(
            cls.real_service, cls.slow_facilitator
        )
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls) -> None:
        for server, thread in ((cls.server, cls.thread), (cls.fb_server, cls.fb_thread), (cls.slow_server, cls.slow_thread)):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)

    def setUp(self) -> None:
        for fac in (self.facilitator, self.fallback_facilitator, self.slow_facilitator):
            fac.verify.reset_mock()
            fac.settle.reset_mock()

    def _paid_post(self, base_url: str, path: str, data: Any, amount: int, header_name: str = "X-PAYMENT") -> Tuple[int, Dict[str, Any], Dict[str, str], str]:
        nonce = "0x" + uuid.uuid4().hex
        header_val = make_test_payment_header(self.config, amount=amount, nonce=nonce)
        status, body, resp_headers = http_json_request(base_url, "POST", path, data=data, headers={header_name: header_val})
        return status, body, resp_headers, nonce

    def test_36_rce_and_dos_payloads_are_400_and_never_settled(self) -> None:
        for label, code in HOSTILE_VAULT_SNIPPETS:
            with self.subTest(vault=label):
                payload = dict(VALID_VAULT_PAYLOAD, deposit_fn_code=code)
                status, body, resp_headers, nonce = self._paid_post(self.base_url, "/x402/verify-vault-and-rounding", payload, 20000)
                self.assertEqual(status, 400, body)
                self.assertNotIn("settlementReceipt", body)
                self.assertNotIn("x-payment-response", {k.lower() for k in resp_headers})
                self.assertFalse(self.store.is_consumed(f"nonce:{nonce}"))

        hostile_exprs = ["__import__('os').system('id')", "a ** 10000", "1 << 100000000", "a.__class__", "a if a else 'x'"]
        for expr in hostile_exprs:
            with self.subTest(bitvec=expr):
                payload = {"mode": "bitvec", "expr": expr, "var_bitwidths": {"a": 8}, "target_bitwidth": 8}
                status, body, _, _ = self._paid_post(self.base_url, "/x402/verify-zk-and-bitvec", payload, 30000)
                self.assertEqual(status, 400, body)

        with self.subTest(zk="constraint_rce"):
            payload = {
                "mode": "zk",
                "public_inputs": [],
                "witness_vars": ["w"],
                "output_var": "w",
                "constraints_exprs": ["__import__('os').system('id') == w"],
            }
            status, body, _, _ = self._paid_post(self.base_url, "/x402/verify-zk-and-bitvec", payload, 30000)
            self.assertEqual(status, 400, body)

        with self.subTest(differential="while_true"):
            payload = {
                "code_a": "def f(x: int) -> int:\n    while True:\n        pass\n    return x",
                "code_b": "def g(x: int) -> int:\n    return x",
                "arg_names": ["x"],
            }
            status, body, _, _ = self._paid_post(self.base_url, "/x402/verify-differential-spec", payload, 50000)
            self.assertEqual(status, 400, body)

        with self.subTest(polymarket="custom_formula_rce"):
            payload = {
                "outcome_ask_prices": [0.4, 0.5],
                "fee_bps": 200,
                "custom_conversion_formula": "def calc_released(m: int, amt: int, fee: int) -> int:\n    return __import__('os').getpid()",
            }
            status, body, _, _ = self._paid_post(self.base_url, "/x402/verify-polymarket-basket", payload, 20000)
            self.assertEqual(status, 400, body)

        self.assertEqual(self.facilitator.settle.call_count, 0)
        self.assertEqual(self.store.size(), 0)

    def test_37_zk_underconstrained_refuted_by_z3_and_fallback(self) -> None:
        payload = {
            "mode": "zk",
            "public_inputs": [],
            "witness_vars": ["w"],
            "output_var": "w",
            "constraints_exprs": ["w * 0 == 0"],
        }
        for label, base_url, facilitator, expected_mode in (
            ("z3", self.base_url, self.facilitator, "z3" if self.real_service.is_z3_native else None),
            ("fallback", self.fb_base_url, self.fallback_facilitator, "fallback_bounded"),
        ):
            with self.subTest(engine=label):
                status, body, resp_headers, _ = self._paid_post(base_url, "/x402/verify-zk-and-bitvec", payload, 30000)
                self.assertEqual(status, 200, body)
                self.assertIs(body.get("verified"), False)
                if expected_mode:
                    self.assertEqual(body.get("solver_mode"), expected_mode)
                cex = body.get("counterexample") or {}
                self.assertIsInstance(cex.get("witness_1"), dict)
                self.assertIsInstance(cex.get("witness_2"), dict)
                self.assertNotEqual(cex["witness_1"].get("w"), cex["witness_2"].get("w"))
                self.assertIn("X-PAYMENT-RESPONSE", resp_headers)
                self.assertEqual(facilitator.settle.call_count, 1)

    def test_38_zk_giant_domain_on_fallback_fails_closed_503_and_unpaid(self) -> None:
        payload = {
            "mode": "zk",
            "public_inputs": ["x"],
            "witness_vars": ["w"],
            "output_var": "w",
            "constraints_exprs": ["w * w == x"],
            "domain_bounds": [0, 1000],
        }
        status, body, resp_headers, nonce = self._paid_post(self.fb_base_url, "/x402/verify-zk-and-bitvec", payload, 30000)
        self.assertEqual(status, 503, body)
        self.assertIs(body.get("verified", False), False)
        self.assertNotIn("settlementReceipt", body)
        self.assertNotIn("x-payment-response", {k.lower() for k in resp_headers})
        self.assertEqual(self.fallback_facilitator.settle.call_count, 0)
        self.assertFalse(self.fb_store.is_consumed(f"nonce:{nonce}"))

        with self.subTest(zk="empty_witness_is_400"):
            status, body, _, _ = self._paid_post(
                self.fb_base_url,
                "/x402/verify-zk-and-bitvec",
                dict(payload, witness_vars=[], domain_bounds=[0, 3]),
                30000,
            )
            self.assertEqual(status, 400, body)
        self.assertEqual(self.fallback_facilitator.settle.call_count, 0)

    def test_39_corrupt_body_with_valid_payment_is_400_unpaid_and_nonce_reusable(self) -> None:
        nonce = "0x" + uuid.uuid4().hex
        header_val = make_test_payment_header(self.config, amount=20000, nonce=nonce)
        headers = {"X-PAYMENT": header_val}

        status, body, _ = http_json_request(self.base_url, "POST", "/x402/verify-vault-and-rounding", raw_bytes=b"{not json", headers=headers)
        self.assertEqual(status, 400, body)
        status, body, _ = http_json_request(self.base_url, "POST", "/x402/verify-vault-and-rounding", data=[1, 2], headers=headers)
        self.assertEqual(status, 400, body)
        self.assertEqual(self.facilitator.verify.call_count, 0)

        status, body, _ = http_json_request(self.base_url, "POST", "/x402/verify-vault-and-rounding", data={}, headers=headers)
        self.assertEqual(status, 400, body)
        self.assertEqual(self.facilitator.settle.call_count, 0)
        self.assertFalse(self.store.is_consumed(f"nonce:{nonce}"))

        status, body, resp_headers = http_json_request(self.base_url, "POST", "/x402/verify-vault-and-rounding", data=VALID_VAULT_PAYLOAD, headers=headers)
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("verified"))
        self.assertIn("X-PAYMENT-RESPONSE", resp_headers)
        self.assertEqual(self.facilitator.settle.call_count, 1)
        self.assertTrue(self.store.is_consumed(f"nonce:{nonce}"))

        status, body, _ = http_json_request(self.base_url, "POST", "/x402/verify-vault-and-rounding", data=VALID_VAULT_PAYLOAD, headers=headers)
        self.assertEqual(status, 402, body)
        self.assertIn("replay", str(body.get("error", "")).lower())
        self.assertEqual(self.facilitator.settle.call_count, 1)

    def test_40_missing_payment_header_is_402_before_body_validation(self) -> None:
        status, body, _ = http_json_request(self.base_url, "POST", "/x402/verify-vault-and-rounding", raw_bytes=b"{not json")
        self.assertEqual(status, 402, body)
        self.assertEqual(body.get("x402Version"), 1)
        self.assertEqual(body["accepts"][0]["maxAmountRequired"], "20000")
        self.assertEqual(self.facilitator.verify.call_count, 0)
        self.assertEqual(self.facilitator.settle.call_count, 0)

    def test_41_payment_signature_header_gets_payment_response_header(self) -> None:
        status, body, resp_headers, nonce = self._paid_post(
            self.base_url, "/x402/verify-vault-and-rounding", VALID_VAULT_PAYLOAD, 20000, header_name="PAYMENT-SIGNATURE"
        )
        self.assertEqual(status, 200, body)
        lowered = {k.lower(): v for k, v in resp_headers.items()}
        self.assertIn("x-payment-response", lowered)
        self.assertIn("payment-response", lowered)
        self.assertEqual(lowered["x-payment-response"], lowered["payment-response"])
        self.assertTrue(self.store.is_consumed(f"nonce:{nonce}"))

    def test_42_concurrent_same_nonce_settles_at_most_once(self) -> None:
        nonce = "0x" + uuid.uuid4().hex
        header_val = make_test_payment_header(self.config, amount=20000, nonce=nonce)
        results: list = []

        def worker() -> None:
            results.append(
                http_json_request(
                    self.slow_base_url, "POST", "/x402/verify-vault-and-rounding", data=VALID_VAULT_PAYLOAD, headers={"X-PAYMENT": header_val}
                )
            )

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15.0)

        statuses = sorted(r[0] for r in results)
        self.assertEqual(statuses, [200, 402], results)
        self.assertLessEqual(self.slow_facilitator.settle.call_count, 1)
        self.assertEqual(self.slow_facilitator.settle.call_count, 1)
        self.assertTrue(self.slow_store.is_consumed(f"nonce:{nonce}"))

    def test_43_mcp_handler_failure_releases_nonce_for_retry(self) -> None:
        store = ReplayNonceStore(max_entries=100)
        facilitator = mock.Mock(wraps=DeterministicMockFacilitator(self.config))
        nonce = "0x" + uuid.uuid4().hex
        header_val = make_test_payment_header(self.config, amount=20000, nonce=nonce)

        def call(arguments: Dict[str, Any]) -> Dict[str, Any]:
            req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "x402_verify_vault_rounding", "arguments": dict(arguments, paymentHeader=header_val)},
            }
            return handle_jsonrpc_message(req, self.config, self.real_service, store, facilitator) or {}

        hostile = call(dict(VALID_VAULT_PAYLOAD, deposit_fn_code=HOSTILE_VAULT_SNIPPETS[0][1]))
        self.assertTrue(hostile["result"].get("isError"))
        self.assertEqual(facilitator.settle.call_count, 0)
        self.assertFalse(store.is_consumed(f"nonce:{nonce}"))

        ok = call(VALID_VAULT_PAYLOAD)
        self.assertFalse(ok["result"].get("isError"), ok)
        self.assertIn("x402PaymentResponse", ok["result"]["_meta"])
        self.assertEqual(facilitator.settle.call_count, 1)
        self.assertTrue(store.is_consumed(f"nonce:{nonce}"))

    def test_44_native_path_bignum_dos_vectors_are_400_and_unpaid(self) -> None:
        vault = "/x402/verify-vault-and-rounding"
        zkbv = "/x402/verify-zk-and-bitvec"
        diff = "/x402/verify-differential-spec"
        poly = "/x402/verify-polymarket-basket"
        ident_a = "def f(a: int) -> int:\n    return a"
        vectors = [
            ("vault_pow_tower", vault, 20000,
             dict(VALID_VAULT_PAYLOAD, deposit_fn_code=_VAULT_SIG + "    return (((deposit ** 64) ** 64) ** 64) ** 64")),
            ("vault_symbolic_exponent", vault, 20000,
             dict(VALID_VAULT_PAYLOAD, deposit_fn_code=_VAULT_SIG + "    return deposit ** total_shares")),
            ("vault_symbolic_shift", vault, 20000,
             dict(VALID_VAULT_PAYLOAD, deposit_fn_code=_VAULT_SIG + "    return 1 << deposit")),
            ("vault_mult_chain", vault, 20000,
             dict(VALID_VAULT_PAYLOAD, deposit_fn_code=_VAULT_SIG + "    return " + " * ".join(["deposit"] * 70))),
            ("vault_assigned_growth", vault, 20000,
             dict(VALID_VAULT_PAYLOAD, deposit_fn_code=_VAULT_SIG + "    x = deposit ** 64\n    x = x * x\n    return x")),
            ("bitvec_pow_tower", zkbv, 30000,
             {"mode": "bitvec", "expr": "((a ** 64) ** 64) ** 64", "var_bitwidths": {"a": 256}, "target_bitwidth": 256}),
            ("bitvec_wide_pow", zkbv, 30000,
             {"mode": "bitvec", "expr": "a ** 64", "var_bitwidths": {"a": 256}, "target_bitwidth": 256}),
            ("bitvec_symbolic_exponent", zkbv, 30000,
             {"mode": "bitvec", "expr": "a ** b", "var_bitwidths": {"a": 8, "b": 8}, "target_bitwidth": 8}),
            ("bitvec_symbolic_shift", zkbv, 30000,
             {"mode": "bitvec", "expr": "a << b", "var_bitwidths": {"a": 8, "b": 8}, "target_bitwidth": 8}),
            ("bitvec_width_over_cap", zkbv, 30000,
             {"mode": "bitvec", "expr": "a + 1", "var_bitwidths": {"a": 4096}, "target_bitwidth": 256}),
            ("zk_wide_domain_pow", zkbv, 30000,
             {"mode": "zk", "public_inputs": ["x"], "witness_vars": ["w"], "output_var": "w",
              "constraints_exprs": ["w ** 64 == x"], "domain_bounds": [0, 2 ** 100]}),
            ("differential_pow_square", diff, 50000,
             {"code_a": "def f(a: int) -> int:\n    return (a ** 63) * (a ** 63)", "code_b": ident_a, "arg_names": ["a"]}),
            ("differential_huge_unsigned_width", diff, 50000,
             {"code_a": ident_a, "code_b": ident_a, "arg_names": ["a"], "unsigned_bit_width": 10 ** 9}),
            ("polymarket_huge_outcomes", poly, 20000,
             {"outcome_ask_prices": [0.4, 0.5], "num_outcomes": 10 ** 9, "convert_no_subset_size": 2}),
            ("polymarket_huge_fee", poly, 20000, {"outcome_ask_prices": [0.4, 0.5], "fee_bps": 10 ** 6}),
            ("polymarket_subset_over_outcomes", poly, 20000,
             {"outcome_ask_prices": [0.4, 0.5], "num_outcomes": 2, "convert_no_subset_size": 3}),
        ]
        for label, path, amount, payload in vectors:
            with self.subTest(vector=label):
                status, body, resp_headers, nonce = self._paid_post(self.base_url, path, payload, amount)
                self.assertEqual(status, 400, body)
                self.assertNotIn("settlementReceipt", body)
                self.assertNotIn("x-payment-response", {k.lower() for k in resp_headers})
                self.assertFalse(self.store.is_consumed(f"nonce:{nonce}"))
        self.assertEqual(self.facilitator.settle.call_count, 0)

    def test_45_bit_bounded_arithmetic_keeps_legit_payloads_paid(self) -> None:
        legit = [
            ("vault_muldiv_scaled", "/x402/verify-vault-and-rounding", 20000,
             dict(VALID_VAULT_PAYLOAD, deposit_fn_code=_VAULT_SIG + "    return deposit * total_shares * 1000000 // (total_assets * 1000000)")),
            ("bitvec_shift_mask_256", "/x402/verify-zk-and-bitvec", 30000,
             {"mode": "bitvec", "expr": "(a << 128) & ((1 << 256) - 1)", "var_bitwidths": {"a": 256}, "target_bitwidth": 256}),
            ("bitvec_add_128", "/x402/verify-zk-and-bitvec", 30000,
             {"mode": "bitvec", "expr": "a + b", "var_bitwidths": {"a": 128, "b": 128}, "target_bitwidth": 256}),
            ("differential_64bit_domain", "/x402/verify-differential-spec", 50000,
             {"code_a": "def f(a: int, b: int) -> int:\n    return a * b + 1",
              "code_b": "def g(a: int, b: int) -> int:\n    return b * a + 1",
              "arg_names": ["a", "b"], "domain_bounds": [0, 2 ** 64 - 1], "unsigned_bit_width": 64, "fuzz_iterations": 32}),
            ("polymarket_default_formula", "/x402/verify-polymarket-basket", 20000,
             {"outcome_ask_prices": [0.3, 0.3, 0.3], "fee_bps": 200, "num_outcomes": 3, "convert_no_subset_size": 2}),
        ]
        for label, path, amount, payload in legit:
            with self.subTest(vector=label):
                status, body, resp_headers, nonce = self._paid_post(self.base_url, path, payload, amount)
                self.assertEqual(status, 200, body)
                self.assertIn("settlementReceipt", body)
                self.assertIn("x-payment-response", {k.lower() for k in resp_headers})
                self.assertTrue(self.store.is_consumed(f"nonce:{nonce}"))
        self.assertEqual(self.facilitator.settle.call_count, len(legit))

    def test_46_input_cardinality_caps_are_400_and_unpaid(self) -> None:
        vault = "/x402/verify-vault-and-rounding"
        zkbv = "/x402/verify-zk-and-bitvec"
        diff = "/x402/verify-differential-spec"
        poly = "/x402/verify-polymarket-basket"
        nine_args = [f"a{i}" for i in range(9)]
        nine_sig = "def f(" + ", ".join(nine_args) + "):\n    return " + " + ".join(nine_args)
        vectors = [
            ("bitvec_4_vars", zkbv, 30000, {"mode": "bitvec", "expr": "a + b + c + d", "var_bitwidths": {"a": 8, "b": 8, "c": 8, "d": 8}, "target_bitwidth": 8}),
            ("zk_4_vars", zkbv, 30000, {"mode": "zk", "public_inputs": ["x"], "witness_vars": ["w1", "w2", "w3"], "output_var": "w1", "constraints_exprs": ["w1 + w2 + w3 == x"], "domain_bounds": [0, 3]}),
            ("zk_9_constraints", zkbv, 30000, {"mode": "zk", "public_inputs": ["x"], "witness_vars": ["w"], "output_var": "w", "constraints_exprs": ["w == x"] * 9, "domain_bounds": [0, 3]}),
            ("bitvec_9_preconditions", zkbv, 30000, {"mode": "bitvec", "expr": "a", "var_bitwidths": {"a": 8}, "target_bitwidth": 8, "preconditions": ["a > 0"] * 9}),
            ("differential_9_args", diff, 50000, {"code_a": nine_sig, "code_b": nine_sig, "arg_names": nine_args}),
            ("bitvec_width_513", zkbv, 30000, {"mode": "bitvec", "expr": "a", "var_bitwidths": {"a": 513}, "target_bitwidth": 8}),
            ("polymarket_257_prices", poly, 20000, {"outcome_ask_prices": [0.3] * 257}),
            ("polymarket_price_1e308", poly, 20000, {"outcome_ask_prices": [1e308, 0.3]}),
            ("polymarket_payout_nan", poly, 20000, {"outcome_ask_prices": [0.3, 0.3], "payout_per_share": float("nan")}),
            ("polymarket_fee_bps_inf", poly, 20000, {"outcome_ask_prices": [0.3, 0.3], "fee_bps": float("inf")}),
            ("vault_max_assets_str", vault, 20000, dict(VALID_VAULT_PAYLOAD, max_assets="100")),
            ("differential_fuzz_iterations_inf", diff, 50000, {"code_a": "def f(a):\n    return a", "code_b": "def g(a):\n    return a", "arg_names": ["a"], "fuzz_iterations": float("inf")}),
            ("differential_seed_list", diff, 50000, {"code_a": "def f(a):\n    return a", "code_b": "def g(a):\n    return a", "arg_names": ["a"], "seed": [1]}),
            ("zk_public_inputs_str", zkbv, 30000, {"mode": "zk", "public_inputs": "xy", "witness_vars": ["w"], "output_var": "w", "constraints_exprs": ["w == x"], "domain_bounds": [0, 3]}),
        ]
        for label, path, amount, payload in vectors:
            with self.subTest(vector=label):
                status, body, resp_headers, nonce = self._paid_post(self.base_url, path, payload, amount)
                self.assertEqual(status, 400, body)
                self.assertNotIn("settlementReceipt", body)
                self.assertNotIn("x-payment-response", {k.lower() for k in resp_headers})
                self.assertFalse(self.store.is_consumed(f"nonce:{nonce}"))
        self.assertEqual(self.facilitator.settle.call_count, 0)

    def test_47_fallback_zk_fails_closed_on_huge_domain_and_deadline(self) -> None:
        zkbv = "/x402/verify-zk-and-bitvec"
        huge = {"mode": "zk", "public_inputs": [], "witness_vars": ["w"], "output_var": "w", "constraints_exprs": ["w == 0"], "domain_bounds": [0, 2 ** 100]}
        small = {"mode": "zk", "public_inputs": ["x"], "witness_vars": ["w"], "output_var": "w", "constraints_exprs": ["w == x"], "domain_bounds": [0, 3]}
        with self.subTest(fallback="huge_domain"):
            status, body, resp_headers, nonce = self._paid_post(self.fb_base_url, zkbv, huge, 30000)
            self.assertEqual(status, 503, body)
            self.assertNotIn("settlementReceipt", body)
            self.assertNotIn("x-payment-response", {k.lower() for k in resp_headers})
            self.assertFalse(self.fb_store.is_consumed(f"nonce:{nonce}"))
        with self.subTest(fallback="deadline"):
            with mock.patch.object(prover_service_module, "_FALLBACK_SEARCH_SECONDS", -1.0):
                status, body, resp_headers, nonce = self._paid_post(self.fb_base_url, zkbv, small, 30000)
            self.assertEqual(status, 503, body)
            self.assertNotIn("settlementReceipt", body)
            self.assertFalse(self.fb_store.is_consumed(f"nonce:{nonce}"))
        with self.subTest(fallback="legit_after_deadline_restored"):
            status, body, _, nonce = self._paid_post(self.fb_base_url, zkbv, small, 30000)
            self.assertEqual(status, 200, body)
            self.assertTrue(self.fb_store.is_consumed(f"nonce:{nonce}"))
        self.assertEqual(self.fallback_facilitator.settle.call_count, 1)


class TestFacilitatorAndRegistrationSpecs(unittest.TestCase):
    """Unit tests for RemoteHTTPFacilitatorClient Coinbase/PayAI spec parsing and env defaults."""

    def test_29_remote_http_facilitator_mocked_coinbase_payai_spec(self) -> None:
        client = RemoteHTTPFacilitatorClient(
            facilitator_url="https://api.developer.coinbase.com/x402",
            bearer_token="mock_cdp_jwt_token",
        )
        req_spec = {"scheme": "exact", "network": "base", "maxAmountRequired": "20000"}

        mock_payment_payload = {
            "x402Version": 1,
            "scheme": "exact",
            "network": "base",
            "payload": {
                "authorization": {
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": SAMPLE_PAY_TO,
                    "value": "20000",
                    "validAfter": "0",
                    "validBefore": str(int(time.time()) + 3600),
                    "nonce": "0xabc123",
                },
                "signature": "0x1234567890abcdef",
            },
        }
        mock_payment_header = json.dumps(mock_payment_payload)

        # 1. Happy path: standard Coinbase / PayAI {"isValid": true, "payer": "0x123..."}
        mock_resp_success = MagicMock()
        mock_resp_success.read.return_value = json.dumps({
            "isValid": True,
            "payer": "0x1111111111111111111111111111111111111111",
        }).encode("utf-8")
        mock_resp_success.__enter__.return_value = mock_resp_success

        with patch("urllib.request.urlopen", return_value=mock_resp_success) as mock_urlopen:
            valid, err, details = client.verify(mock_payment_header, req_spec)
            self.assertTrue(valid)
            self.assertIsNone(err)
            self.assertIsNotNone(details)
            self.assertTrue(details.get("isValid"))
            # Check Bearer auth header was attached
            called_req = mock_urlopen.call_args[0][0]
            self.assertEqual(called_req.get_header("Authorization"), "Bearer mock_cdp_jwt_token")
            # Assert paymentPayload sent as dict and paymentHeader NOT sent
            posted_data = json.loads(called_req.data.decode("utf-8"))
            self.assertIn("paymentPayload", posted_data)
            self.assertIsInstance(posted_data["paymentPayload"], dict)
            self.assertNotIn("paymentHeader", posted_data)
            self.assertEqual(posted_data["x402Version"], 1)
            self.assertEqual(posted_data["paymentRequirements"], req_spec)

        # 2. Failure path: {"isValid": false, "invalidReason": "insufficient_funds", "invalidMessage": "Payer balance too low"}
        mock_resp_fail = MagicMock()
        mock_resp_fail.read.return_value = json.dumps({
            "isValid": False,
            "invalidReason": "insufficient_funds",
            "invalidMessage": "Payer balance too low",
        }).encode("utf-8")
        mock_resp_fail.__enter__.return_value = mock_resp_fail

        with patch("urllib.request.urlopen", return_value=mock_resp_fail):
            valid, err, details = client.verify(mock_payment_header, req_spec)
            self.assertFalse(valid)
            self.assertEqual(err, "Payer balance too low")

        # 3. Settle happy path: {"txHash": "0x987...", "success": True}
        mock_resp_settle_ok = MagicMock()
        mock_resp_settle_ok.read.return_value = json.dumps({
            "success": True,
            "txHash": "0x9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef",
        }).encode("utf-8")
        mock_resp_settle_ok.__enter__.return_value = mock_resp_settle_ok

        with patch("urllib.request.urlopen", return_value=mock_resp_settle_ok) as mock_urlopen_settle:
            settled, tx_hash, err = client.settle(mock_payment_header, req_spec)
            self.assertTrue(settled)
            self.assertEqual(tx_hash, "0x9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef")
            self.assertIsNone(err)
            called_req_settle = mock_urlopen_settle.call_args[0][0]
            posted_data_settle = json.loads(called_req_settle.data.decode("utf-8"))
            self.assertIn("paymentPayload", posted_data_settle)
            self.assertIsInstance(posted_data_settle["paymentPayload"], dict)
            self.assertNotIn("paymentHeader", posted_data_settle)

        # 4. Settle failure path: {"errorMessage": "EIP-3009 nonce expired or used", "errorReason": "nonce_expired"}
        mock_resp_settle_fail = MagicMock()
        mock_resp_settle_fail.read.return_value = json.dumps({
            "success": False,
            "errorMessage": "EIP-3009 nonce expired or used",
            "errorReason": "nonce_expired",
        }).encode("utf-8")
        mock_resp_settle_fail.__enter__.return_value = mock_resp_settle_fail

        with patch("urllib.request.urlopen", return_value=mock_resp_settle_fail):
            settled, tx_hash, err = client.settle(mock_payment_header, req_spec)
            self.assertFalse(settled)
            self.assertIsNone(tx_hash)
            self.assertEqual(err, "EIP-3009 nonce expired or used")

        # 5. A mined tx hash without success=true (failed transfer inside the facilitator's batch) is not a settlement
        for settle_body, expected_err in (
            (
                {
                    "success": False,
                    "errorReason": "transfer_event_mismatch",
                    "transaction": "0x" + "de" * 32,
                },
                "transfer_event_mismatch",
            ),
            ({"transaction": "0x" + "ad" * 32}, "Settlement failed at facilitator"),
        ):
            mock_resp_settle_tx_only = MagicMock()
            mock_resp_settle_tx_only.read.return_value = json.dumps(settle_body).encode("utf-8")
            mock_resp_settle_tx_only.__enter__.return_value = mock_resp_settle_tx_only
            with patch("urllib.request.urlopen", return_value=mock_resp_settle_tx_only):
                settled, tx_hash, err = client.settle(mock_payment_header, req_spec)
                self.assertFalse(settled)
                self.assertIsNone(tx_hash)
                self.assertEqual(err, expected_err)

    def test_29b_cdp_api_key_never_sent_to_non_coinbase_facilitators(self) -> None:
        # Regression: CDP_API_KEY used to be the bearer fallback, so it reached PayAI on every verify/settle.
        ok_resp = MagicMock()
        ok_resp.read.return_value = json.dumps({"isValid": True}).encode("utf-8")
        ok_resp.__enter__.return_value = ok_resp
        with patch.dict(os.environ, {"CDP_API_KEY": "cdp-key-sentinel"}):
            os.environ.pop("X402_FACILITATOR_BEARER_TOKEN", None)
            for bearer, expected_auth in ((None, [None, None]), ("payai-token", ["Bearer payai-token", None])):
                client = RemoteHTTPFacilitatorClient(
                    facilitator_url="https://facilitator.payai.network",
                    bearer_token=bearer,
                    secondary_facilitator_url="https://x402.org/facilitator",
                )
                with patch(
                    "urllib.request.urlopen",
                    side_effect=[urllib.error.URLError("primary down"), ok_resp],
                ) as mock_urlopen:
                    client._post("verify", {})
                sent = [c.args[0] for c in mock_urlopen.call_args_list]
                self.assertEqual(
                    [r.full_url for r in sent],
                    ["https://facilitator.payai.network/verify", "https://x402.org/facilitator/verify"],
                )
                self.assertEqual([r.get_header("Authorization") for r in sent], expected_auth)

    def test_30_zero_env_defaults_to_production_base_and_payai(self) -> None:
        old_env = os.environ.copy()
        try:
            for k in list(os.environ.keys()):
                if k.startswith("X402_"):
                    del os.environ[k]
            cfg = X402Config.from_env()
            self.assertEqual(cfg.pay_to_address, DEFAULT_BASE_PAY_TO)
            self.assertEqual(cfg.pay_to_address, "0xc8dc4ecb93c4c665Fad07E1261F5f7D60e3C6E0F")
            self.assertEqual(cfg.facilitator_url, DEFAULT_FACILITATOR_URL)
            self.assertEqual(cfg.facilitator_url, "https://facilitator.payai.network")
            self.assertEqual(cfg.network, "base")
            self.assertEqual(cfg.asset_address, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
        finally:
            os.environ.clear()
            os.environ.update(old_env)

    def test_31_end_to_end_x402_v2_payment_facilitator_and_mock(self) -> None:
        config = X402Config(pay_to_address=SAMPLE_PAY_TO, network="base")
        mock_facilitator = DeterministicMockFacilitator(config)

        v2_payload = {
            "x402Version": 2,
            "scheme": "exact",
            "network": "eip155:8453",
            "payload": {
                "authorization": {
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": SAMPLE_PAY_TO,
                    "value": "20000",
                    "validAfter": "0",
                    "validBefore": str(int(time.time()) + 3600),
                    "nonce": "0x" + "a" * 64,
                },
                "signature": "0x" + "b" * 130,
            },
        }
        v2_raw_header = json.dumps(v2_payload)
        requirement = {
            "scheme": "exact",
            "network": "base",
            "amount": "20000",
            "payTo": SAMPLE_PAY_TO,
        }

        # 1. Verify with DeterministicMockFacilitator (CAIP-2 alias match eip155:8453 == base)
        valid, err, details = mock_facilitator.verify(v2_raw_header, requirement)
        self.assertTrue(valid, f"Mock facilitator failed: {err}")
        self.assertIsNone(err)
        assert details is not None
        self.assertEqual(details["recipient"], SAMPLE_PAY_TO.lower())

        settled, tx_hash, err = mock_facilitator.settle(v2_raw_header, requirement)
        self.assertTrue(settled)
        self.assertIsNotNone(tx_hash)
        assert tx_hash is not None
        self.assertTrue(tx_hash.startswith("0x"))

        # 2. Verify with RemoteHTTPFacilitatorClient
        remote_client = RemoteHTTPFacilitatorClient(
            facilitator_url="https://api.developer.coinbase.com/x402",
            bearer_token="mock_v2_token",
        )
        mock_resp_v2 = MagicMock()
        mock_resp_v2.read.return_value = json.dumps({
            "isValid": True,
            "payer": "0x1111111111111111111111111111111111111111",
        }).encode("utf-8")
        mock_resp_v2.__enter__.return_value = mock_resp_v2

        with patch("urllib.request.urlopen", return_value=mock_resp_v2) as mock_urlopen:
            valid_r, err_r, details_r = remote_client.verify(v2_raw_header, requirement)
            self.assertTrue(valid_r)
            self.assertIsNone(err_r)
            called_req = mock_urlopen.call_args[0][0]
            posted = json.loads(called_req.data.decode("utf-8"))
            self.assertEqual(posted["x402Version"], 2)
            self.assertIsInstance(posted["paymentPayload"], dict)
            self.assertEqual(posted["paymentPayload"]["x402Version"], 2)
            self.assertNotIn("paymentHeader", posted)
            # CAIP-2 normalized requirements
            req_sent = posted["paymentRequirements"]
            self.assertEqual(req_sent["network"], "eip155:8453")
            self.assertEqual(req_sent["amount"], "20000")
            self.assertEqual(req_sent["extra"], {"name": "USD Coin", "version": "2"})

    def test_32_vault_unannotated_functions_pass_prover_service(self) -> None:
        config = X402Config(pay_to_address=SAMPLE_PAY_TO)
        service = ProverService(config)
        payload = {
            "deposit_fn_code": "def preview_deposit(deposit, total_assets, total_shares):\n    return (deposit * total_shares) // total_assets\n",
            "redeem_fn_code": "def preview_redeem(shares, total_assets, total_shares):\n    return (shares * total_assets) // total_shares\n",
            "max_assets": 10000,
            "max_shares": 10000,
            "check_zero_share_mint": False,
        }
        res = service.verify_vault_and_rounding(payload)
        self.assertTrue(res["verified"])
        self.assertIn("vault_rounding", res["check_type"])

    def test_33_generator_frame_escape_rejected_by_auditor(self) -> None:
        config = X402Config(pay_to_address=SAMPLE_PAY_TO)
        service = ProverService(config)
        malicious_code = (
            "def exploit(deposit, total_assets, total_shares):\n"
            "    g = (x for x in ())\n"
            "    f = g.gi_frame.f_back.f_builtins\n"
            "    return 1\n"
        )
        payload = {
            "deposit_fn_code": malicious_code,
            "redeem_fn_code": "def preview_redeem(shares, total_assets, total_shares):\n    return shares\n",
        }
        with self.assertRaises(ValueError):
            service.verify_vault_and_rounding(payload)


class TestHermesTenMicroservicesAndAffiliate(unittest.TestCase):
    """Full unit and HTTP loopback test coverage for the 10 Hermes microservices."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = X402Config(pay_to_address=SAMPLE_PAY_TO)
        cls.prover_service = ProverService(cls.config)
        cls.nonce_store = ReplayNonceStore()
        cls.facilitator = DeterministicMockFacilitator(cls.config)

        # Allocate ephemeral port for loopback server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        cls.server_port = sock.getsockname()[1]
        sock.close()

        cls.server = create_http_server(
            host="127.0.0.1",
            port=cls.server_port,
            config=cls.config,
            prover_service=cls.prover_service,
            nonce_store=cls.nonce_store,
            facilitator=cls.facilitator,
        )
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2.0)

    def _http_request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        url = f"http://127.0.0.1:{self.server_port}{path}"
        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)
        body_bytes = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                resp_headers = {k: v for k, v in resp.getheaders()}
                content = resp.read().decode("utf-8")
                try:
                    parsed = json.loads(content) if content else {}
                except Exception:
                    parsed = {"raw": content, "text": content}
                return resp.status, parsed, resp_headers
        except urllib.error.HTTPError as http_err:
            resp_headers = {k: v for k, v in http_err.headers.items()}
            err_content = http_err.read().decode("utf-8")
            try:
                parsed = json.loads(err_content)
            except Exception:
                parsed = {"raw": err_content}
            return http_err.code, parsed, resp_headers

    def test_58_erc4626_inflation_guard_logic(self) -> None:
        # Vulnerable case: 0 virtual offset and huge donation yields 0 victim shares
        vuln = self.prover_service.verify_erc4626_inflation_guard({
            "virtual_shares_offset": 0,
            "virtual_assets_offset": 0,
            "attacker_initial_deposit": 1,
            "attacker_donation": 100000,
            "victim_deposit": 1000,
        })
        self.assertFalse(vuln["verified"])
        self.assertTrue(vuln["inflation_vulnerable"])
        self.assertEqual(vuln["victim_shares_minted"], 0)
        self.assertIsNotNone(vuln["counterexample"])

        # Protected case: virtual_shares_offset=1000 protects victim
        safe = self.prover_service.verify_erc4626_inflation_guard({
            "virtual_shares_offset": 1000,
            "virtual_assets_offset": 1,
            "attacker_initial_deposit": 1,
            "attacker_donation": 1000,
            "victim_deposit": 10000,
        })
        self.assertTrue(safe["verified"])
        self.assertFalse(safe["inflation_vulnerable"])
        self.assertGreater(safe["victim_shares_minted"], 0)
        self.assertIsNone(safe["counterexample"])

    def test_59_amm_constant_product_logic(self) -> None:
        # Safe swap
        safe = self.prover_service.verify_amm_constant_product({
            "reserve_x": 1000000,
            "reserve_y": 1000000,
            "amount_in": 1000,
            "fee_bps": 30,
            "rounding_direction": "down",
        })
        self.assertTrue(safe["verified"])
        self.assertFalse(safe["invariant_violated"])

        # Exploitative swap with amount_out higher than max_valid_amount_out
        vuln = self.prover_service.verify_amm_constant_product({
            "reserve_x": 1000000,
            "reserve_y": 1000000,
            "amount_in": 1000,
            "amount_out": 999999,
        })
        self.assertFalse(vuln["verified"])
        self.assertTrue(vuln["invariant_violated"])
        self.assertIsNotNone(vuln["counterexample"])

    def test_60_crosschain_bridge_memo_logic(self) -> None:
        # Valid memo
        valid_res = self.prover_service.verify_crosschain_bridge_memo({
            "memo": "=:BTC.BTC:bc1qxyz:10000000:thor1aff:50",
            "max_affiliate_bps": 100,
            "require_slippage_limit": True,
        })
        self.assertTrue(valid_res["verified"])
        self.assertEqual(valid_res["action"], "=")
        self.assertEqual(valid_res["limit_atomic"], 10000000)
        self.assertEqual(valid_res["affiliate_bps"], 50)
        self.assertEqual(len(valid_res["issues"]), 0)

        # Injection attempt
        inj_res = self.prover_service.verify_crosschain_bridge_memo({
            "memo": "=:BTC.BTC:bc1qxyz;DROP TABLE transactions:1000",
        })
        self.assertFalse(inj_res["verified"])
        self.assertIn("injection_character_detected", inj_res["issues"])

        # Excessive affiliate fee
        fee_res = self.prover_service.verify_crosschain_bridge_memo({
            "memo": "=:BTC.BTC:bc1qxyz:1000:thor1aff:500",
            "max_affiliate_bps": 100,
        })
        self.assertFalse(fee_res["verified"])
        self.assertTrue(any("affiliate_fee_exceeds_max" in iss for iss in fee_res["issues"]))

    def test_61_cardano_eutxo_conservation_logic(self) -> None:
        # Conserved transaction
        safe_inputs = [
            {"lovelace": 5000000, "assets": {"TokenA": 100}, "is_script": False},
        ]
        safe_outputs = [
            {"lovelace": 4800000, "assets": {"TokenA": 100}},
        ]
        res = self.prover_service.verify_cardano_eutxo_conservation({
            "inputs": safe_inputs,
            "outputs": safe_outputs,
            "fee_lovelace": 200000,
            "min_utxo_lovelace": 1000000,
        })
        self.assertTrue(res["verified"])
        self.assertTrue(res["lovelace_conserved"])
        self.assertTrue(res["native_assets_conserved"])

        # Double satisfaction risk
        script_inputs = [
            {"lovelace": 5000000, "assets": {}, "is_script": True, "has_unique_input_ref": False},
            {"lovelace": 5000000, "assets": {}, "is_script": True, "has_unique_input_ref": False},
        ]
        script_outputs = [{"lovelace": 9800000, "assets": {}}]
        ds_res = self.prover_service.verify_cardano_eutxo_conservation({
            "inputs": script_inputs,
            "outputs": script_outputs,
            "fee_lovelace": 200000,
        })
        self.assertFalse(ds_res["verified"])
        self.assertTrue(ds_res["double_satisfaction_risk"])

    def test_62_mev_sandwich_bound_logic(self) -> None:
        # High slippage = sandwich profitable
        high_slip = self.prover_service.verify_mev_sandwich_bound({
            "reserve_in": 10000000,
            "reserve_out": 10000000,
            "user_amount_in": 100000,
            "slippage_bps": 500,
            "fee_bps": 30,
            "attacker_gas_cost_in": 10,
        })
        self.assertFalse(high_slip["verified"])
        self.assertTrue(high_slip["sandwich_profitable"])
        self.assertGreater(high_slip["optimal_frontrun_in"], 0)

        # Low slippage = sandwich proof
        low_slip = self.prover_service.verify_mev_sandwich_bound({
            "reserve_in": 10000000,
            "reserve_out": 10000000,
            "user_amount_in": 100000,
            "slippage_bps": 5,
            "fee_bps": 30,
            "attacker_gas_cost_in": 5000,
        })
        self.assertTrue(low_slip["verified"])
        self.assertFalse(low_slip["sandwich_profitable"])

    def test_63_permit2_signature_scope_logic(self) -> None:
        now = int(time.time())
        # Safe scope
        safe = self.prover_service.verify_permit2_signature_scope({
            "spender": "0x1111111111111111111111111111111111111111",
            "amount": 1000000,
            "expiration": now + 86400,
            "sig_deadline": now + 600,
            "chain_id": 8453,
            "current_timestamp": now,
        })
        self.assertTrue(safe["verified"])
        self.assertEqual(len(safe["risks"]), 0)

        # Unlimited approval + expired deadline
        risky = self.prover_service.verify_permit2_signature_scope({
            "spender": "0x1111111111111111111111111111111111111111",
            "amount": str((1 << 160) - 1),
            "expiration": now + 35 * 86400,
            "sig_deadline": now - 10,
            "current_timestamp": now,
        })
        self.assertFalse(risky["verified"])
        self.assertTrue(risky["unlimited_approval"])
        self.assertTrue(any("unlimited_approval_risk" in r for r in risky["risks"]))
        self.assertTrue(any("expired_signature_deadline" in r for r in risky["risks"]))

    def test_64_liquidation_waterfall_logic(self) -> None:
        # Solvent healthy position
        healthy = self.prover_service.verify_liquidation_waterfall({
            "collateral_value": 20000,
            "debt_value": 10000,
            "liquidation_threshold_bps": 8500,
        })
        self.assertTrue(healthy["verified"])
        self.assertFalse(healthy["liquidatable"])

        # Liquidatable but fully covered by insurance
        covered = self.prover_service.verify_liquidation_waterfall({
            "collateral_value": 10000,
            "debt_value": 10000,
            "liquidation_threshold_bps": 8500,
            "close_factor_bps": 5000,
            "liquidation_bonus_bps": 500,
            "insurance_fund_balance": 5000,
        })
        self.assertTrue(covered["verified"])
        self.assertTrue(covered["liquidatable"])
        self.assertEqual(covered["socialized_loss"], 0)

        # Underwater shortfall exceeding insurance fund
        underwater = self.prover_service.verify_liquidation_waterfall({
            "collateral_value": 3000,
            "debt_value": 10000,
            "liquidation_threshold_bps": 8500,
            "close_factor_bps": 5000,
            "liquidation_bonus_bps": 500,
            "insurance_fund_balance": 100,
        })
        self.assertFalse(underwater["verified"])
        self.assertGreater(underwater["socialized_loss"], 0)

    def test_65_merkle_airdrop_claim_logic(self) -> None:
        claims = [
            {"account": "0xaaaa", "index": 0, "amount": 1000},
            {"account": "0xbbbb", "index": 1, "amount": 2000},
        ]
        # Sound double-hash
        res = self.prover_service.verify_merkle_airdrop_claim({
            "claims": claims,
            "leaf_hash_mode": "double_hash",
        })
        self.assertTrue(res["verified"])
        self.assertFalse(res["second_preimage_vulnerable"])
        self.assertTrue(res["computed_merkle_root"].startswith("0x"))

        # Single-hash vulnerable
        res_v = self.prover_service.verify_merkle_airdrop_claim({
            "claims": claims,
            "leaf_hash_mode": "single_hash",
        })
        self.assertFalse(res_v["verified"])
        self.assertTrue(res_v["second_preimage_vulnerable"])

        # Duplicate account
        dup_claims = [
            {"account": "0xaaaa", "index": 0, "amount": 1000},
            {"account": "0xaaaa", "index": 1, "amount": 2000},
        ]
        res_dup = self.prover_service.verify_merkle_airdrop_claim({"claims": dup_claims})
        self.assertFalse(res_dup["verified"])
        self.assertGreater(len(res_dup["duplicate_claims"]), 0)

    def test_66_fiat_crypto_otc_settlement_logic(self) -> None:
        # Reconciled within spread tolerance (50 bps)
        # fx = 1200 ARS/USD. 1200000 ARS cents = 12,000 ARS = 10 USD = 10,000,000 USDC atomic
        res_safe = self.prover_service.verify_fiat_crypto_otc_settlement({
            "fiat_legs": [{"cvu": "00001", "amount_ars_cents": 1200000}],
            "crypto_legs": [{"wallet": "0x1111", "amount_usdc_atomic": 10000000}],
            "agreed_fx_ars_per_usd": 1200.0,
            "max_spread_bps": 50,
        })
        self.assertTrue(res_safe["verified"])
        self.assertFalse(res_safe["spread_skimming_detected"])
        self.assertIn("cmp_psav_certificate_sha256", res_safe)

        # Spread skimming detected (delivering only 9,000,000 atomic = 10% spread)
        res_skim = self.prover_service.verify_fiat_crypto_otc_settlement({
            "fiat_legs": [{"cvu": "00001", "amount_ars_cents": 1200000}],
            "crypto_legs": [{"wallet": "0x1111", "amount_usdc_atomic": 9000000}],
            "agreed_fx_ars_per_usd": 1200.0,
            "max_spread_bps": 50,
        })
        self.assertFalse(res_skim["verified"])
        self.assertTrue(res_skim["spread_skimming_detected"])
        self.assertGreater(res_skim["effective_spread_bps"], 50)

    def test_67_sar_ed25519_dossier_logic(self) -> None:
        # Dark vessel inside Argentine EEZ
        res_safe = self.prover_service.verify_sar_ed25519_dossier({
            "vessel_id": "IUU-TARGET-42",
            "lat": -45.5,
            "lon": -60.0,
            "rcs_db": 48.0,
            "ais_active": False,
        })
        self.assertTrue(res_safe["verified"])
        self.assertTrue(res_safe["inside_eez"])
        self.assertTrue(res_safe["dark_vessel_detected"])
        self.assertTrue(res_safe["ed25519_canonical_s_valid"])

        # Non-canonical Ed25519 scalar (s >= L) malleability attack
        # L = 2^252 + 27742317777372353535851937790883648493
        # L in hex (little-endian bytes): s = L (scalar >= L)
        L = 7237005577332262213973186563042994240857116359379907606001950938285454250989
        non_canonical_s_bytes = (L + 1).to_bytes(32, "little")
        malleable_sig_hex = ("00" * 32) + non_canonical_s_bytes.hex()
        res_mal = self.prover_service.verify_sar_ed25519_dossier({
            "vessel_id": "IUU-MALLEABLE",
            "lat": -45.5,
            "lon": -60.0,
            "rcs_db": 48.0,
            "ais_active": False,
            "ed25519_signature_hex": malleable_sig_hex,
        })
        self.assertFalse(res_mal["verified"])
        self.assertFalse(res_mal["ed25519_canonical_s_valid"])

    def test_68_http_paid_hermes_endpoints_ignore_referral_header(self) -> None:
        # A legacy X-Referral-Agent header is accepted but no rebate is claimed in the receipt
        endpoint = "/x402/verify-erc4626-inflation-guard"
        amt = self.config.price_erc4626_inflation_atomic  # 30000
        payment_header = make_test_payment_header(self.config, amount=amt)

        referral_agent = "0x7777777777777777777777777777777777777777"
        status, body, headers = self._http_request(
            "POST",
            endpoint,
            data={
                "virtual_shares_offset": 1000,
                "virtual_assets_offset": 1,
                "attacker_initial_deposit": 1,
                "attacker_donation": 1000,
                "victim_deposit": 10000,
            },
            headers={
                "X-PAYMENT": payment_header,
                "X-Referral-Agent": referral_agent,
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(body.get("verified"))
        self.assertIn("settlementReceipt", body)
        self.assertNotIn("referralRebate", body)

    def test_69_http_referral_program_route_removed(self) -> None:
        status, _, _ = self._http_request("GET", "/x402/referral-program")
        self.assertEqual(status, 404)

    def test_70_mcp_paid_hermes_tools(self) -> None:
        # Test paid MCP call for x402_verify_crosschain_bridge_memo
        amt = self.config.price_crosschain_memo_atomic  # 20000
        payment_header = make_test_payment_header(self.config, amount=amt)
        req = {
            "jsonrpc": "2.0",
            "id": 999,
            "method": "tools/call",
            "params": {
                "name": "x402_verify_crosschain_bridge_memo",
                "arguments": {
                    "memo": "=:BTC.BTC:bc1qxyz:500000:thor1aff:50",
                    "paymentHeader": payment_header,
                },
            },
        }
        res = handle_jsonrpc_message(
            req=req,
            config=self.config,
            prover_service=self.prover_service,
            nonce_store=self.nonce_store,
            facilitator=self.facilitator,
        )
        self.assertIsNotNone(res)
        self.assertNotIn("error", res)
        self.assertFalse(res["result"].get("isError", False))
        meta = res["result"].get("_meta", {})
        self.assertIn("settlement", meta)
        self.assertTrue(meta["settlement"].get("success"))

    def test_71_llms_txt_and_aeo_discovery(self) -> None:
        manifest = self.prover_service.build_bazaar_discovery_manifest()
        endpoints = [ep["resource"] for ep in manifest["endpoints"]]
        self.assertEqual(len(endpoints), 16)

        for path in ("/llms.txt", "/x402/llms.txt"):
            status, body, headers = self._http_request("GET", path)
            self.assertEqual(status, 200)
            content_type = headers.get("Content-Type") or headers.get("content-type") or ""
            self.assertTrue(content_type.startswith("text/plain"), f"Unexpected content-type: {content_type}")
            text = body.get("raw") or body.get("text") or ""
            self.assertTrue(len(text) > 1000)
            self.assertIn("Omni x402 Formal Invariant Prover", text)
            self.assertIn("eip155:8453", text)
            self.assertNotIn("X-Referral-Agent", text)
            self.assertIn("https://www.x402scan.com/server/f2245b59-82c5-46ae-bb13-d88836d7910f", text)
            self.assertIn("https://www.x402scan.com/server/4f613c20-a216-4742-be54-8cd621415701", text)
            for ep in endpoints:
                self.assertIn(ep, text, f"Endpoint {ep} missing in {path}")

    def test_72_openapi_enriched_spec_without_referral_header(self) -> None:
        status, body, _ = self._http_request("GET", "/openapi.json")
        self.assertEqual(status, 200)
        compact = json.dumps(body, separators=(",", ":"))
        compact_size = len(compact.encode("utf-8"))
        self.assertLess(compact_size, 80000, f"OpenAPI spec size {compact_size} exceeds 80000 bytes limit")

        guidance = body.get("info", {}).get("x-guidance", "")
        self.assertNotIn("X-Referral-Agent", guidance)

        paths = body.get("paths", {})
        self.assertEqual(len(paths), 16)
        for route, path_item in paths.items():
            post_op = path_item.get("post", {})
            params = post_op.get("parameters", [])
            param_names = [p.get("name") for p in params]
            self.assertNotIn("X-Referral-Agent", param_names, f"X-Referral-Agent still advertised on {route}")

    def test_73_mcp_directory_manifests_and_skill_md(self) -> None:
        import os
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        smithery_path = os.path.join(base_dir, "smithery.yaml")
        glama_path = os.path.join(base_dir, "glama.json")
        skill_path = os.path.join(base_dir, "SKILL.md")

        self.assertTrue(os.path.exists(smithery_path), "smithery.yaml does not exist")
        self.assertTrue(os.path.exists(glama_path), "glama.json does not exist")
        self.assertTrue(os.path.exists(skill_path), "SKILL.md does not exist")

        with open(smithery_path, "r", encoding="utf-8") as f:
            smithery_content = f.read()

        with open(glama_path, "r", encoding="utf-8") as f:
            glama_content = f.read()
            glama_json = json.loads(glama_content)

        with open(skill_path, "r", encoding="utf-8") as f:
            skill_content = f.read()

        manifest = self.prover_service.build_bazaar_discovery_manifest()
        endpoints = [ep["resource"] for ep in manifest["endpoints"]]
        self.assertEqual(len(endpoints), 16)

        # All 16 endpoints must be in smithery.yaml, glama.json, and SKILL.md
        for ep in endpoints:
            self.assertIn(ep, smithery_content, f"Missing {ep} in smithery.yaml")
            self.assertIn(ep, glama_content, f"Missing {ep} in glama.json")
            self.assertIn(ep, skill_content, f"Missing {ep} in SKILL.md")

        # Check glama.json metadata
        self.assertEqual(glama_json.get("name"), "omni-x402-prover")
        self.assertEqual(glama_json.get("homepage"), "https://gateway.stealthmark.io")
        self.assertEqual(
            glama_json.get("servers"),
            ["https://gateway.stealthmark.io", "https://sentinel.oceaneye-ai.com"]
        )
        self.assertEqual(
            glama_json.get("x402scan"),
            [
                "https://www.x402scan.com/server/4f613c20-a216-4742-be54-8cd621415701",
                "https://www.x402scan.com/server/f2245b59-82c5-46ae-bb13-d88836d7910f",
            ]
        )
        self.assertEqual(len(glama_json.get("tools", [])), 17)

        # Check smithery.yaml stdio config
        self.assertIn("stdio", smithery_content)
        self.assertIn("X402_PAY_TO_ADDRESS", smithery_content)
        self.assertIn("X402_FACILITATOR_URL", smithery_content)
        self.assertIn("X402_NETWORK", smithery_content)
        self.assertIn("omni_x402_prover.mcp_server", smithery_content)

        # Check SKILL.md frontmatter and agentcash / MCP docs
        self.assertTrue(skill_content.startswith("---\nname: omni-x402-formal-prover"))
        self.assertIn("agentcash", skill_content)
        self.assertNotIn("X-Referral-Agent", skill_content)


_CDP_KEY_ID = "test-only-cdp-key-id"
_CDP_SECRET = "test-only-cdp-secret-value"
_CDP_ENV_NAMES = (
    "CDP_API_KEY",
    "CDP_API_KEY_ID",
    "CDP_API_KEY_SECRET",
    "X402_FACILITATOR_BEARER_TOKEN",
    "X402_SECONDARY_FACILITATOR_URL",
)
_HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None


class _FakeEd25519Key:
    """Stand-in signing key so the JWT tests run without the optional `cryptography` package."""

    def __init__(self) -> None:
        self.signed: list = []

    def sign(self, data: bytes) -> bytes:
        self.signed.append(data)
        return b"fake-ed25519-signature"


def _ok_response(body: Dict[str, Any]) -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = json.dumps(body).encode("utf-8")
    resp.__enter__.return_value = resp
    return resp


def _decode_jwt_segment(segment: str) -> Dict[str, Any]:
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


class TestCDPFacilitatorAuth(unittest.TestCase):
    """CDP JWT auth on the Coinbase failover path; nothing CDP-related may reach PayAI."""

    def setUp(self) -> None:
        self.fake_key = _FakeEd25519Key()

    def _client(
        self, env: Dict[str, str], loader_error: Optional[BaseException] = None, **kwargs: Any
    ) -> RemoteHTTPFacilitatorClient:
        kwargs.setdefault("facilitator_url", DEFAULT_FACILITATOR_URL)
        with patch.dict(os.environ, env):
            for name in _CDP_ENV_NAMES:
                if name not in env:
                    os.environ.pop(name, None)
            with patch(
                "omni_x402_prover.x402_protocol._load_cdp_private_key",
                return_value=("EdDSA", self.fake_key),
                side_effect=loader_error,
            ):
                return RemoteHTTPFacilitatorClient(**kwargs)

    def _assert_cdp_jwt(self, request: urllib.request.Request, endpoint: str) -> Dict[str, Any]:
        auth = request.get_header("Authorization")
        self.assertIsNotNone(auth)
        self.assertTrue(auth.startswith("Bearer "))
        header_b64, claims_b64, signature_b64 = auth[len("Bearer "):].split(".")
        header = _decode_jwt_segment(header_b64)
        claims = _decode_jwt_segment(claims_b64)
        self.assertEqual(
            {k: header[k] for k in ("alg", "kid", "typ")},
            {"alg": "EdDSA", "kid": _CDP_KEY_ID, "typ": "JWT"},
        )
        self.assertRegex(header["nonce"], r"^[0-9]{16}$")
        self.assertEqual(claims["sub"], _CDP_KEY_ID)
        self.assertEqual(claims["iss"], "cdp")
        self.assertEqual(claims["uris"], [f"POST api.cdp.coinbase.com/platform/v2/x402/{endpoint}"])
        self.assertEqual(claims["exp"] - claims["nbf"], 120)
        self.assertLess(abs(claims["nbf"] - time.time()), 30)
        self.assertEqual(
            signature_b64,
            base64.urlsafe_b64encode(b"fake-ed25519-signature").rstrip(b"=").decode("ascii"),
        )
        self.assertIn(f"{header_b64}.{claims_b64}".encode("ascii"), self.fake_key.signed)
        return header

    def test_74_cdp_secondary_gets_a_fresh_request_bound_jwt(self) -> None:
        client = self._client({"CDP_API_KEY_ID": _CDP_KEY_ID, "CDP_API_KEY_SECRET": _CDP_SECRET})
        self.assertEqual(client.secondary_facilitator_url, COINBASE_CDP_FACILITATOR_URL)
        with patch(
            "urllib.request.urlopen",
            side_effect=[
                urllib.error.URLError("payai down"),
                _ok_response({"isValid": True}),
                urllib.error.URLError("payai down"),
                _ok_response({"success": True, "transaction": "0x" + "ab" * 32}),
            ],
        ) as mock_urlopen:
            client._post("verify", {})
            client._post("settle", {})
        sent = [c.args[0] for c in mock_urlopen.call_args_list]
        self.assertEqual(
            [r.full_url for r in sent],
            [
                f"{DEFAULT_FACILITATOR_URL}/verify",
                f"{COINBASE_CDP_FACILITATOR_URL}/verify",
                f"{DEFAULT_FACILITATOR_URL}/settle",
                f"{COINBASE_CDP_FACILITATOR_URL}/settle",
            ],
        )
        self.assertIsNone(sent[0].get_header("Authorization"))
        self.assertIsNone(sent[2].get_header("Authorization"))
        verify_header = self._assert_cdp_jwt(sent[1], "verify")
        settle_header = self._assert_cdp_jwt(sent[3], "settle")
        self.assertNotEqual(verify_header["nonce"], settle_header["nonce"])
        self.assertEqual(len(self.fake_key.signed), 2)

    def test_75_nothing_from_cdp_reaches_payai_or_non_coinbase_hosts(self) -> None:
        env = {"CDP_API_KEY_ID": _CDP_KEY_ID, "CDP_API_KEY_SECRET": _CDP_SECRET}
        non_coinbase_secondaries = (
            "https://x402.org/facilitator",
            "https://api.cdp.coinbase.com.evil.example/x402",
            "http://api.cdp.coinbase.com/platform/v2/x402",
        )
        for bearer, payai_auth in ((None, None), ("payai-token", "Bearer payai-token")):
            for secondary in non_coinbase_secondaries:
                with self.subTest(bearer=bearer, secondary=secondary):
                    client = self._client(env, bearer_token=bearer, secondary_facilitator_url=secondary)
                    with patch(
                        "urllib.request.urlopen",
                        side_effect=[
                            _ok_response({"isValid": True}),
                            urllib.error.URLError("payai down"),
                            _ok_response({"isValid": True}),
                        ],
                    ) as mock_urlopen:
                        client._post("verify", {"probe": 1})
                        client._post("verify", {"probe": 2})
                    sent = [c.args[0] for c in mock_urlopen.call_args_list]
                    self.assertEqual(
                        [r.full_url for r in sent],
                        [f"{DEFAULT_FACILITATOR_URL}/verify"] * 2 + [f"{secondary}/verify"],
                    )
                    self.assertEqual(
                        [r.get_header("Authorization") for r in sent], [payai_auth, payai_auth, None]
                    )
                    for r in sent:
                        wire = json.dumps(r.header_items()) + r.data.decode("utf-8")
                        self.assertNotIn(_CDP_KEY_ID, wire)
                        self.assertNotIn(_CDP_SECRET, wire)
        self.assertEqual(self.fake_key.signed, [])

    def test_76_payai_outage_fails_over_to_cdp_for_verify_and_settle(self) -> None:
        client = self._client({"CDP_API_KEY_ID": _CDP_KEY_ID, "CDP_API_KEY_SECRET": _CDP_SECRET})
        req_spec = {"scheme": "exact", "network": "base", "maxAmountRequired": "20000"}
        payment_header = json.dumps({
            "x402Version": 1,
            "scheme": "exact",
            "network": "base",
            "payload": {
                "authorization": {
                    "from": SAMPLE_PAYER,
                    "to": SAMPLE_PAY_TO,
                    "value": "20000",
                    "validAfter": "0",
                    "validBefore": str(int(time.time()) + 3600),
                    "nonce": "0x" + "cd" * 32,
                },
                "signature": "0x" + "a" * 130,
            },
        })
        tx = "0x" + "ef" * 32
        payai_503 = urllib.error.HTTPError(
            f"{DEFAULT_FACILITATOR_URL}/settle", 503, "Service Unavailable", None, None
        )
        self.addCleanup(payai_503.close)
        with patch(
            "urllib.request.urlopen",
            side_effect=[
                urllib.error.URLError("payai down"),
                _ok_response({"isValid": True, "payer": SAMPLE_PAYER}),
                payai_503,
                _ok_response({"success": True, "transaction": tx, "network": "base"}),
            ],
        ) as mock_urlopen:
            valid, err, details = client.verify(payment_header, req_spec)
            settled, tx_hash, settle_err = client.settle(payment_header, req_spec)
        self.assertEqual((valid, err), (True, None))
        self.assertTrue(details["isValid"])
        self.assertEqual((settled, tx_hash, settle_err), (True, tx, None))
        sent = [c.args[0] for c in mock_urlopen.call_args_list]
        self.assertEqual(
            [r.full_url for r in sent],
            [
                f"{DEFAULT_FACILITATOR_URL}/verify",
                f"{COINBASE_CDP_FACILITATOR_URL}/verify",
                f"{DEFAULT_FACILITATOR_URL}/settle",
                f"{COINBASE_CDP_FACILITATOR_URL}/settle",
            ],
        )
        self._assert_cdp_jwt(sent[1], "verify")
        self._assert_cdp_jwt(sent[3], "settle")
        self.assertEqual(sent[1].data, sent[0].data)
        self.assertEqual(sent[3].data, sent[2].data)

    def test_77_missing_or_unusable_cdp_credentials_send_no_authorization_and_warn(self) -> None:
        both = {"CDP_API_KEY_ID": _CDP_KEY_ID, "CDP_API_KEY_SECRET": _CDP_SECRET}
        cases = (
            ({"CDP_API_KEY_ID": _CDP_KEY_ID}, None, "CDP_API_KEY_SECRET not set"),
            ({"CDP_API_KEY_SECRET": _CDP_SECRET}, None, "CDP_API_KEY_ID not set"),
            ({"CDP_API_KEY": "legacy-cdp-key-sentinel"}, None, "CDP_API_KEY_ID and CDP_API_KEY_SECRET not set"),
            (both, ImportError("No module named 'cryptography'"), "the 'cryptography' package is not installed"),
            (
                both,
                ValueError(f"cannot parse {_CDP_SECRET}"),
                "CDP_API_KEY_SECRET is not a valid CDP Secret API key (ValueError)",
            ),
        )
        for env, loader_error, reason in cases:
            with self.subTest(reason=reason):
                client = self._client(env, loader_error=loader_error)
                with patch(
                    "urllib.request.urlopen",
                    side_effect=[urllib.error.URLError("payai down"), _ok_response({"isValid": True})],
                ) as mock_urlopen:
                    with self.assertLogs("omni_x402_prover.x402", level="WARNING") as logs:
                        client._post("verify", {})
                sent = [c.args[0] for c in mock_urlopen.call_args_list]
                self.assertEqual(sent[1].full_url, f"{COINBASE_CDP_FACILITATOR_URL}/verify")
                self.assertEqual([r.get_header("Authorization") for r in sent], [None, None])
                output = "\n".join(logs.output)
                self.assertIn(reason, output)
                for value in (_CDP_KEY_ID, _CDP_SECRET, "legacy-cdp-key-sentinel"):
                    self.assertNotIn(value, output)
                    for r in sent:
                        self.assertNotIn(value, json.dumps(r.header_items()))
        self.assertEqual(self.fake_key.signed, [])

    @unittest.skipUnless(_HAS_CRYPTOGRAPHY, "optional 'cryptography' package not installed")
    def test_78_real_cdp_key_formats_produce_verifiable_jwts(self) -> None:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        def ec_pem(curve: Any) -> Tuple[Any, str]:
            key = ec.generate_private_key(curve)
            pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            return key, pem.decode("ascii")

        ed_key = ed25519.Ed25519PrivateKey.generate()
        raw = serialization.Encoding.Raw
        ed_secret = base64.b64encode(
            ed_key.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            + ed_key.public_key().public_bytes(raw, serialization.PublicFormat.Raw)
        ).decode("ascii")
        es_key, es_pem = ec_pem(ec.SECP256R1())

        def verify_eddsa(signature: bytes, signing_input: bytes) -> None:
            ed_key.public_key().verify(signature, signing_input)

        def verify_es256(signature: bytes, signing_input: bytes) -> None:
            self.assertEqual(len(signature), 64)
            der = encode_dss_signature(
                int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            )
            es_key.public_key().verify(der, signing_input, ec.ECDSA(hashes.SHA256()))

        for secret, alg, verify_signature in (
            (ed_secret, "EdDSA", verify_eddsa),
            (es_pem.replace("\n", "\\n"), "ES256", verify_es256),
        ):
            with self.subTest(alg=alg):
                with patch.dict(os.environ, {"CDP_API_KEY_ID": _CDP_KEY_ID, "CDP_API_KEY_SECRET": secret}):
                    client = RemoteHTTPFacilitatorClient(facilitator_url=DEFAULT_FACILITATOR_URL)
                auth = client._headers_for_url(f"{COINBASE_CDP_FACILITATOR_URL}/settle")["Authorization"]
                header_b64, claims_b64, signature_b64 = auth[len("Bearer "):].split(".")
                self.assertEqual(_decode_jwt_segment(header_b64)["alg"], alg)
                self.assertEqual(
                    _decode_jwt_segment(claims_b64)["uris"],
                    ["POST api.cdp.coinbase.com/platform/v2/x402/settle"],
                )
                signature = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
                verify_signature(signature, f"{header_b64}.{claims_b64}".encode("ascii"))

        for bad_secret in (base64.b64encode(b"too-short").decode("ascii"), ec_pem(ec.SECP384R1())[1]):
            with self.assertRaises(ValueError):
                _load_cdp_private_key(bad_secret)


if __name__ == "__main__":
    unittest.main()
