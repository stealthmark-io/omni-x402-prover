"""
Unit and integration tests for Diamond Mine C1:
Streams Collateral Graph Detector (Yield-Stablecoin & Vault Circular Collateral Tarjan SCC,
Z3 Contagion & Solvency Shock Witness, and Curator Risk Leaderboard).

100% deterministic, offline test suite with zero external network dependencies.
"""

from __future__ import annotations

import base64
import html
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
import uuid
from http import HTTPStatus
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import pytest

from omni_x402_prover.http_server import create_http_server
from omni_x402_prover.prover_service import ProverService
from omni_x402_prover.x402_protocol import (
    DeterministicMockFacilitator,
    ReplayNonceStore,
    X402Config,
)
from omni_x402_prover.streams_collateral_detector import (
    OFFCHAIN_BLACKBOX_CUSTODY,
    SELECTOR_CURVE_COINS,
    SELECTOR_ERC20_DECIMALS,
    SELECTOR_ERC20_SYMBOL,
    SELECTOR_ERC20_TOTAL_SUPPLY,
    SELECTOR_ERC4626_ASSET,
    SELECTOR_ERC4626_TOTAL_ASSETS,
    SELECTOR_MORPHO,
    SELECTOR_MORPHO_WITHDRAW_QUEUE,
    SELECTOR_MORPHO_WITHDRAW_QUEUE_LEN,
    SELECTOR_PENDLE_SY,
    STREAMS_REDACTION_NOTICE,
    StreamsLeaderboard,
    analyze_collateral_streams,
    compute_insolvency_shock_witness,
    decode_address_from_hex,
    decode_string_from_hex,
    decode_uint256_from_hex,
    discover_collateral_graph,
    encode_uint256,
    get_global_streams_leaderboard,
    render_streams_badge_svg,
    render_streams_leaderboard_html,
    run_daily_streams_ranking_job,
    run_streams_demo,
    solve_linear_system,
    tarjan_scc,
    validate_evm_address,
)


def make_test_payment_header(
    config: X402Config,
    amount: int = 50000,
    to_address: Optional[str] = None,
    valid_before_offset: int = 3600,
    nonce: Optional[str] = None,
    payer: str = "0x1111111111111111111111111111111111111111",
    signature: str = "0x" + "a" * 130,
) -> str:
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
    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")


# ---------------------------------------------------------------------------
# Test Suite 1: EVM Address Validation & ABI Codec
# ---------------------------------------------------------------------------


class TestStreamsAddressAndCodec(unittest.TestCase):
    """Unit tests for EVM address validation and ABI word codec."""

    def test_validate_evm_address_valid(self):
        valid = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
        res = validate_evm_address(valid)
        self.assertEqual(res, valid.lower())

        mixed = "0x833589FCD6EDb6e08F4C7C32D4f71b54bda02913"
        self.assertEqual(validate_evm_address(mixed), valid.lower())

    def test_validate_evm_address_invalid(self):
        with self.assertRaises(ValueError):
            validate_evm_address("not_an_address")
        with self.assertRaises(ValueError):
            validate_evm_address("0x123")
        with self.assertRaises(ValueError):
            validate_evm_address("0x" + "0" * 40)  # Zero address rejected
        with self.assertRaises(ValueError):
            validate_evm_address(12345)  # Non-string

    def test_abi_codecs(self):
        encoded_0 = encode_uint256(0)
        self.assertEqual(encoded_0, "0" * 64)
        encoded_1 = encode_uint256(1)
        self.assertEqual(encoded_1, "0" * 63 + "1")

        addr = decode_address_from_hex("0x" + "0" * 24 + "833589fcd6edb6e08f4c7c32d4f71b54bda02913")
        self.assertEqual(addr, "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")
        self.assertIsNone(decode_address_from_hex("0x" + "0" * 64))

        val = decode_uint256_from_hex("0x" + hex(1000000)[2:].zfill(64))
        self.assertEqual(val, 1000000)

        sym = decode_string_from_hex("0x5553444300000000000000000000000000000000000000000000000000000000")
        self.assertEqual(sym, "USDC")


# ---------------------------------------------------------------------------
# Test Suite 2: On-Chain Collateral Graph Adapter (Mocked RPC)
# ---------------------------------------------------------------------------


class TestStreamsGraphAdapter(unittest.TestCase):
    """Unit tests for discover_collateral_graph with deterministic mocked RPC transport."""

    def test_unsupported_chain_rejected(self):
        with self.assertRaises(ValueError):
            discover_collateral_graph("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", chain="solana")

    def test_erc4626_pure_hard_reserve(self):
        vault_addr = "0x1234567890123456789012345678901234567890"
        usdc_addr = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"

        def mock_rpc(chain: str, payload: dict) -> dict:
            params = payload.get("params", [{}])[0]
            to = params.get("to", "").lower()
            data = params.get("data", "")

            if to == vault_addr:
                if data == SELECTOR_ERC20_SYMBOL:
                    return {"jsonrpc": "2.0", "id": 1, "result": "0x" + "USDC_VAULT".encode("utf-8").hex().ljust(64, "0")}
                if data == SELECTOR_ERC20_DECIMALS:
                    return {"jsonrpc": "2.0", "id": 1, "result": "0x" + hex(6)[2:].zfill(64)}
                if data == SELECTOR_ERC20_TOTAL_SUPPLY:
                    return {"jsonrpc": "2.0", "id": 1, "result": "0x" + hex(1000000)[2:].zfill(64)}
                if data == SELECTOR_ERC4626_ASSET:
                    return {"jsonrpc": "2.0", "id": 1, "result": "0x" + "0" * 24 + usdc_addr[2:]}
                if data == SELECTOR_ERC4626_TOTAL_ASSETS:
                    return {"jsonrpc": "2.0", "id": 1, "result": "0x" + hex(1000000)[2:].zfill(64)}
            return {"jsonrpc": "2.0", "id": 1, "result": "0x"}

        graph = discover_collateral_graph(vault_addr, chain="ethereum", rpc_transport=mock_rpc)
        self.assertEqual(graph["root_token"], vault_addr)
        self.assertIn(vault_addr, graph["nodes"])
        self.assertIn(usdc_addr, graph["nodes"])
        self.assertTrue(graph["nodes"][usdc_addr]["is_terminal"])
        self.assertEqual(len(graph["edges"]), 1)
        self.assertEqual(graph["edges"][0]["target"], usdc_addr)
        self.assertEqual(graph["edges"][0]["weight_bps"], 10000)

    def test_erc4626_with_unbacked_gap_emits_blackbox(self):
        vault_addr = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        usdc_addr = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"

        def mock_rpc(chain: str, payload: dict) -> dict:
            params = payload.get("params", [{}])[0]
            to = params.get("to", "").lower()
            data = params.get("data", "")

            if to == vault_addr:
                if data == SELECTOR_ERC20_TOTAL_SUPPLY:
                    return {"jsonrpc": "2.0", "id": 1, "result": "0x" + hex(1000000)[2:].zfill(64)}
                if data == SELECTOR_ERC4626_ASSET:
                    return {"jsonrpc": "2.0", "id": 1, "result": "0x" + "0" * 24 + usdc_addr[2:]}
                if data == SELECTOR_ERC4626_TOTAL_ASSETS:
                    # 70% assets backed, 30% unbacked gap (< 95%)
                    return {"jsonrpc": "2.0", "id": 1, "result": "0x" + hex(700000)[2:].zfill(64)}
            return {"jsonrpc": "2.0", "id": 1, "result": "0x"}

        graph = discover_collateral_graph(vault_addr, chain="ethereum", rpc_transport=mock_rpc)
        self.assertIn(OFFCHAIN_BLACKBOX_CUSTODY, graph["nodes"])
        self.assertTrue(graph["nodes"][OFFCHAIN_BLACKBOX_CUSTODY]["is_blackbox"])

        targets = {e["target"]: e["weight_bps"] for e in graph["edges"]}
        self.assertEqual(targets[usdc_addr], 7000)
        self.assertEqual(targets[OFFCHAIN_BLACKBOX_CUSTODY], 3000)

    def test_synthetic_token_without_onchain_reserve_emits_blackbox(self):
        synth_addr = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

        def mock_rpc(chain: str, payload: dict) -> dict:
            params = payload.get("params", [{}])[0]
            to = params.get("to", "").lower()
            data = params.get("data", "")
            if to == synth_addr:
                if data == SELECTOR_ERC20_SYMBOL:
                    return {"jsonrpc": "2.0", "id": 1, "result": "0x" + "SYNTH_YIELD".encode("utf-8").hex().ljust(64, "0")}
                if data == SELECTOR_ERC20_TOTAL_SUPPLY:
                    return {"jsonrpc": "2.0", "id": 1, "result": "0x" + hex(5000000)[2:].zfill(64)}
            return {"jsonrpc": "2.0", "id": 1, "result": "0x"}

        graph = discover_collateral_graph(synth_addr, chain="ethereum", rpc_transport=mock_rpc)
        self.assertIn(OFFCHAIN_BLACKBOX_CUSTODY, graph["nodes"])
        self.assertEqual(len(graph["edges"]), 1)
        self.assertEqual(graph["edges"][0]["target"], OFFCHAIN_BLACKBOX_CUSTODY)
        self.assertEqual(graph["edges"][0]["weight_bps"], 10000)

    def test_curve_and_pendle_probing(self):
        pool_addr = "0xcccccccccccccccccccccccccccccccccccccccc"
        coin0 = "0xdddddddddddddddddddddddddddddddddddddddd"
        coin1 = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

        def mock_rpc(chain: str, payload: dict) -> dict:
            params = payload.get("params", [{}])[0]
            to = params.get("to", "").lower()
            data = params.get("data", "")
            if to == pool_addr:
                if data == SELECTOR_CURVE_COINS + encode_uint256(0):
                    return {"jsonrpc": "2.0", "id": 1, "result": "0x" + "0" * 24 + coin0[2:]}
                if data == SELECTOR_CURVE_COINS + encode_uint256(1):
                    return {"jsonrpc": "2.0", "id": 1, "result": "0x" + "0" * 24 + coin1[2:]}
            return {"jsonrpc": "2.0", "id": 1, "result": "0x"}

        graph = discover_collateral_graph(pool_addr, chain="ethereum", max_depth=1, rpc_transport=mock_rpc)
        targets = [e["target"] for e in graph["edges"]]
        self.assertIn(coin0, targets)
        self.assertIn(coin1, targets)


# ---------------------------------------------------------------------------
# Test Suite 3: Tarjan Strongly Connected Components (SCC)
# ---------------------------------------------------------------------------


class TestTarjanSCC(unittest.TestCase):
    """Unit tests for Tarjan's SCC cycle detection."""

    def test_two_node_cycle(self):
        nodes = ["a", "b"]
        edges = [("a", "b", 10000), ("b", "a", 10000)]
        sccs = tarjan_scc(nodes, edges)
        self.assertEqual(len(sccs), 1)
        self.assertEqual(set(sccs[0]), {"a", "b"})

    def test_three_node_cycle(self):
        nodes = ["a", "b", "c"]
        edges = [("a", "b", 10000), ("b", "c", 10000), ("c", "a", 10000)]
        sccs = tarjan_scc(nodes, edges)
        self.assertEqual(len(sccs), 1)
        self.assertEqual(set(sccs[0]), {"a", "b", "c"})

    def test_self_loop(self):
        nodes = ["a", "b"]
        edges = [("a", "a", 10000), ("a", "b", 10000)]
        sccs = tarjan_scc(nodes, edges)
        self.assertEqual(len(sccs), 1)
        self.assertEqual(sccs[0], ["a"])

    def test_pure_dag_no_cycles(self):
        nodes = ["a", "b", "c", "d"]
        edges = [("a", "b", 10000), ("b", "c", 10000), ("c", "d", 10000)]
        sccs = tarjan_scc(nodes, edges)
        self.assertEqual(len(sccs), 0)

    def test_multiple_disjoint_cycles(self):
        nodes = ["a", "b", "c", "d"]
        edges = [("a", "b", 10000), ("b", "a", 10000), ("c", "d", 10000), ("d", "c", 10000)]
        sccs = tarjan_scc(nodes, edges)
        self.assertEqual(len(sccs), 2)


# ---------------------------------------------------------------------------
# Test Suite 4: Contagion Shock Witness & Z3 / Analytical Fallback
# ---------------------------------------------------------------------------


class TestContagionWitness(unittest.TestCase):
    """Unit tests for Z3 and exact analytical fixed-point contagion solvers."""

    def test_analytical_linear_system_solver(self):
        # Identity 2x2
        A = [[1.0, 0.0], [0.0, 1.0]]
        b = [3.0, 7.0]
        x = solve_linear_system(A, b)
        self.assertIsNotNone(x)
        self.assertAlmostEqual(x[0], 3.0)
        self.assertAlmostEqual(x[1], 7.0)

        # Singular matrix returns None
        A_sing = [[1.0, 1.0], [2.0, 2.0]]
        self.assertIsNone(solve_linear_system(A_sing, [1.0, 2.0]))

    def test_z3_and_analytical_parity_on_circular_stream(self):
        demo_res = run_streams_demo("xusd_deusd_circular")
        w_z3 = demo_res["z3_contagion_witness"]
        self.assertTrue(w_z3["is_vulnerable"])
        self.assertIsNotNone(w_z3["min_wipeout_haircut_pct"])
        self.assertAlmostEqual(w_z3["min_wipeout_haircut_pct"], 15.83, places=1)

        # Force analytical solver fallback
        fragile = set(demo_res["nodes"].keys())
        w_analytical = compute_insolvency_shock_witness(
            demo_res["root_token"],
            demo_res["nodes"],
            [(e["source"].lower(), e["target"].lower(), e["weight_bps"]) for e in demo_res["edges"]],
            fragile,
            use_z3=False,
        )
        self.assertEqual(w_analytical["solver"], "analytical_fixed_point")
        self.assertTrue(w_analytical["is_vulnerable"])
        self.assertAlmostEqual(w_analytical["min_wipeout_haircut_pct"], 15.83, places=1)

    def test_opaque_offchain_stream_contagion(self):
        demo_res = run_streams_demo("opaque_offchain_yield")
        w = demo_res["z3_contagion_witness"]
        self.assertTrue(w["is_vulnerable"])
        self.assertAlmostEqual(w["min_wipeout_haircut_pct"], 15.38, places=1)

    def test_clean_hard_backed_immunity(self):
        demo_res = run_streams_demo("clean_erc4626_usdc")
        w = demo_res["z3_contagion_witness"]
        self.assertFalse(w["is_vulnerable"])
        self.assertIsNone(w["min_wipeout_haircut_pct"])


# ---------------------------------------------------------------------------
# Test Suite 5: Built-in Demos & Classifications
# ---------------------------------------------------------------------------


class TestStreamsDemos(unittest.TestCase):
    """Unit tests for built-in deterministic demo topologies."""

    def test_demo_xusd_deusd_circular(self):
        res = run_streams_demo("xusd_deusd_circular")
        self.assertEqual(res["risk_classification"], "CIRCULAR_COLLATERAL_TRAP")
        self.assertEqual(res["grade"], "F")
        self.assertLessEqual(res["score"], 39)
        self.assertGreaterEqual(len(res["circular_scc_cycles"]), 1)
        self.assertGreaterEqual(len(res["blackbox_hops"]), 1)
        self.assertGreater(res["amplification_multiplier"], 1.0)
        self.assertEqual(res["effective_hard_backing_bps"], 2500)

    def test_demo_opaque_offchain_yield(self):
        res = run_streams_demo("opaque_offchain_yield")
        self.assertEqual(res["risk_classification"], "OPAQUE_OFFCHAIN_STREAM")
        self.assertEqual(res["grade"], "D")
        self.assertTrue(40 <= res["score"] <= 54)
        self.assertEqual(len(res["circular_scc_cycles"]), 0)
        self.assertEqual(len(res["blackbox_hops"]), 1)
        self.assertEqual(res["amplification_multiplier"], 1.0)
        self.assertEqual(res["effective_hard_backing_bps"], 3500)

    def test_demo_clean_erc4626_usdc(self):
        res = run_streams_demo("clean_erc4626_usdc")
        self.assertEqual(res["risk_classification"], "CLEAN_HARD_BACKED")
        self.assertEqual(res["grade"], "A+")
        self.assertGreaterEqual(res["score"], 95)
        self.assertEqual(len(res["circular_scc_cycles"]), 0)
        self.assertEqual(len(res["blackbox_hops"]), 0)
        self.assertEqual(res["amplification_multiplier"], 1.0)
        self.assertEqual(res["effective_hard_backing_bps"], 10000)

    def test_unknown_demo_raises(self):
        with self.assertRaises(ValueError):
            run_streams_demo("nonexistent_demo")


# ---------------------------------------------------------------------------
# Test Suite 6: SVG Badge & Leaderboard HTML Rendering
# ---------------------------------------------------------------------------


class TestRenderingAndEscaping(unittest.TestCase):
    """Unit tests for SVG badge generation and HTML dashboard rendering."""

    def test_svg_badge_xss_escaping(self):
        xss_payload = '<script>alert("xss")</script>'
        svg = render_streams_badge_svg(label=xss_payload, grade="F", score=10)
        self.assertIn("&lt;script&gt;", svg)
        self.assertNotIn("<script>", svg)
        self.assertIn("<svg", svg)
        self.assertIn("</svg>", svg)
        self.assertIn("#EF4444", svg)  # Grade F color

    def test_leaderboard_html_rendering(self):
        entries = [
            {
                "token_address": "0x1111111111111111111111111111111111110001",
                "symbol": "xUSD",
                "name": "Circular Stream xUSD",
                "chain": "ethereum",
                "grade": "F",
                "score": 10,
                "circular_scc_count": 1,
                "blackbox_hops_count": 1,
                "effective_hard_backing_bps": 2500,
                "amplification_multiplier": 4.0,
                "risk_classification": "CIRCULAR_COLLATERAL_TRAP",
            }
        ]
        html_out = render_streams_leaderboard_html(entries, base_url="http://127.0.0.1:8000")
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("Omni Streams", html_out)
        self.assertIn("xUSD", html_out)
        self.assertIn("1 Loop(s)", html_out)
        self.assertIn("25.0%", html_out)
        self.assertIn("$199/mo", html_out)


# ---------------------------------------------------------------------------
# Test Suite 7: SQLite Curator Leaderboard & Ranking Job
# ---------------------------------------------------------------------------


class TestStreamsLeaderboardStore(unittest.TestCase):
    """Unit tests for SQLite persistent leaderboard and ranking jobs."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_streams.db")

    def tearDown(self):
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
            os.rmdir(self.tmp_dir)
        except Exception:
            pass

    def test_sqlite_seeding_and_ranking(self):
        board = StreamsLeaderboard(db_path=self.db_path)
        ranked = board.get_ranked_entries()
        self.assertGreaterEqual(len(ranked), 4)

        # Verify benchmark entries exist
        symbols = [r["symbol"] for r in ranked]
        self.assertIn("sDAI", symbols)
        self.assertIn("gtUSDC", symbols)
        self.assertIn("xUSD", symbols)

        # Record a new entry
        new_analysis = {
            "token_address": "0x4444444444444444444444444444444444440004",
            "chain": "arbitrum",
            "risk_classification": "CLEAN_HARD_BACKED",
            "grade": "A+",
            "score": 99,
            "circular_scc_cycles": [],
            "blackbox_hops": [],
            "effective_hard_backing_bps": 10000,
            "amplification_multiplier": 1.0,
        }
        board.record_entry(new_analysis, symbol="arbUSDC", name="Arbitrum Native USDC Vault")
        entry = board.get_entry("0x4444444444444444444444444444444444440004")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["score"], 99)

        # Ranked list places score 99 first
        updated_ranked = board.get_ranked_entries()
        self.assertEqual(updated_ranked[0]["symbol"], "arbUSDC")

    def test_daily_ranking_job(self):
        ranked = run_daily_streams_ranking_job(db_path=self.db_path)
        self.assertIsInstance(ranked, list)
        self.assertGreaterEqual(len(ranked), 4)

    def test_readonly_fallback_to_memory(self):
        invalid_path = "/invalid_directory_that_cannot_exist/never_ever.db"
        board = StreamsLeaderboard(db_path=invalid_path)
        self.assertEqual(board.db_path, ":memory:")
        ranked = board.get_ranked_entries()
        self.assertGreaterEqual(len(ranked), 4)


# ---------------------------------------------------------------------------
# Test Suite 8: HTTP Server End-to-End Integration
# ---------------------------------------------------------------------------


class TestHTTPStreamsEndToEnd(unittest.TestCase):
    """End-to-end integration tests for free preview/badge/leaderboard & paid Mode C."""

    @classmethod
    def setUpClass(cls):
        cls.config = X402Config(pay_to_address="0x1111111111111111111111111111111111111111")
        cls.prover_service = ProverService(cls.config)
        cls.nonce_store = ReplayNonceStore(max_entries=100)
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
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=1.0)

    def test_get_streams_preview_missing_params(self):
        req = Request(f"{self.base_url}/x402/streams/preview")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req)
        self.assertEqual(ctx.exception.code, HTTPStatus.BAD_REQUEST)
        err = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("error", err)

    def test_get_streams_preview_demo_redacted(self):
        req = Request(f"{self.base_url}/x402/streams/preview?demo=xusd_deusd_circular")
        with urlopen(req) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "ok")
            self.assertEqual(data["risk_classification"], "CIRCULAR_COLLATERAL_TRAP")
            self.assertEqual(data["grade"], "F")
            self.assertEqual(data["circular_scc_count"], 1)
            self.assertEqual(data["circular_scc_cycles"], STREAMS_REDACTION_NOTICE)
            self.assertEqual(data["z3_contagion_witness"], STREAMS_REDACTION_NOTICE)
            self.assertIn("badge_svg_url", data)

    def test_get_streams_preview_error_is_generic_and_logged(self):
        secret = "internal detail /opt/omni/private-path"
        req = Request(f"{self.base_url}/x402/streams/preview?demo=xusd_deusd_circular")
        with patch(
            "omni_x402_prover.http_server.run_streams_demo",
            side_effect=RuntimeError(secret),
        ), self.assertLogs("omni_x402_prover.http", level="ERROR") as logs:
            with self.assertRaises(HTTPError) as ctx:
                urlopen(req)
        self.assertEqual(ctx.exception.code, HTTPStatus.INTERNAL_SERVER_ERROR)
        err = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertEqual(err, {"error": "Failed to compute streams preview"})
        self.assertEqual(str(logs.records[0].exc_info[1]), secret)

    def test_get_streams_badge_svg(self):
        req = Request(f"{self.base_url}/x402/streams/badge.svg?demo=clean_erc4626_usdc")
        with urlopen(req) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertEqual(resp.headers.get("Content-Type"), "image/svg+xml; charset=utf-8")
            svg_text = resp.read().decode("utf-8")
            self.assertIn("<svg", svg_text)
            self.assertIn("A+", svg_text)

    def test_get_streams_leaderboard_json_and_html(self):
        # JSON
        req_json = Request(f"{self.base_url}/x402/streams/leaderboard")
        with urlopen(req_json) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "ok")
            self.assertGreaterEqual(data["count"], 4)
            self.assertIn("b2b_offers", data)

        # HTML
        req_html = Request(f"{self.base_url}/x402/streams/leaderboard?format=html")
        with urlopen(req_html) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertEqual(resp.headers.get("Content-Type"), "text/html; charset=utf-8")
            html_text = resp.read().decode("utf-8")
            self.assertIn("<!DOCTYPE html>", html_text)
            self.assertIn("Omni Streams", html_text)

    def test_paid_post_mode_c_unpaid_returns_402(self):
        payload = json.dumps({"streams_demo": "xusd_deusd_circular"}).encode("utf-8")
        req = Request(
            f"{self.base_url}/x402/verify-forensic-graph",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req)
        self.assertEqual(ctx.exception.code, HTTPStatus.PAYMENT_REQUIRED)
        self.assertTrue(ctx.exception.headers.get("PAYMENT-REQUIRED"))

    def test_paid_post_mode_c_paid_returns_unredacted_cycles_and_witness(self):
        payment_header = make_test_payment_header(
            self.config,
            amount=self.config.price_forensic_graph_atomic,
        )
        payload = json.dumps({"streams_demo": "xusd_deusd_circular"}).encode("utf-8")
        req = Request(
            f"{self.base_url}/x402/verify-forensic-graph",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Payment": payment_header,
            },
        )
        with urlopen(req) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["mode"], "streams_circular_collateral_c1")
            self.assertFalse(data["verified"])  # Circular collateral trap is NOT verified safe
            self.assertEqual(data["risk_classification"], "CIRCULAR_COLLATERAL_TRAP")
            self.assertEqual(data["grade"], "F")

            # Must be full unredacted structures, NOT the redaction string!
            self.assertIsInstance(data["circular_scc_cycles"], list)
            self.assertGreaterEqual(len(data["circular_scc_cycles"]), 1)
            self.assertNotEqual(data["circular_scc_cycles"], STREAMS_REDACTION_NOTICE)

            self.assertIsInstance(data["z3_contagion_witness"], dict)
            self.assertNotEqual(data["z3_contagion_witness"], STREAMS_REDACTION_NOTICE)
            self.assertAlmostEqual(data["z3_contagion_witness"]["min_wipeout_haircut_pct"], 15.83, places=1)

    def test_paid_post_mode_c_clean_vault_verified_true(self):
        payment_header = make_test_payment_header(
            self.config,
            amount=self.config.price_forensic_graph_atomic,
        )
        payload = json.dumps({"streams_demo": "clean_erc4626_usdc"}).encode("utf-8")
        req = Request(
            f"{self.base_url}/x402/verify-forensic-graph",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Payment": payment_header,
            },
        )
        with urlopen(req) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["mode"], "streams_circular_collateral_c1")
            self.assertTrue(data["verified"])  # 100% hard backed is verified safe!
            self.assertEqual(data["grade"], "A+")


# ---------------------------------------------------------------------------
# Test Suite 9: Backward Compatibility of Mode A and Mode B
# ---------------------------------------------------------------------------


class TestForensicGraphModesAAndB(unittest.TestCase):
    """Verify Mode A (task) and Mode B (transactions + tainted_sources) remain 100% untouched."""

    def setUp(self):
        self.config = X402Config()
        self.prover = ProverService(self.config)

    def test_mode_b_direct_graph(self):
        payload = {
            "transactions": [
                {
                    "source": "0x1111111111111111111111111111111111111111",
                    "target": "0x2222222222222222222222222222222222222222",
                    "amount_usd": 50000.0,
                    "asset": "USDC",
                    "tx_type": "TRANSFER",
                    "timestamp": 1700000000,
                }
            ],
            "tainted_sources": ["0x1111111111111111111111111111111111111111"],
        }
        res = self.prover.verify_forensic_graph(payload)
        self.assertIn("verified", res)
        self.assertIn("mode", res)
        self.assertNotEqual(res["mode"], "streams_circular_collateral_c1")

    def test_mode_a_swarm_task(self):
        payload = {
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
        res = self.prover.verify_forensic_graph(payload)
        self.assertEqual(res["mode"], "swarm_task_v2")
