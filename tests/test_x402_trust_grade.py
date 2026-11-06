"""
Unit and integration tests for Diamond Mine C3:
x402 Trust Grade (Passive Seller Grader, Dynamic SVG Badge, Crawler & Leaderboard).

100% deterministic, offline test suite with zero external network dependencies.
"""

from __future__ import annotations

import base64
import html
import json
import os
import sqlite3
import threading
import time
import unittest
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
from omni_x402_prover.x402_trust_grade import (
    B2B_OFFERS,
    BASE_USDC_CONTRACT,
    GRADE_COLORS,
    REDACTION_NOTICE,
    SSRFSafeRedirectHandler,
    TrustGradeLeaderboard,
    build_seller_fix_pack,
    crawl_x402_directory,
    get_global_leaderboard,
    grade_demo_profile,
    passive_http_get,
    query_base_usdc_onchain,
    render_leaderboard_html,
    render_trust_grade_svg,
    score_x402_seller,
    validate_public_https_target,
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
    import uuid
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
# Test Suite 1: SSRF & Passive Transport Guard
# ---------------------------------------------------------------------------

class TestSSRFAndTransportGuard(unittest.TestCase):
    """Verifies strict SSRF prevention and safe passive transport properties."""

    def test_ssrf_rejects_empty_and_credentials(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            validate_public_https_target("")
        self.assertIn("non-empty string", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            validate_public_https_target("https://admin:secret@gateway.example.com")
        self.assertIn("credentials", str(ctx.exception))

    def test_ssrf_rejects_non_https_schemes(self) -> None:
        disallowed = [
            "http://gateway.example.com",
            "ftp://gateway.example.com",
            "file:///etc/passwd",
            "gopher://gateway.example.com",
            "data:text/plain;base64,SGVsbG8=",
        ]
        for u in disallowed:
            with self.assertRaises(ValueError):
                validate_public_https_target(u)

    def test_ssrf_rejects_loopback_and_private_ips(self) -> None:
        def mock_resolver(host, port, **kwargs):
            ip_map = {
                "127.0.0.1": "127.0.0.1",
                "localhost": "127.0.0.1",
                "internal.local": "10.0.0.5",
                "corp.vpn": "192.168.1.1",
                "metadata.cloud": "169.254.169.254",
                "ipv6.loopback": "::1",
                "ipv6.cloud": "fd20:ce::254",
            }
            ip = ip_map.get(host, host)
            return [(2, 1, 6, "", (ip, port))]

        disallowed_targets = [
            "https://127.0.0.1",
            "https://localhost",
            "https://internal.local",
            "https://corp.vpn",
            "https://metadata.cloud/latest/meta-data",
            "https://169.254.169.254/latest/meta-data",
            "https://ipv6.loopback",
            "https://ipv6.cloud",
        ]
        for target in disallowed_targets:
            with self.assertRaises(ValueError) as ctx:
                validate_public_https_target(target, allow_loopback_for_tests=False, resolver=mock_resolver)
            self.assertTrue("SSRF blocked" in str(ctx.exception) or "Invalid scheme" in str(ctx.exception))

    def test_ssrf_allows_loopback_only_when_explicitly_configured(self) -> None:
        def mock_resolver(host, port, **kwargs):
            return [(2, 1, 6, "", ("127.0.0.1", port))]

        # Denied when False
        with self.assertRaises(ValueError):
            validate_public_https_target("http://127.0.0.1:8402", allow_loopback_for_tests=False, resolver=mock_resolver)

        # Allowed when True
        res = validate_public_https_target(
            "http://127.0.0.1:8402", allow_loopback_for_tests=True, resolver=mock_resolver
        )
        self.assertEqual(res, "http://127.0.0.1:8402")

        res_lh = validate_public_https_target(
            "http://localhost:8402/x402", allow_loopback_for_tests=True, resolver=mock_resolver
        )
        self.assertEqual(res_lh, "http://localhost:8402/x402")

    def test_ssrf_redirect_handler_blocks_redirection_to_disallowed_target(self) -> None:
        handler = SSRFSafeRedirectHandler(allow_loopback_for_tests=False)
        req = Request("https://gateway.example.com")

        with self.assertRaises(ValueError) as ctx:
            handler.redirect_request(
                req=req,
                fp=None,
                code=302,
                msg="Found",
                headers={},
                newurl="http://127.0.0.1:8080/steal-creds",
            )
        self.assertIn("Invalid scheme", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            handler.redirect_request(
                req=req,
                fp=None,
                code=301,
                msg="Moved Permanently",
                headers={},
                newurl="https://169.254.169.254/latest/meta-data",
            )
        self.assertIn("SSRF blocked", str(ctx.exception))


# ---------------------------------------------------------------------------
# Test Suite 2: Passive Grading Dimensions & Cloudflare 1010 Detection
# ---------------------------------------------------------------------------

class TestPassiveGradingEngine(unittest.TestCase):
    """Tests the 6 passive scoring dimensions with injected transports."""

    def test_cloudflare_1010_detected_and_penalized(self) -> None:
        """
        Cloudflare Browser Integrity Check (Error 1010) on Python-urllib UA must be
        detected, penalized to 0 in agent_accessibility, and trigger WAF skip rule generation.
        """
        def mock_transport(url: str, headers: Dict[str, str], timeout: float) -> Tuple[int, Dict[str, str], bytes]:
            ua = headers.get("User-Agent", "")
            if "Python-urllib" in ua:
                return (
                    403,
                    {"server": "cloudflare", "cf-ray": "1234567890abcdef-EZE"},
                    b"<html><head><title>Access denied | error code: 1010</title></head>"
                    b"<body>Error code: 1010. The owner of this website has banned your access based on your browser's signature.</body></html>",
                )
            if "StealthMark" in ua:
                return (
                    200,
                    {
                        "access-control-allow-origin": "*",
                        "access-control-expose-headers": "PAYMENT-REQUIRED",
                    },
                    b'{"status": "ok"}',
                )
            return (404, {}, b"Not Found")

        def mock_resolver(host, port, **kwargs):
            return [(2, 1, 6, "", ("93.184.216.34", port))]

        result = score_x402_seller(
            "https://cf-blocked-seller.io/x402/service",
            http_transport=mock_transport,
            resolver=mock_resolver,
        )

        self.assertFalse(result["agent_accessible"])
        self.assertTrue(result["cf_1010_detected"])
        self.assertEqual(result["dimension_scores"]["agent_accessibility"], 0)

        codes = [f["code"] for f in result["findings"]]
        self.assertIn("CF_1010_BLOCKED", codes)

        fix_pack = build_seller_fix_pack(result, redacted=False)
        self.assertTrue(fix_pack["cloudflare_waf_fix"]["recommended"])
        self.assertIn("bic", fix_pack["cloudflare_waf_fix"]["api_payload"]["rules"][0]["action_parameters"]["products"])
        self.assertIn("curl -s -X POST", fix_pack["cloudflare_waf_fix"]["curl_command"])

    def test_perfect_a_plus_seller_scoring(self) -> None:
        """
        Reference A+ seller with TLS, Python-urllib 402 challenge, valid mcp.json,
        CORS exposed headers, and active Base USDC onchain settlement history.
        """
        def mock_transport(url: str, headers: Dict[str, str], timeout: float) -> Tuple[int, Dict[str, str], bytes]:
            if url.endswith("/.well-known/mcp.json"):
                return (
                    200,
                    {"content-type": "application/json"},
                    json.dumps({
                        "name": "omni-prover-service",
                        "repository": "https://github.com/stealthmark/omni-prover",
                        "tools": [{"name": "verify_invariant"}],
                    }).encode("utf-8"),
                )
            if url.endswith("/openapi.json"):
                return (200, {"content-type": "application/json"}, b'{"openapi": "3.1.0"}')

            challenge_header = json.dumps({
                "scheme": "exact",
                "network": "eip155:8453",
                "maxAmountRequired": "50000",
                "payTo": "0x1111111111111111111111111111111111111111",
                "asset": BASE_USDC_CONTRACT,
                "outputSchema": {"type": "object"},
            })

            return (
                402,
                {
                    "content-type": "application/json",
                    "access-control-allow-origin": "*",
                    "access-control-expose-headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE",
                    "payment-required": challenge_header,
                },
                json.dumps({
                    "accepts": [{
                        "network": "eip155:8453",
                        "payTo": "0x1111111111111111111111111111111111111111",
                        "maxAmountRequired": "50000",
                        "asset": BASE_USDC_CONTRACT,
                        "outputSchema": {"type": "object"},
                    }]
                }).encode("utf-8"),
            )

        def mock_rpc(payload: Dict[str, Any]) -> Dict[str, Any]:
            method = payload.get("method")
            if method == "eth_call":
                # Return balance of 10,000 USDC (0x2710 in units of 1e6)
                return {"result": "0x0000000000000000000000000000000000000000000000000000000000989680"}
            if method == "eth_blockNumber":
                return {"result": "0x1400000"}
            if method == "eth_getLogs":
                # 2 unique buyers
                return {
                    "result": [
                        {
                            "topics": [
                                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                                "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                "0x0000000000000000000000001111111111111111111111111111111111111111",
                            ]
                        },
                        {
                            "topics": [
                                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                                "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                "0x0000000000000000000000001111111111111111111111111111111111111111",
                            ]
                        },
                    ]
                }
            return {"result": None}

        def mock_resolver(host, port, **kwargs):
            return [(2, 1, 6, "", ("93.184.216.34", port))]

        res = score_x402_seller(
            "https://gateway.stealthmark.io/x402/verify",
            http_transport=mock_transport,
            rpc_transport=mock_rpc,
            resolver=mock_resolver,
        )

        self.assertGreaterEqual(res["score"], 90)
        self.assertIn(res["grade"], ("A", "A+"))
        self.assertTrue(res["agent_accessible"])
        self.assertFalse(res["cf_1010_detected"])
        self.assertEqual(res["dimension_scores"]["tls_and_headers"], 15)
        self.assertEqual(res["dimension_scores"]["agent_accessibility"], 20)
        self.assertEqual(res["dimension_scores"]["x402_challenge_schema"], 25)
        self.assertEqual(res["dimension_scores"]["mcp_and_discovery"], 15)
        self.assertEqual(res["dimension_scores"]["onchain_payto_history"], 15)

    def test_zero_address_and_missing_cors_penalized(self) -> None:
        """Zero address payTo and missing CORS must be penalized."""
        def mock_transport(url: str, headers: Dict[str, str], timeout: float) -> Tuple[int, Dict[str, str], bytes]:
            return (
                402,
                {"content-type": "application/json"},
                json.dumps({
                    "accepts": [{
                        "network": "eip155:8453",
                        "payTo": "0x0000000000000000000000000000000000000000",
                        "maxAmountRequired": "1000",
                    }]
                }).encode("utf-8"),
            )

        def mock_resolver(host, port, **kwargs):
            return [(2, 1, 6, "", ("93.184.216.34", port))]

        res = score_x402_seller(
            "https://bad-seller.io/x402",
            http_transport=mock_transport,
            resolver=mock_resolver,
        )

        codes = [f["code"] for f in res["findings"]]
        self.assertIn("PAYTO_ZERO_ADDRESS", codes)
        self.assertIn("CORS_ORIGIN_MISSING", codes)
        self.assertIn("CORS_EXPOSE_HEADERS_MISSING", codes)
        self.assertIn("MCP_MANIFEST_MISSING", codes)
        self.assertLess(res["score"], 70)

    def test_deterministic_demo_profiles(self) -> None:
        p_plus = grade_demo_profile("perfect_a_plus")
        self.assertEqual(p_plus["grade"], "A+")
        self.assertEqual(p_plus["score"], 98)
        self.assertTrue(p_plus["agent_accessible"])

        p_blocked = grade_demo_profile("cf_1010_blocked")
        self.assertIn(p_blocked["grade"], ("D", "F"))
        self.assertFalse(p_blocked["agent_accessible"])
        self.assertTrue(p_blocked["cf_1010_detected"])

        with self.assertRaises(ValueError):
            grade_demo_profile("unknown_random_demo")

    def test_root_origin_auto_probe_bazaar_resource(self) -> None:
        """
        When bare root https://seller.example is passed, score_x402_seller must
        read endpoints[0]['resource'] from /.well-known/x402-bazaar.json and probe
        THAT resource, avoiding false positives on root homepages.
        """
        probed_urls: List[str] = []

        def mock_transport(url: str, headers: Dict[str, str], timeout: float) -> Tuple[int, Dict[str, str], bytes]:
            probed_urls.append(url)
            if url.endswith("/.well-known/x402-bazaar.json"):
                return (
                    200,
                    {"content-type": "application/json"},
                    json.dumps({
                        "x402Version": 1,
                        "endpoints": [{
                            "resource": "https://seller.example/x402/verify-vault",
                            "network": "eip155:8453",
                            "payTo": "0x1111111111111111111111111111111111111111",
                            "priceAtomic": "20000",
                            "asset": BASE_USDC_CONTRACT,
                            "outputSchema": {"type": "object"},
                        }]
                    }).encode("utf-8"),
                )
            if url.endswith("/.well-known/mcp.json"):
                return (
                    200,
                    {"content-type": "application/json"},
                    json.dumps({
                        "name": "seller-service",
                        "repository": "https://github.com/example/seller",
                        "tools": [{"name": "verify"}],
                    }).encode("utf-8"),
                )
            if url.endswith("/x402/verify-vault"):
                return (
                    402,
                    {
                        "content-type": "application/json",
                        "access-control-allow-origin": "*",
                        "access-control-expose-headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE",
                    },
                    json.dumps({
                        "accepts": [{
                            "network": "eip155:8453",
                            "payTo": "0x1111111111111111111111111111111111111111",
                            "maxAmountRequired": "20000",
                            "asset": BASE_USDC_CONTRACT,
                            "outputSchema": {"type": "object"},
                        }]
                    }).encode("utf-8"),
                )
            if url.endswith("/openapi.json"):
                return (200, {}, b'{"openapi": "3.1.0"}')
            # If bare root '/' is hit, pretend it's a web HTML page without x402 headers
            return (200, {"content-type": "text/html"}, b"<html>Web Landing Page</html>")

        def mock_resolver(host, port, **kwargs):
            return [(2, 1, 6, "", ("93.184.216.34", port))]

        res = score_x402_seller(
            "https://seller.example",  # bare root
            http_transport=mock_transport,
            resolver=mock_resolver,
        )

        self.assertIn("https://seller.example/x402/verify-vault", probed_urls)
        self.assertTrue(res["agent_accessible"])
        self.assertEqual(res["dimension_scores"]["agent_accessibility"], 20)
        self.assertEqual(res["dimension_scores"]["tls_and_headers"], 15)
        self.assertEqual(res["dimension_scores"]["x402_challenge_schema"], 25)

    def test_root_origin_fallback_to_mcp_on_403(self) -> None:
        """
        When bare root returns 403 and no bazaar endpoints exist, but mcp.json is 200,
        it probes mcp.json as fallback without crashing.
        """
        def mock_transport(url: str, headers: Dict[str, str], timeout: float) -> Tuple[int, Dict[str, str], bytes]:
            if url.endswith("/.well-known/x402-bazaar.json"):
                return (404, {}, b"Not Found")
            if url.endswith("/.well-known/mcp.json"):
                return (
                    200,
                    {
                        "content-type": "application/json",
                        "access-control-allow-origin": "*",
                        "access-control-expose-headers": "PAYMENT-REQUIRED",
                    },
                    json.dumps({
                        "name": "mcp-only-service",
                        "repository": "https://github.com/example/mcp",
                        "tools": [],
                    }).encode("utf-8"),
                )
            if url == "https://mcp-fallback.io/":
                return (403, {}, b"Forbidden")
            return (404, {}, b"Not Found")

        def mock_resolver(host, port, **kwargs):
            return [(2, 1, 6, "", ("93.184.216.34", port))]

        res = score_x402_seller(
            "https://mcp-fallback.io",
            http_transport=mock_transport,
            resolver=mock_resolver,
        )
        self.assertTrue(res["agent_accessible"])

    def test_query_base_usdc_onchain_block_range_fallback(self) -> None:
        """
        Tests that query_base_usdc_onchain queries balanceOf and falls back block ranges.
        """
        call_counts = {"50k": 0, "9k5": 0}

        def mock_rpc(payload: Dict[str, Any]) -> Dict[str, Any]:
            method = payload.get("method")
            if method == "eth_call":
                return {"result": "0x00000000000000000000000000000000000000000000000000000000004c4b40"}
            if method == "eth_blockNumber":
                return {"result": "0x3300000"}
            if method == "eth_getLogs":
                return {
                    "result": [
                        {
                            "topics": [
                                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                                "0x000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                                "0x0000000000000000000000001111111111111111111111111111111111111111",
                            ]
                        }
                    ]
                }
            return {"result": None}

        onchain_res = query_base_usdc_onchain(
            "0x1111111111111111111111111111111111111111",
            rpc_transport=mock_rpc,
        )
        self.assertTrue(onchain_res["valid_address"])
        self.assertEqual(onchain_res["balance"], 5000000)
        self.assertEqual(onchain_res["unique_buyers"], 1)


# ---------------------------------------------------------------------------
# Test Suite 3: Fix Pack Redaction & Dynamic SVG XSS Safety
# ---------------------------------------------------------------------------

class TestFixPackAndSVGSafety(unittest.TestCase):
    """Tests fix pack redaction logic and SVG XSS neutralization."""

    def test_fix_pack_redaction_mode(self) -> None:
        demo = grade_demo_profile("cf_1010_blocked")

        # Redacted preview
        redacted = build_seller_fix_pack(demo, redacted=True)
        self.assertEqual(redacted["cloudflare_waf_fix"]["expression"], REDACTION_NOTICE)
        self.assertEqual(redacted["mcp_manifest_template"]["mcp_json"], REDACTION_NOTICE)
        self.assertEqual(redacted["cors_headers_snippet"]["fastapi_snippet"], REDACTION_NOTICE)
        self.assertEqual(redacted["x402_schema_fix"]["challenge_header_example"], REDACTION_NOTICE)

        # Unredacted paid pack
        unredacted = build_seller_fix_pack(demo, redacted=False)
        self.assertNotEqual(unredacted["cloudflare_waf_fix"]["expression"], REDACTION_NOTICE)
        self.assertIn("cf.threat_score", unredacted["cloudflare_waf_fix"]["expression"])
        self.assertIn("schemaVersion", unredacted["mcp_manifest_template"]["mcp_json"])
        self.assertIn("CORSMiddleware", unredacted["cors_headers_snippet"]["fastapi_snippet"])

    def test_svg_badge_xss_prevention(self) -> None:
        malicious_label = '<script>alert("xss")</script>'
        malicious_grade = '"><img src=x onerror=alert(1)>'

        svg = render_trust_grade_svg(label=malicious_label, grade=malicious_grade, score=99)

        self.assertTrue(svg.startswith('<svg xmlns="http://www.w3.org/2000/svg"'))
        self.assertTrue(svg.endswith("</svg>"))
        self.assertNotIn("<script>", svg)
        self.assertNotIn("<img", svg)
        self.assertIn("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;", svg)
        self.assertIn("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;", svg)

    def test_svg_badge_colors(self) -> None:
        svg_a = render_trust_grade_svg(grade="A+", score=98)
        self.assertIn(GRADE_COLORS["A+"], svg_a)

        svg_f = render_trust_grade_svg(grade="F", score=25)
        self.assertIn(GRADE_COLORS["F"], svg_f)


# ---------------------------------------------------------------------------
# Test Suite 4: Leaderboard Persistence & Directory Crawler
# ---------------------------------------------------------------------------

class TestLeaderboardAndCrawler(unittest.TestCase):
    """Tests SQLite persistence, :memory: fallback, and directory crawling."""

    def test_leaderboard_pre_seeds_and_upsert(self) -> None:
        board = TrustGradeLeaderboard(db_path=":memory:")
        entries = board.get_ranked_entries()
        domains = [e["domain"] for e in entries]

        self.assertIn("gateway.stealthmark.io", domains)
        self.assertIn("sentinel.oceaneye-ai.com", domains)

        # Upsert new domain
        board.upsert(
            domain="custom-agent.ai",
            seller_url="https://custom-agent.ai",
            grade="B",
            score=78,
            agent_accessible=True,
            cf_1010_detected=False,
            dimension_scores={"tls_and_headers": 15},
            findings_count=1,
        )

        entry = board.get_domain_entry("custom-agent.ai")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["grade"], "B")
        self.assertEqual(entry["score"], 78)

    def test_leaderboard_memory_fallback_on_unwritable_path(self) -> None:
        # Invalid directory path that cannot be written
        unwritable_path = "/dev/null/impossible_dir/leaderboard.db"
        board = TrustGradeLeaderboard(db_path=unwritable_path)
        self.assertTrue(board._is_memory)

        # Still operates normally in memory
        board.upsert(
            domain="fallback.io",
            seller_url="https://fallback.io",
            grade="A",
            score=88,
            agent_accessible=True,
            cf_1010_detected=False,
        )
        self.assertIsNotNone(board.get_domain_entry("fallback.io"))

    def test_leaderboard_env_default_path(self) -> None:
        import tempfile
        tmp_db = os.path.join(tempfile.gettempdir(), "test_omni_env_db.db")
        try:
            if os.path.exists(tmp_db):
                os.remove(tmp_db)
            with patch.dict(os.environ, {"OMNI_TRUST_DB_PATH": tmp_db}):
                board = TrustGradeLeaderboard()
                self.assertEqual(board.db_path, tmp_db)
                self.assertFalse(board._is_memory)
        finally:
            if os.path.exists(tmp_db):
                try:
                    os.remove(tmp_db)
                except Exception:
                    pass

    def test_render_leaderboard_html(self) -> None:
        board = TrustGradeLeaderboard(db_path=":memory:")
        entries = board.get_ranked_entries()
        html_out = render_leaderboard_html(entries, base_url="https://gateway.stealthmark.io")

        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("gateway.stealthmark.io", html_out)
        self.assertIn("$49 Audit &amp; Listing Fix", html_out)
        self.assertIn("$19/mo Badge &amp; Synthetic Monitor", html_out)
        self.assertIn("badge.svg?domain=gateway.stealthmark.io", html_out)

    def test_crawl_x402_directory_batch(self) -> None:
        board = TrustGradeLeaderboard(db_path=":memory:")

        def mock_transport(url: str, headers: Dict[str, str], timeout: float) -> Tuple[int, Dict[str, str], bytes]:
            return (
                200,
                {
                    "content-type": "application/json",
                    "access-control-allow-origin": "*",
                    "access-control-expose-headers": "PAYMENT-REQUIRED",
                },
                b'{"name": "test-seller"}',
            )

        entries = [
            "https://seller-one.com/x402",
            {"resource": "https://seller-two.com/verify"},
        ]

        with patch("omni_x402_prover.x402_trust_grade.validate_public_https_target", side_effect=lambda u, **kw: u):
            crawled = crawl_x402_directory(
                entries,
                leaderboard=board,
                http_transport=mock_transport,
            )

        self.assertEqual(len(crawled), 2)
        domains = [e["domain"] for e in board.get_ranked_entries()]
        self.assertIn("seller-one.com", domains)
        self.assertIn("seller-two.com", domains)


# ---------------------------------------------------------------------------
# Test Suite 5: End-to-End HTTP Server Integration
# ---------------------------------------------------------------------------

class TestHTTPTrustGradeEndToEnd(unittest.TestCase):
    """End-to-end tests against ephemeral ThreadingHTTPServer loopback."""

    @classmethod
    def setUpClass(cls) -> None:
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
    ) -> Tuple[int, Any, Dict[str, str]]:
        url = f"{self.base_url}{path}"
        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)

        body_bytes = json.dumps(data).encode("utf-8") if data is not None else None
        req = Request(url, data=body_bytes, headers=req_headers, method=method)

        try:
            with urlopen(req, timeout=5.0) as resp:
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                content_type = resp_headers.get("content-type", "")
                raw_body = resp.read()
                if "application/json" in content_type:
                    body = json.loads(raw_body.decode("utf-8"))
                else:
                    body = raw_body.decode("utf-8", errors="ignore")
                return resp.status, body, resp_headers
        except HTTPError as he:
            resp_headers = {k.lower(): v for k, v in he.headers.items()}
            raw_body = he.read()
            try:
                body = json.loads(raw_body.decode("utf-8"))
            except Exception:
                body = raw_body.decode("utf-8", errors="ignore")
            return he.code, body, resp_headers

    def test_preview_endpoint(self) -> None:
        # Missing parameters -> 400 Bad Request
        status, body, _ = self._http_request("GET", "/x402/trust-grade/preview")
        self.assertEqual(status, 400)
        self.assertIn("error", body)

        # SSRF forbidden URL -> 400 Bad Request
        status, body, _ = self._http_request("GET", "/x402/trust-grade/preview?url=http://127.0.0.1:8080")
        self.assertEqual(status, 400)
        status_bypass, body_bypass, _ = self._http_request("GET", "/x402/trust-grade/preview?url=http://127.0.0.1:8080&allow_loopback=1")
        self.assertEqual(status_bypass, 400)
        self.assertIn("Invalid target URL", body.get("error", ""))

        # Demo profile -> 200 OK with redacted fix_pack
        status, body, _ = self._http_request("GET", "/x402/trust-grade/preview?demo=cf_1010_blocked")
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ok")
        self.assertIn(body.get("grade"), ("D", "F"))
        self.assertEqual(body["fix_pack"]["cloudflare_waf_fix"]["expression"], REDACTION_NOTICE)
        self.assertIn(body.get("unlock_price"), ("$0.05 USDC",))

    def test_badge_svg_endpoint(self) -> None:
        status, body, headers = self._http_request("GET", "/x402/trust-grade/badge.svg?demo=perfect_a_plus")
        self.assertEqual(status, 200)
        self.assertIn("image/svg+xml", headers.get("content-type", ""))
        self.assertTrue(body.startswith('<svg xmlns="http://www.w3.org/2000/svg"'))
        self.assertIn("A+", body)

    def test_leaderboard_endpoints(self) -> None:
        # JSON format
        status, body, headers = self._http_request("GET", "/x402/trust-grade/leaderboard")
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ok")
        self.assertIsInstance(body.get("leaderboard"), list)
        self.assertGreaterEqual(body.get("count", 0), 2)

        # HTML format
        status, body, headers = self._http_request("GET", "/x402/trust-grade/leaderboard?format=html")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertIn("<!DOCTYPE html>", body)
        self.assertIn("x402 Trust Grade Leaderboard", body)

    def test_paid_dossier_unredacts_fix_pack(self) -> None:
        """
        POST /x402/verify-sar-ed25519-dossier with {'demo': 'cf_1010_blocked'}:
        Unpaid -> HTTP 402 challenge
        Paid via DeterministicMockFacilitator -> HTTP 200 with full unredacted fix_pack
        """
        route = "/x402/verify-sar-ed25519-dossier"
        req_payload = {"demo": "cf_1010_blocked"}

        # 1. Unpaid request -> 402
        status, body, headers = self._http_request("POST", route, data=req_payload)
        self.assertEqual(status, 402)
        self.assertIn("payment-required", headers)

        # 2. Paid request -> 200
        amt = self.config.price_sar_ed25519_atomic  # 50000
        payment_header = make_test_payment_header(self.config, amount=amt)

        status, body, headers = self._http_request(
            "POST",
            route,
            data=req_payload,
            headers={"X-PAYMENT": payment_header},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body.get("check_type"), "x402_trust_grade_dossier")
        self.assertTrue(body.get("ed25519_canonical_s_valid"))
        self.assertIn("dossier_sha256", body)
        self.assertIn("fix_pack", body)

        # Full fix pack must NOT be redacted
        fix_pack = body["fix_pack"]
        self.assertNotEqual(fix_pack["cloudflare_waf_fix"]["expression"], REDACTION_NOTICE)
        self.assertIn("cf.threat_score", fix_pack["cloudflare_waf_fix"]["expression"])
        self.assertIn("ruleset", fix_pack["cloudflare_waf_fix"]["curl_command"])
