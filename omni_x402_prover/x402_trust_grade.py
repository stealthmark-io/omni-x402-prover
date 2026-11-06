"""
x402 Trust Grade: Passive x402 & Model Context Protocol (MCP) Seller Grader,
Dynamic SVG Badge Generator, Directory Crawler, and Leaderboard Store.

Operates with zero external dependencies (100% Python 3.10+ standard library).
Evaluates 6 passive trust dimensions:
  1. tls_and_headers (15 pts)
  2. agent_accessibility (20 pts)
  3. x402_challenge_schema (25 pts)
  4. mcp_and_discovery (15 pts)
  5. onchain_payto_history (15 pts)
  6. latency_and_hygiene (10 pts)
Total: 0..100 -> Grade in {"A+", "A", "B", "C", "D", "F"}.
"""

from __future__ import annotations

import html
import ipaddress
import json
import logging
import os
import re
import socket
import sqlite3
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("omni_x402_prover.trust_grade")

# ---------------------------------------------------------------------------
# Constants & Defaults
# ---------------------------------------------------------------------------

DEFAULT_BASE_RPC_URL = "https://base-rpc.publicnode.com"
FALLBACK_BASE_RPC_URL = "https://mainnet.base.org"
BASE_USDC_CONTRACT = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
SELECTOR_BALANCE_OF = "0x70a08231"
TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

REDACTION_NOTICE = (
    "[REDACTED — Unlock full Fix Pack via POST /x402/verify-sar-ed25519-dossier "
    "($0.05 USDC) or $49 Listing & WAF Audit]"
)

INVALID_TARGET_MESSAGE = "Invalid target URL: only public https:// URLs are accepted"

B2B_OFFERS = [
    {
        "tier": "audit_and_fix",
        "name": "$49 Audit & Listing Fix",
        "price_usd": 49,
        "description": (
            "Full Cloudflare WAF unblocking (Skip BIC rule), MCP/Glama registry listing, "
            "and x402 v2 challenge remediation done for you."
        ),
        "contact_url": "https://stealthmark.io/pricing?service=fix49",
    },
    {
        "tier": "uptime_badge_monitor",
        "name": "$19/mo Badge & Uptime Monitor",
        "price_usd": 19,
        "billing": "monthly",
        "description": (
            "Continuous 5-minute agent synthetic probe, dynamic trust badge CDN, "
            "and instant Telegram/webhook alert on bot block."
        ),
        "contact_url": "https://stealthmark.io/pricing?service=monitor19",
    },
]

GRADE_COLORS = {
    "A+": "#10b981",
    "A": "#10b981",
    "B": "#3b82f6",
    "C": "#f59e0b",
    "D": "#f97316",
    "F": "#ef4444",
}

CLOUD_METADATA_IPS = {
    "169.254.169.254",
    "fd20:ce::254",
    "0.0.0.0",
}


# ---------------------------------------------------------------------------
# Strict SSRF & Target URL Guard
# ---------------------------------------------------------------------------

def validate_public_https_target(
    url: str,
    *,
    allow_loopback_for_tests: bool = False,
    resolver: Callable[..., List[Any]] = socket.getaddrinfo,
) -> str:
    """
    Strict SSRF guard:
    - Rejects empty URLs and credentials in URL (user:pass).
    - Requires 'https' scheme (or 'http://127.0.0.1:<port>' / 'http://localhost:<port>'
      ONLY when allow_loopback_for_tests=True).
    - Resolves all A/AAAA records via resolver and rejects private, loopback, link-local,
      multicast, unspecified, reserved, or cloud metadata IPs via ipaddress.ip_address.
    """
    if not url or not isinstance(url, str):
        raise ValueError("Target URL must be a non-empty string")

    clean_url = url.strip()
    parsed = urllib.parse.urlparse(clean_url)

    if parsed.username or parsed.password:
        raise ValueError("Target URL must not contain credentials (user:pass)")

    if allow_loopback_for_tests:
        if parsed.scheme not in ("https", "http"):
            raise ValueError(f"Invalid scheme '{parsed.scheme}': only HTTPS (or HTTP loopback for tests) allowed")
        if parsed.scheme == "http":
            host_check = (parsed.hostname or "").lower()
            if host_check not in ("127.0.0.1", "localhost", "::1"):
                raise ValueError("HTTP scheme is only permitted for 127.0.0.1 or localhost in test mode")
    else:
        if parsed.scheme != "https":
            raise ValueError(f"Invalid scheme '{parsed.scheme}': only HTTPS scheme is allowed")

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise ValueError("Target URL missing valid hostname")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        addr_infos = resolver(hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except Exception as exc:
        raise ValueError(f"DNS resolution failed for hostname '{hostname}': {exc}") from exc

    if not addr_infos:
        raise ValueError(f"No IP addresses resolved for hostname '{hostname}'")

    for addr in addr_infos:
        sockaddr = addr[4]
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as ip_exc:
            raise ValueError(f"Resolved host returned invalid IP address: '{ip_str}'") from ip_exc

        if allow_loopback_for_tests and (ip.is_loopback or ip_str in ("127.0.0.1", "::1", "localhost")):
            continue

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
            or ip_str in CLOUD_METADATA_IPS
            or str(ip).startswith("169.254.")
        ):
            raise ValueError(
                f"SSRF blocked: target host '{hostname}' resolved to disallowed network address {ip_str}"
            )

    return clean_url


class SSRFSafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Custom HTTP redirect handler that validates target URL of every redirect."""

    def __init__(
        self,
        allow_loopback_for_tests: bool = False,
        resolver: Callable[..., List[Any]] = socket.getaddrinfo,
    ) -> None:
        super().__init__()
        self.allow_loopback_for_tests = allow_loopback_for_tests
        self.resolver = resolver

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        validate_public_https_target(
            newurl,
            allow_loopback_for_tests=self.allow_loopback_for_tests,
            resolver=self.resolver,
        )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# ---------------------------------------------------------------------------
# Passive HTTP Transport
# ---------------------------------------------------------------------------

def passive_http_get(
    url: str,
    *,
    user_agent: Optional[str] = None,
    timeout: float = 5.0,
    allow_loopback_for_tests: bool = False,
    http_transport: Optional[Callable[..., Any]] = None,
    resolver: Callable[..., List[Any]] = socket.getaddrinfo,
) -> Dict[str, Any]:
    """
    Performs a 100% passive HTTP GET request with SSRF validation,
    capped body read (65536 bytes), and safe redirect handling.
    """
    validate_public_https_target(
        url,
        allow_loopback_for_tests=allow_loopback_for_tests,
        resolver=resolver,
    )

    ua = user_agent or "Python-urllib/3.12"

    if http_transport is not None:
        start_t = time.perf_counter()
        res = http_transport(url, headers={"User-Agent": ua}, timeout=timeout)
        duration_ms = (time.perf_counter() - start_t) * 1000.0

        if isinstance(res, dict):
            status = int(res.get("status_code", 200))
            headers = {k.lower(): str(v) for k, v in res.get("headers", {}).items()}
            raw_body = res.get("body", b"")
            body = raw_body if isinstance(raw_body, bytes) else str(raw_body).encode("utf-8")
            latency = float(res.get("latency_ms", duration_ms))
        elif isinstance(res, (tuple, list)) and len(res) >= 3:
            status = int(res[0])
            headers = {k.lower(): str(v) for k, v in res[1].items()}
            raw_body = res[2]
            body = raw_body if isinstance(raw_body, bytes) else str(raw_body).encode("utf-8")
            latency = duration_ms
        else:
            status = getattr(res, "status", getattr(res, "status_code", 200))
            res_headers = getattr(res, "headers", {})
            headers = {k.lower(): str(v) for k, v in dict(res_headers).items()}
            raw_body = getattr(res, "body", b"")
            if callable(getattr(res, "read", None)):
                raw_body = res.read(65536)
            body = raw_body if isinstance(raw_body, bytes) else str(raw_body).encode("utf-8")
            latency = duration_ms

        return {
            "status_code": status,
            "headers": headers,
            "body": body[:65536],
            "latency_ms": latency,
            "url": url,
        }

    # Standard urllib transport
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": ua,
            "Accept": "*/*",
        },
        method="GET",
    )
    redirect_handler = SSRFSafeRedirectHandler(
        allow_loopback_for_tests=allow_loopback_for_tests,
        resolver=resolver,
    )
    opener = urllib.request.build_opener(redirect_handler)

    start_t = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(65536)
            status = resp.status
            headers = {k.lower(): str(v) for k, v in resp.headers.items()}
    except urllib.error.HTTPError as he:
        body = he.read(65536) if hasattr(he, "read") else b""
        status = he.code
        headers = {k.lower(): str(v) for k, v in he.headers.items()} if hasattr(he, "headers") else {}
    except Exception as exc:
        duration_ms = (time.perf_counter() - start_t) * 1000.0
        return {
            "status_code": 0,
            "headers": {},
            "body": str(exc).encode("utf-8"),
            "latency_ms": duration_ms,
            "url": url,
            "error": str(exc),
        }

    duration_ms = (time.perf_counter() - start_t) * 1000.0
    return {
        "status_code": status,
        "headers": headers,
        "body": body[:65536],
        "latency_ms": duration_ms,
        "url": url,
    }


# ---------------------------------------------------------------------------
# Read-Only Base JSON-RPC Helper
# ---------------------------------------------------------------------------

def query_base_usdc_onchain(
    pay_to_address: str,
    *,
    rpc_transport: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    rpc_url: str = DEFAULT_BASE_RPC_URL,
    timeout: float = 3.5,
) -> Dict[str, Any]:
    """
    Read-only query to Base mainnet Base USDC contract:
    - balanceOf(payTo) via eth_call
    - Recent Transfer logs via eth_getLogs with fallback block ranges & RPC endpoints
    """
    clean_addr = (pay_to_address or "").strip().lower()
    if not clean_addr.startswith("0x") or len(clean_addr) != 42 or clean_addr == "0x" + "0" * 40:
        return {
            "balance": 0,
            "transfer_count": 0,
            "unique_buyers": 0,
            "valid_address": False,
        }

    addr_padded = "000000000000000000000000" + clean_addr[2:]
    call_data = SELECTOR_BALANCE_OF + addr_padded

    def _do_rpc(method: str, params: list, target_url: str = rpc_url) -> Optional[Any]:
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        if rpc_transport is not None:
            res = rpc_transport(payload)
            return res.get("result")

        urls_to_try = [target_url]
        if target_url != FALLBACK_BASE_RPC_URL:
            urls_to_try.append(FALLBACK_BASE_RPC_URL)
        elif target_url != DEFAULT_BASE_RPC_URL:
            urls_to_try.append(DEFAULT_BASE_RPC_URL)

        req_body = json.dumps(payload).encode("utf-8")
        for try_url in urls_to_try:
            req = urllib.request.Request(
                try_url,
                data=req_body,
                headers={"Content-Type": "application/json", "User-Agent": "StealthMark-TrustGrade/1.0"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read(65536).decode("utf-8"))
                    if "result" in data:
                        return data.get("result")
                    if "error" in data:
                        logger.debug("RPC query %s to %s returned error: %s", method, try_url, data["error"])
            except Exception as exc:
                logger.debug("RPC query %s to %s failed: %s", method, try_url, exc)
        return None

    # Query 1: balanceOf
    raw_bal = _do_rpc("eth_call", [{"to": BASE_USDC_CONTRACT, "data": call_data}, "latest"])
    balance = 0
    if raw_bal and isinstance(raw_bal, str) and raw_bal.startswith("0x"):
        try:
            balance = int(raw_bal, 16)
        except ValueError:
            balance = 0

    # Query 2: recent Transfer logs to payTo
    topic2 = "0x" + addr_padded
    block_num_hex = _do_rpc("eth_blockNumber", [])
    curr_block = 0
    if block_num_hex and isinstance(block_num_hex, str) and block_num_hex.startswith("0x"):
        try:
            curr_block = int(block_num_hex, 16)
        except ValueError:
            curr_block = 0

    # First try 50,000 blocks
    from_block_50k = hex(max(0, curr_block - 50_000)) if curr_block > 0 else "latest"
    logs = _do_rpc(
        "eth_getLogs",
        [
            {
                "address": BASE_USDC_CONTRACT,
                "topics": [TOPIC_TRANSFER, None, topic2],
                "fromBlock": from_block_50k,
                "toBlock": "latest",
            }
        ],
    )

    # If 50,000 blocks failed or returned None, retry on publicnode or with 9,500 blocks
    if logs is None and rpc_transport is None and curr_block > 0:
        if rpc_url != "https://base-rpc.publicnode.com":
            logs = _do_rpc(
                "eth_getLogs",
                [
                    {
                        "address": BASE_USDC_CONTRACT,
                        "topics": [TOPIC_TRANSFER, None, topic2],
                        "fromBlock": from_block_50k,
                        "toBlock": "latest",
                    }
                ],
                target_url="https://base-rpc.publicnode.com",
            )

        if logs is None:
            from_block_9500 = hex(max(0, curr_block - 9_500))
            logs = _do_rpc(
                "eth_getLogs",
                [
                    {
                        "address": BASE_USDC_CONTRACT,
                        "topics": [TOPIC_TRANSFER, None, topic2],
                        "fromBlock": from_block_9500,
                        "toBlock": "latest",
                    }
                ],
                target_url=rpc_url,
            )
            if logs is None and rpc_url != "https://base-rpc.publicnode.com":
                logs = _do_rpc(
                    "eth_getLogs",
                    [
                        {
                            "address": BASE_USDC_CONTRACT,
                            "topics": [TOPIC_TRANSFER, None, topic2],
                            "fromBlock": from_block_9500,
                            "toBlock": "latest",
                        }
                    ],
                    target_url="https://base-rpc.publicnode.com",
                )

    transfer_count = 0
    unique_buyers = set()
    if isinstance(logs, list):
        transfer_count = len(logs)
        for log in logs:
            topics = log.get("topics", [])
            if len(topics) >= 2:
                from_topic = topics[1]
                if isinstance(from_topic, str) and len(from_topic) >= 26:
                    unique_buyers.add(from_topic[-40:].lower())

    return {
        "balance": balance,
        "transfer_count": transfer_count,
        "unique_buyers": len(unique_buyers),
        "valid_address": True,
    }


# ---------------------------------------------------------------------------
# 6 Passive Grading Dimensions Engine
# ---------------------------------------------------------------------------

def score_x402_seller(
    target_url: str,
    *,
    allow_loopback_for_tests: bool = False,
    http_transport: Optional[Callable[..., Any]] = None,
    rpc_transport: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    resolver: Callable[..., List[Any]] = socket.getaddrinfo,
) -> Dict[str, Any]:
    """
    Passively grades an x402 / MCP seller across 6 dimensions:
      1. tls_and_headers (15 pts)
      2. agent_accessibility (20 pts)
      3. x402_challenge_schema (25 pts)
      4. mcp_and_discovery (15 pts)
      5. onchain_payto_history (15 pts)
      6. latency_and_hygiene (10 pts)
    Total score: 0..100 -> Grade in {"A+", "A", "B", "C", "D", "F"}.
    """
    validated_url = validate_public_https_target(
        target_url,
        allow_loopback_for_tests=allow_loopback_for_tests,
        resolver=resolver,
    )
    parsed = urllib.parse.urlparse(validated_url)
    domain = (parsed.hostname or "").lower()
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    findings: List[Dict[str, Any]] = []
    latencies: List[float] = []
    has_5xx = False

    def _fetch(url: str, ua: str) -> Dict[str, Any]:
        nonlocal has_5xx
        res = passive_http_get(
            url,
            user_agent=ua,
            allow_loopback_for_tests=allow_loopback_for_tests,
            http_transport=http_transport,
            resolver=resolver,
        )
        lat = res.get("latency_ms", 0.0)
        if lat > 0:
            latencies.append(lat)
        if res.get("status_code", 0) >= 500:
            has_5xx = True
        return res

    # Probes:
    # Probe 1 & 2: Bazaar catalog /.well-known/x402-bazaar.json and MCP /.well-known/mcp.json FIRST
    probe_bazaar = _fetch(f"{base_origin}/.well-known/x402-bazaar.json", "StealthMark-TrustGrade/1.0")
    probe_mcp = _fetch(f"{base_origin}/.well-known/mcp.json", "StealthMark-TrustGrade/1.0")

    bazaar_payload = None
    if probe_bazaar.get("status_code") == 200:
        try:
            bazaar_payload = json.loads(probe_bazaar.get("body", b"").decode("utf-8"))
        except Exception:
            pass

    # Resolve target resource URL to probe
    target_resource_url = validated_url
    resolved_resource = None

    if parsed.path in ("", "/"):
        if (
            bazaar_payload
            and isinstance(bazaar_payload.get("endpoints"), list)
            and len(bazaar_payload["endpoints"]) > 0
        ):
            ep0 = bazaar_payload["endpoints"][0]
            raw_res = ep0.get("resource") or ""
            if raw_res:
                if raw_res.startswith("http://") or raw_res.startswith("https://"):
                    res_parsed = urllib.parse.urlparse(raw_res)
                    clean_path = res_parsed.path or ""
                    if clean_path:
                        resolved_resource = f"{base_origin}{clean_path}"
                elif raw_res.startswith("/"):
                    resolved_resource = f"{base_origin}{raw_res}"

        if resolved_resource:
            target_resource_url = resolved_resource

    # Probe target resource with standard Python SDK UA and StealthMark UA
    probe_urllib = _fetch(target_resource_url, "Python-urllib/3.12")
    probe_stealth = _fetch(target_resource_url, "StealthMark-TrustGrade/1.0 (+https://gateway.stealthmark.io)")

    # Fallback to /.well-known/mcp.json if no bazaar endpoint exists and / returns 403 or 404
    if parsed.path in ("", "/") and not resolved_resource and probe_urllib.get("status_code") in (403, 404):
        if probe_mcp.get("status_code") == 200:
            target_resource_url = f"{base_origin}/.well-known/mcp.json"
            probe_urllib = _fetch(target_resource_url, "Python-urllib/3.12")
            probe_stealth = _fetch(target_resource_url, "StealthMark-TrustGrade/1.0 (+https://gateway.stealthmark.io)")

    # Discovery Probes: OpenAPI or llms.txt
    probe_openapi = _fetch(f"{base_origin}/openapi.json", "StealthMark-TrustGrade/1.0")
    probe_llms = (
        _fetch(f"{base_origin}/llms.txt", "StealthMark-TrustGrade/1.0")
        if probe_openapi.get("status_code") != 200
        else {"status_code": 404}
    )

    # -----------------------------------------------------------------------
    # Dimension 1: tls_and_headers (15 pts)
    # -----------------------------------------------------------------------
    score_tls = 0
    if parsed.scheme == "https":
        score_tls += 5

    # Check CORS from probes
    headers = dict(probe_bazaar.get("headers", {}))
    headers.update(probe_mcp.get("headers", {}))
    headers.update(probe_urllib.get("headers", {}))
    headers.update(probe_stealth.get("headers", {}))

    allow_origin = headers.get("access-control-allow-origin", "")
    if allow_origin:
        score_tls += 5
    else:
        findings.append({
            "code": "CORS_ORIGIN_MISSING",
            "severity": "HIGH",
            "title": "Missing Access-Control-Allow-Origin Header",
            "summary": "Target does not return Access-Control-Allow-Origin, blocking browser-based AI agents and web dApps.",
        })

    expose_headers = headers.get("access-control-expose-headers", "").upper()
    x402_exposed = any(h in expose_headers for h in ("PAYMENT-REQUIRED", "PAYMENT-RESPONSE", "X-PAYMENT-RESPONSE"))
    if x402_exposed:
        score_tls += 5
    else:
        findings.append({
            "code": "CORS_EXPOSE_HEADERS_MISSING",
            "severity": "HIGH",
            "title": "Missing Access-Control-Expose-Headers for x402",
            "summary": (
                "Access-Control-Expose-Headers does not expose PAYMENT-REQUIRED or PAYMENT-RESPONSE, "
                "preventing SDK buyers from reading 402 challenge parameters."
            ),
        })

    # -----------------------------------------------------------------------
    # Dimension 2: agent_accessibility (20 pts)
    # -----------------------------------------------------------------------
    score_agent = 20
    cf_1010_detected = False
    agent_accessible = True

    status_urllib = probe_urllib.get("status_code", 0)
    body_urllib = probe_urllib.get("body", b"").decode("utf-8", errors="ignore").lower()
    status_stealth = probe_stealth.get("status_code", 0)

    # Cloudflare Browser Integrity Check (Error 1010) check
    if status_urllib == 403 and ("1010" in body_urllib or "browser integrity check" in body_urllib or "error code: 1010" in body_urllib):
        cf_1010_detected = True
        agent_accessible = False
        score_agent = 0
        findings.append({
            "code": "CF_1010_BLOCKED",
            "severity": "CRITICAL",
            "title": "Cloudflare Browser Integrity Check (Error 1010) Blocks AI Agents",
            "summary": (
                "Probe with standard Python-urllib received HTTP 403 (Error 1010: Browser Integrity Check). "
                "Autonomous agents and SDK buyers cannot purchase from this seller without a WAF bypass rule."
            ),
        })
    elif status_urllib == 403 and status_stealth in (200, 402):
        agent_accessible = False
        score_agent = 5
        findings.append({
            "code": "BOT_BLOCKED",
            "severity": "HIGH",
            "title": "Automated Agent Runtime Blocked",
            "summary": (
                "Target returned HTTP 403 to Python-urllib UA while crawler UA succeeded. "
                "Standard Python/Node SDK clients will fail to connect."
            ),
        })
    elif status_urllib == 403:
        agent_accessible = False
        score_agent = 5
        findings.append({
            "code": "HTTP_403_FORBIDDEN",
            "severity": "HIGH",
            "title": "Target Returned HTTP 403 Forbidden",
            "summary": "Target endpoint rejected agent connection probe with HTTP 403 Forbidden.",
        })

    # -----------------------------------------------------------------------
    # Dimension 3: x402_challenge_schema (25 pts)
    # -----------------------------------------------------------------------
    score_challenge = 0
    discovered_pay_to = ""
    discovered_network = ""
    discovered_asset = ""
    discovered_amount = 0
    has_valid_accepts = False
    has_output_schema = False

    # Check 1: probe 402 response from probe_urllib or probe_stealth
    active_challenge_probe = probe_urllib if probe_urllib.get("status_code") == 402 else probe_stealth
    challenge_payload = None

    if active_challenge_probe.get("status_code") == 402:
        try:
            challenge_payload = json.loads(active_challenge_probe.get("body", b"").decode("utf-8"))
        except Exception:
            pass

        # Also inspect PAYMENT-REQUIRED header
        h_req = active_challenge_probe.get("headers", {}).get("payment-required")
        if h_req and not challenge_payload:
            try:
                challenge_payload = json.loads(h_req)
            except Exception:
                pass

    # Check 2: Bazaar manifest probe (if not already parsed)
    if not bazaar_payload and probe_bazaar.get("status_code") == 200:
        try:
            bazaar_payload = json.loads(probe_bazaar.get("body", b"").decode("utf-8"))
        except Exception:
            pass

    # Extract requirement candidate
    candidate_req = None
    if challenge_payload:
        accepts = challenge_payload.get("accepts", [])
        if isinstance(accepts, list) and len(accepts) > 0:
            candidate_req = accepts[0]
            has_valid_accepts = True
        elif isinstance(challenge_payload.get("payload"), dict):
            candidate_req = challenge_payload.get("payload")
            has_valid_accepts = True
        elif challenge_payload.get("network") and challenge_payload.get("payTo"):
            candidate_req = challenge_payload
            has_valid_accepts = True

    if not candidate_req and bazaar_payload:
        endpoints = bazaar_payload.get("endpoints", [])
        if isinstance(endpoints, list) and len(endpoints) > 0:
            has_valid_accepts = True
            ep0 = endpoints[0]
            prov = bazaar_payload.get("provider", {})
            candidate_req = {
                "network": ep0.get("network") or prov.get("network"),
                "payTo": ep0.get("payTo") or prov.get("payTo"),
                "maxAmountRequired": ep0.get("priceAtomic") or ep0.get("maxAmountRequired"),
                "asset": ep0.get("asset") or prov.get("asset"),
                "outputSchema": ep0.get("outputSchema"),
            }

    if has_valid_accepts:
        score_challenge += 5
    else:
        findings.append({
            "code": "X402_CHALLENGE_MISSING",
            "severity": "HIGH",
            "title": "Missing x402 Challenge or Bazaar Manifest",
            "summary": "Target does not serve HTTP 402 challenge with accepts[] or /.well-known/x402-bazaar.json.",
        })

    if candidate_req:
        discovered_network = str(candidate_req.get("network", "")).strip().lower()
        discovered_pay_to = str(candidate_req.get("payTo", "")).strip()
        discovered_asset = str(candidate_req.get("asset", "")).strip().lower()
        raw_amt = candidate_req.get("maxAmountRequired") or candidate_req.get("priceAtomic") or 0
        try:
            discovered_amount = int(raw_amt)
        except (ValueError, TypeError):
            discovered_amount = 0

        # CAIP-2 network check (eip155:8453, eip155:84532, or solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp)
        if discovered_network in ("eip155:8453", "base", "eip155:84532", "solana:5eykt4usfv8p8njdtrepy1vzqkqzkvdp"):
            score_challenge += 5
        else:
            findings.append({
                "code": "X402_INVALID_NETWORK",
                "severity": "MEDIUM",
                "title": "Invalid or Unsupported CAIP-2 Network",
                "summary": f"Target declared network '{discovered_network}'. Recommended: 'eip155:8453' (Base).",
            })

        # Non-zero payTo address check
        if discovered_pay_to and discovered_pay_to.lower() not in ("0x0", "0x" + "0" * 40, ""):
            score_challenge += 5
        else:
            findings.append({
                "code": "PAYTO_ZERO_ADDRESS",
                "severity": "HIGH",
                "title": "Zero or Invalid payTo Address",
                "summary": "payTo address is missing or set to the zero/burn address (0x000...000).",
            })

        # Positive price / maxAmountRequired
        if discovered_amount > 0:
            score_challenge += 4
        else:
            findings.append({
                "code": "PRICE_ATOMIC_ZERO",
                "severity": "LOW",
                "title": "Zero or Non-Integer Price",
                "summary": "Challenge maxAmountRequired or priceAtomic is not a positive integer.",
            })

        # Base USDC asset check
        if discovered_asset in (BASE_USDC_CONTRACT, "usdc", "usdc.e"):
            score_challenge += 3
        else:
            findings.append({
                "code": "ASSET_NON_STANDARD",
                "severity": "LOW",
                "title": "Non-Standard Settlement Asset",
                "summary": f"Asset '{discovered_asset}' does not match standard Base USDC contract ({BASE_USDC_CONTRACT}).",
            })

        # outputSchema / discoverable check
        if candidate_req.get("outputSchema") or candidate_req.get("discoverable"):
            score_challenge += 3
            has_output_schema = True
        else:
            findings.append({
                "code": "OUTPUT_SCHEMA_MISSING",
                "severity": "LOW",
                "title": "Missing outputSchema",
                "summary": "Endpoint specification lacks outputSchema for automated client response parsing.",
            })

    # -----------------------------------------------------------------------
    # Dimension 4: mcp_and_discovery (15 pts)
    # -----------------------------------------------------------------------
    score_discovery = 0
    mcp_valid = False
    if probe_mcp.get("status_code") == 200:
        try:
            mcp_data = json.loads(probe_mcp.get("body", b"").decode("utf-8"))
            if isinstance(mcp_data, dict):
                # Valid name
                name = mcp_data.get("name", "")
                if name and isinstance(name, str) and len(name.strip()) > 0:
                    score_discovery += 3

                # Valid repo
                repo = mcp_data.get("repository", "")
                if repo and isinstance(repo, str) and not any(p in repo.lower() for p in ("todo", "placeholder", "xxx")):
                    score_discovery += 4
                else:
                    findings.append({
                        "code": "MCP_REPO_PLACEHOLDER",
                        "severity": "LOW",
                        "title": "MCP Repository URL is Placeholder or Missing",
                        "summary": "MCP manifest repository field is empty or contains placeholder text.",
                    })

                # Tools or install section
                if mcp_data.get("tools") or mcp_data.get("install") or mcp_data.get("endpoints"):
                    score_discovery += 3
                mcp_valid = True
        except Exception:
            pass

    if not mcp_valid:
        findings.append({
            "code": "MCP_MANIFEST_MISSING",
            "severity": "HIGH",
            "title": "Missing /.well-known/mcp.json Manifest",
            "summary": "Target does not serve a valid Model Context Protocol manifest for agent registries.",
        })

    # OpenAPI or llms.txt discovery
    if probe_openapi.get("status_code") == 200 or probe_llms.get("status_code") == 200:
        score_discovery += 5
    else:
        findings.append({
            "code": "DISCOVERY_METADATA_MISSING",
            "severity": "LOW",
            "title": "Missing /openapi.json or /llms.txt",
            "summary": "Target does not publish OpenAPI or llms.txt metadata for AI agent ingestion.",
        })

    # -----------------------------------------------------------------------
    # Dimension 5: onchain_payto_history (15 pts)
    # -----------------------------------------------------------------------
    score_onchain = 0
    if discovered_pay_to and discovered_pay_to.lower() not in ("0x0", "0x" + "0" * 40, ""):
        onchain_res = query_base_usdc_onchain(discovered_pay_to, rpc_transport=rpc_transport)
        if onchain_res.get("valid_address"):
            if onchain_res.get("balance", 0) > 0:
                score_onchain += 5

            unique_buyers = onchain_res.get("unique_buyers", 0)
            if unique_buyers >= 2:
                score_onchain += 10
            elif unique_buyers == 1:
                score_onchain += 5
            else:
                findings.append({
                    "code": "ONCHAIN_NO_HISTORY",
                    "severity": "MEDIUM",
                    "title": "Zero On-Chain Settlement History",
                    "summary": "The specified payTo address has 0 recorded Base USDC settlement transactions over recent blocks.",
                })
        else:
            findings.append({
                "code": "PAYTO_INVALID_FORMAT",
                "severity": "MEDIUM",
                "title": "Malformed payTo Address",
                "summary": f"The payTo address '{discovered_pay_to}' is not a valid 42-character hex Ethereum address.",
            })
    else:
        findings.append({
            "code": "ONCHAIN_NO_PAYTO",
            "severity": "MEDIUM",
            "title": "No payTo Address to Verify On-Chain",
            "summary": "Unable to verify settlement history because no non-zero payTo address was discovered.",
        })

    # -----------------------------------------------------------------------
    # Dimension 6: latency_and_hygiene (10 pts)
    # -----------------------------------------------------------------------
    score_hygiene = 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    if avg_latency < 800.0:
        score_hygiene += 5
    elif avg_latency < 2000.0:
        score_hygiene += 3
    else:
        score_hygiene += 1

    if not has_5xx:
        score_hygiene += 5
    else:
        findings.append({
            "code": "SERVER_5XX_ERROR",
            "severity": "HIGH",
            "title": "HTTP 5xx Server Errors Detected",
            "summary": "One or more passive discovery probes returned HTTP 5xx server errors.",
        })

    # -----------------------------------------------------------------------
    # Final Scoring & Grade Assembly
    # -----------------------------------------------------------------------
    total_score = min(100, max(0, score_tls + score_agent + score_challenge + score_discovery + score_onchain + score_hygiene))

    if total_score >= 95:
        grade = "A+"
    elif total_score >= 85:
        grade = "A"
    elif total_score >= 70:
        grade = "B"
    elif total_score >= 55:
        grade = "C"
    elif total_score >= 40:
        grade = "D"
    else:
        grade = "F"

    dimension_scores = {
        "tls_and_headers": score_tls,
        "agent_accessibility": score_agent,
        "x402_challenge_schema": score_challenge,
        "mcp_and_discovery": score_discovery,
        "onchain_payto_history": score_onchain,
        "latency_and_hygiene": score_hygiene,
    }

    badge_svg_url = f"/x402/trust-grade/badge.svg?domain={domain}"
    badge_markdown = f"[![x402 Trust Grade]({badge_svg_url})]({validated_url})"

    audit_result = {
        "target_url": validated_url,
        "domain": domain,
        "grade": grade,
        "score": total_score,
        "dimension_scores": dimension_scores,
        "agent_accessible": agent_accessible,
        "cf_1010_detected": cf_1010_detected,
        "findings": findings,
        "badge_svg_url": badge_svg_url,
        "badge_markdown": badge_markdown,
        "b2b_offers": B2B_OFFERS,
    }

    # Automatically upsert into leaderboard
    try:
        get_global_leaderboard().upsert(
            domain=domain,
            seller_url=validated_url,
            grade=grade,
            score=total_score,
            agent_accessible=agent_accessible,
            cf_1010_detected=cf_1010_detected,
            dimension_scores=dimension_scores,
            findings_count=len(findings),
        )
    except Exception as exc:
        logger.debug("Leaderboard upsert non-fatal failure: %s", exc)

    return audit_result


# ---------------------------------------------------------------------------
# Built-in Deterministic Demo Profiles
# ---------------------------------------------------------------------------

def grade_demo_profile(demo: str) -> Dict[str, Any]:
    """
    Returns deterministic reference demo profiles for testing and showcase.
    """
    clean_demo = (demo or "").strip().lower()

    if clean_demo == "perfect_a_plus":
        return {
            "target_url": "https://gateway.stealthmark.io",
            "domain": "gateway.stealthmark.io",
            "grade": "A+",
            "score": 98,
            "dimension_scores": {
                "tls_and_headers": 15,
                "agent_accessibility": 20,
                "x402_challenge_schema": 25,
                "mcp_and_discovery": 15,
                "onchain_payto_history": 15,
                "latency_and_hygiene": 8,
            },
            "agent_accessible": True,
            "cf_1010_detected": False,
            "findings": [],
            "badge_svg_url": "/x402/trust-grade/badge.svg?demo=perfect_a_plus",
            "badge_markdown": "[![x402 Trust Grade](/x402/trust-grade/badge.svg?demo=perfect_a_plus)](https://gateway.stealthmark.io)",
            "b2b_offers": B2B_OFFERS,
        }

    if clean_demo in ("cf_1010_blocked", "cf_1010", "blocked"):
        return {
            "target_url": "https://unfixed-seller.example.com",
            "domain": "unfixed-seller.example.com",
            "grade": "F",
            "score": 30,
            "dimension_scores": {
                "tls_and_headers": 10,
                "agent_accessibility": 0,
                "x402_challenge_schema": 15,
                "mcp_and_discovery": 0,
                "onchain_payto_history": 0,
                "latency_and_hygiene": 5,
            },
            "agent_accessible": False,
            "cf_1010_detected": True,
            "findings": [
                {
                    "code": "CF_1010_BLOCKED",
                    "severity": "CRITICAL",
                    "title": "Cloudflare Browser Integrity Check (Error 1010) Blocks AI Agents",
                    "summary": (
                        "Probe with standard Python-urllib received HTTP 403 (Error 1010: Browser Integrity Check). "
                        "Autonomous agents and SDK buyers cannot purchase from this seller without a WAF bypass rule."
                    ),
                },
                {
                    "code": "CORS_EXPOSE_HEADERS_MISSING",
                    "severity": "HIGH",
                    "title": "Missing Access-Control-Expose-Headers",
                    "summary": (
                        "Access-Control-Expose-Headers does not expose PAYMENT-REQUIRED, "
                        "preventing browser-based AI agents and web dApps from reading challenge parameters."
                    ),
                },
                {
                    "code": "MCP_MANIFEST_MISSING",
                    "severity": "HIGH",
                    "title": "Missing /.well-known/mcp.json Manifest",
                    "summary": "Target does not serve a valid Model Context Protocol manifest for agent registries.",
                },
                {
                    "code": "ONCHAIN_NO_HISTORY",
                    "severity": "MEDIUM",
                    "title": "Zero On-Chain Settlement History",
                    "summary": "The specified payTo address has 0 recorded Base USDC settlement transactions over recent blocks.",
                },
            ],
            "badge_svg_url": "/x402/trust-grade/badge.svg?demo=cf_1010_blocked",
            "badge_markdown": "[![x402 Trust Grade](/x402/trust-grade/badge.svg?demo=cf_1010_blocked)](https://unfixed-seller.example.com)",
            "b2b_offers": B2B_OFFERS,
        }

    raise ValueError(f"Unknown demo profile: '{demo}'. Supported demos: 'perfect_a_plus', 'cf_1010_blocked'")


# ---------------------------------------------------------------------------
# Remediation Fix Pack Generator
# ---------------------------------------------------------------------------

def build_seller_fix_pack(audit_result: Dict[str, Any], redacted: bool = False) -> Dict[str, Any]:
    """
    Generates concrete, copy-paste remediation artifacts tailored to audit findings.
    If redacted=True (free preview mode), code/config snippets are replaced by the unlock notice.
    """
    domain = audit_result.get("domain", "seller.example.com")
    has_cf_1010 = audit_result.get("cf_1010_detected", False)
    findings = {f.get("code") for f in audit_result.get("findings", [])}

    if redacted:
        return {
            "cloudflare_waf_fix": {
                "title": "Cloudflare Custom WAF Rule (Skip Browser Integrity Check)",
                "recommended": has_cf_1010 or "CF_1010_BLOCKED" in findings,
                "expression": REDACTION_NOTICE,
                "api_payload": REDACTION_NOTICE,
                "curl_command": REDACTION_NOTICE,
            },
            "mcp_manifest_template": {
                "title": "Model Context Protocol Manifest (/.well-known/mcp.json)",
                "recommended": "MCP_MANIFEST_MISSING" in findings,
                "mcp_json": REDACTION_NOTICE,
                "glama_json": REDACTION_NOTICE,
            },
            "cors_headers_snippet": {
                "title": "CORS Expose-Headers Configuration",
                "recommended": "CORS_EXPOSE_HEADERS_MISSING" in findings,
                "fastapi_snippet": REDACTION_NOTICE,
                "nginx_snippet": REDACTION_NOTICE,
            },
            "x402_schema_fix": {
                "title": "x402 v2 Challenge & Bazaar Manifest Spec",
                "recommended": "X402_CHALLENGE_MISSING" in findings or "X402_INVALID_NETWORK" in findings,
                "challenge_header_example": REDACTION_NOTICE,
                "bazaar_json_example": REDACTION_NOTICE,
            },
        }

    # Full unredacted fix pack
    cf_expression = (
        '(http.request.uri.path contains "/x402" or http.request.uri.path contains "/.well-known") '
        'and cf.threat_score < 20'
    )
    cf_payload = {
        "rules": [
            {
                "action": "skip",
                "action_parameters": {
                    "ruleset": "current",
                    "products": ["bic"],
                },
                "expression": cf_expression,
                "description": "Allow autonomous AI agents and Python/Node x402 buyers (Skip Browser Integrity Check)",
            }
        ]
    }
    cf_curl = (
        'curl -s -X POST "https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/rulesets/phases/http_request_firewall_custom/entrypoint" '
        '-H "Authorization: Bearer {CLOUDFLARE_API_TOKEN}" '
        '-H "Content-Type: application/json" '
        f"-d '{json.dumps(cf_payload)}'"
    )

    mcp_template = {
        "schemaVersion": "1.0",
        "name": f"{domain}-agent-service",
        "description": f"Production x402 and MCP service on {domain}",
        "repository": f"https://github.com/example/{domain}",
        "install": {
            "command": f"npx -y @modelcontextprotocol/inspector https://{domain}",
        },
        "tools": [
            {
                "name": "verify_service",
                "description": "x402 pay-per-proof formal verification endpoint",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {"type": "object"},
                        "paymentHeader": {"type": "string"},
                    },
                    "required": ["payload"],
                },
            }
        ],
    }

    glama_template = {
        "$schema": "https://glama.ai/mcp/manifest-schema.json",
        "name": f"{domain}-agent-service",
        "description": f"x402 pay-per-use service on {domain}",
        "category": "security-and-proofs",
    }

    fastapi_snippet = (
        "from fastapi.middleware.cors import CORSMiddleware\n\n"
        "app.add_middleware(\n"
        "    CORSMiddleware,\n"
        '    allow_origins=["*"],\n'
        "    allow_credentials=True,\n"
        '    allow_methods=["*"],\n'
        '    allow_headers=["*"],\n'
        '    expose_headers=["PAYMENT-REQUIRED", "PAYMENT-RESPONSE", "X-PAYMENT-RESPONSE"],\n'
        ")\n"
    )

    nginx_snippet = (
        "# Add inside your server or location block:\n"
        "add_header 'Access-Control-Allow-Origin' '*' always;\n"
        "add_header 'Access-Control-Expose-Headers' 'PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-PAYMENT-RESPONSE' always;\n"
        "add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization, X-PAYMENT, PAYMENT-SIGNATURE' always;\n"
    )

    challenge_example = {
        "scheme": "exact",
        "network": "eip155:8453",
        "maxAmountRequired": "50000",
        "resource": f"https://{domain}/x402/verify-service",
        "description": "Production verification micropayment",
        "mimeType": "application/json",
        "payTo": "0x1111111111111111111111111111111111111111",
        "asset": BASE_USDC_CONTRACT,
        "outputSchema": {
            "type": "object",
            "properties": {
                "verified": {"type": "boolean"},
                "message": {"type": "string"},
            },
        },
    }

    bazaar_example = {
        "x402Version": 1,
        "supportedVersions": [1, 2],
        "name": f"{domain}-bazaar",
        "provider": {
            "name": f"{domain} Service",
            "network": "eip155:8453",
            "payTo": "0x1111111111111111111111111111111111111111",
            "asset": BASE_USDC_CONTRACT,
        },
        "endpoints": [challenge_example],
    }

    return {
        "cloudflare_waf_fix": {
            "title": "Cloudflare Custom WAF Rule (Skip Browser Integrity Check)",
            "recommended": has_cf_1010 or "CF_1010_BLOCKED" in findings,
            "expression": cf_expression,
            "api_payload": cf_payload,
            "curl_command": cf_curl,
        },
        "mcp_manifest_template": {
            "title": "Model Context Protocol Manifest (/.well-known/mcp.json)",
            "recommended": "MCP_MANIFEST_MISSING" in findings,
            "mcp_json": json.dumps(mcp_template, indent=2),
            "glama_json": json.dumps(glama_template, indent=2),
        },
        "cors_headers_snippet": {
            "title": "CORS Expose-Headers Configuration",
            "recommended": "CORS_EXPOSE_HEADERS_MISSING" in findings,
            "fastapi_snippet": fastapi_snippet,
            "nginx_snippet": nginx_snippet,
        },
        "x402_schema_fix": {
            "title": "x402 v2 Challenge & Bazaar Manifest Spec",
            "recommended": "X402_CHALLENGE_MISSING" in findings or "X402_INVALID_NETWORK" in findings,
            "challenge_header_example": json.dumps(challenge_example, indent=2),
            "bazaar_json_example": json.dumps(bazaar_example, indent=2),
        },
    }


# ---------------------------------------------------------------------------
# Dynamic Shields-Style SVG Badge Generator
# ---------------------------------------------------------------------------

def render_trust_grade_svg(
    label: str = "x402 trust",
    grade: str = "A+",
    score: int = 98,
) -> str:
    """
    Renders a shields.io-compatible dynamic SVG trust grade badge.
    All dynamic inputs are strictly escaped with html.escape(..., quote=True)
    to eliminate SVG/XML injection risks.
    """
    clean_grade = str(grade).strip()
    color = GRADE_COLORS.get(clean_grade, "#6b7280")

    right_text = f"{clean_grade} · {score}/100" if clean_grade != "unknown" else "unknown"

    escaped_label = html.escape(str(label).strip() or "x402 trust", quote=True)
    escaped_right = html.escape(right_text, quote=True)
    aria_label = html.escape(f"{label}: {right_text}", quote=True)

    left_char_count = len(label)
    right_char_count = len(right_text)

    left_width = max(68, int(left_char_count * 6.8 + 14))
    right_width = max(46, int(right_char_count * 6.8 + 14))
    total_width = left_width + right_width

    left_x = int(left_width * 5.0)
    right_x = int((left_width + right_width / 2.0) * 10.0)
    left_len = int(left_width * 10 - 120)
    right_len = int(right_width * 10 - 120)

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{aria_label}">\n'
        '  <linearGradient id="s" x2="0" y2="100%">\n'
        '    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>\n'
        '    <stop offset="1" stop-opacity=".1"/>\n'
        '  </linearGradient>\n'
        '  <clipPath id="r">\n'
        f'    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>\n'
        '  </clipPath>\n'
        '  <g clip-path="url(#r)">\n'
        f'    <rect width="{left_width}" height="20" fill="#1e293b"/>\n'
        f'    <rect x="{left_width}" width="{right_width}" height="20" fill="{color}"/>\n'
        f'    <rect width="{total_width}" height="20" fill="url(#s)"/>\n'
        '  </g>\n'
        '  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">\n'
        f'    <text aria-hidden="true" x="{left_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{left_len}">{escaped_label}</text>\n'
        f'    <text x="{left_x}" y="140" transform="scale(.1)" fill="#fff" textLength="{left_len}">{escaped_label}</text>\n'
        f'    <text aria-hidden="true" x="{right_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{right_len}">{escaped_right}</text>\n'
        f'    <text x="{right_x}" y="140" transform="scale(.1)" fill="#fff" textLength="{right_len}">{escaped_right}</text>\n'
        '  </g>\n'
        '</svg>'
    )


# ---------------------------------------------------------------------------
# Leaderboard Store & Crawler
# ---------------------------------------------------------------------------

class TrustGradeLeaderboard:
    """
    SQLite-backed store for x402 Trust Grade leaderboard entries.
    Automatically falls back to in-memory SQLite if the disk path is not writable
    (e.g., under systemd ProtectSystem=strict environments).
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._lock = threading.Lock()
        if db_path is None:
            db_path = (
                os.environ.get("OMNI_TRUST_DB_PATH")
                or os.environ.get("X402_TRUST_GRADE_DB_PATH")
                or os.path.join(tempfile.gettempdir(), "omni_x402_trust_leaderboard.db")
            )

        self.db_path = db_path
        self._is_memory = False

        try:
            dirname = os.path.dirname(os.path.abspath(db_path))
            if dirname and not os.path.exists(dirname):
                os.makedirs(dirname, exist_ok=True)
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            with self._conn:
                self._conn.execute("CREATE TABLE IF NOT EXISTS _health_check (id INTEGER PRIMARY KEY)")
                self._conn.execute("DROP TABLE _health_check")
        except Exception as exc:
            logger.debug("Failed to open SQLite database at %s (%s). Falling back to in-memory.", db_path, exc)
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._is_memory = True

        self._init_db()

    def _init_db(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS leaderboard (
                    domain TEXT PRIMARY KEY,
                    seller_url TEXT,
                    grade TEXT,
                    score INTEGER,
                    agent_accessible INTEGER,
                    cf_1010_detected INTEGER,
                    last_checked_at TEXT,
                    dimension_scores TEXT,
                    findings_count INTEGER
                )
            """)

            # Pre-seed reference platforms
            cur = self._conn.cursor()
            cur.execute("SELECT domain FROM leaderboard WHERE domain IN ('gateway.stealthmark.io', 'sentinel.oceaneye-ai.com')")
            existing = {r["domain"] for r in cur.fetchall()}
            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            if "gateway.stealthmark.io" not in existing:
                self._conn.execute("""
                    INSERT INTO leaderboard (
                        domain, seller_url, grade, score, agent_accessible, cf_1010_detected,
                        last_checked_at, dimension_scores, findings_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    "gateway.stealthmark.io",
                    "https://gateway.stealthmark.io",
                    "A+",
                    98,
                    1,
                    0,
                    now_iso,
                    json.dumps({
                        "tls_and_headers": 15,
                        "agent_accessibility": 20,
                        "x402_challenge_schema": 25,
                        "mcp_and_discovery": 15,
                        "onchain_payto_history": 15,
                        "latency_and_hygiene": 8,
                    }),
                    0,
                ))

            if "sentinel.oceaneye-ai.com" not in existing:
                self._conn.execute("""
                    INSERT INTO leaderboard (
                        domain, seller_url, grade, score, agent_accessible, cf_1010_detected,
                        last_checked_at, dimension_scores, findings_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    "sentinel.oceaneye-ai.com",
                    "https://sentinel.oceaneye-ai.com",
                    "A+",
                    97,
                    1,
                    0,
                    now_iso,
                    json.dumps({
                        "tls_and_headers": 15,
                        "agent_accessibility": 20,
                        "x402_challenge_schema": 25,
                        "mcp_and_discovery": 15,
                        "onchain_payto_history": 15,
                        "latency_and_hygiene": 7,
                    }),
                    0,
                ))

    def upsert(
        self,
        domain: str,
        seller_url: str,
        grade: str,
        score: int,
        agent_accessible: bool,
        cf_1010_detected: bool,
        dimension_scores: Optional[Dict[str, int]] = None,
        findings_count: int = 0,
    ) -> None:
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        dim_str = json.dumps(dimension_scores or {})
        with self._lock, self._conn:
            self._conn.execute("""
                INSERT INTO leaderboard (
                    domain, seller_url, grade, score, agent_accessible, cf_1010_detected,
                    last_checked_at, dimension_scores, findings_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    seller_url = excluded.seller_url,
                    grade = excluded.grade,
                    score = excluded.score,
                    agent_accessible = excluded.agent_accessible,
                    cf_1010_detected = excluded.cf_1010_detected,
                    last_checked_at = excluded.last_checked_at,
                    dimension_scores = excluded.dimension_scores,
                    findings_count = excluded.findings_count
            """, (
                domain.lower(),
                seller_url,
                grade,
                int(score),
                1 if agent_accessible else 0,
                1 if cf_1010_detected else 0,
                now_iso,
                dim_str,
                int(findings_count),
            ))

    def get_ranked_entries(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                SELECT domain, seller_url, grade, score, agent_accessible, cf_1010_detected,
                       last_checked_at, dimension_scores, findings_count
                FROM leaderboard
                ORDER BY score DESC, domain ASC
                LIMIT ?
            """, (limit,))
            rows = cur.fetchall()
            entries = []
            for r in rows:
                dim_scores = {}
                try:
                    if r["dimension_scores"]:
                        dim_scores = json.loads(r["dimension_scores"])
                except Exception:
                    pass
                entries.append({
                    "domain": r["domain"],
                    "seller_url": r["seller_url"],
                    "grade": r["grade"],
                    "score": r["score"],
                    "agent_accessible": bool(r["agent_accessible"]),
                    "cf_1010_detected": bool(r["cf_1010_detected"]),
                    "last_checked_at": r["last_checked_at"],
                    "dimension_scores": dim_scores,
                    "findings_count": r["findings_count"],
                })
            return entries

    def get_domain_entry(self, domain: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                SELECT domain, seller_url, grade, score, agent_accessible, cf_1010_detected,
                       last_checked_at, dimension_scores, findings_count
                FROM leaderboard
                WHERE domain = ?
            """, (domain.lower(),))
            r = cur.fetchone()
            if not r:
                return None
            dim_scores = {}
            try:
                if r["dimension_scores"]:
                    dim_scores = json.loads(r["dimension_scores"])
            except Exception:
                pass
            return {
                "domain": r["domain"],
                "seller_url": r["seller_url"],
                "grade": r["grade"],
                "score": r["score"],
                "agent_accessible": bool(r["agent_accessible"]),
                "cf_1010_detected": bool(r["cf_1010_detected"]),
                "last_checked_at": r["last_checked_at"],
                "dimension_scores": dim_scores,
                "findings_count": r["findings_count"],
            }


_GLOBAL_LEADERBOARD: Optional[TrustGradeLeaderboard] = None
_GLOBAL_LEADERBOARD_LOCK = threading.Lock()


def get_global_leaderboard() -> TrustGradeLeaderboard:
    global _GLOBAL_LEADERBOARD
    if _GLOBAL_LEADERBOARD is None:
        with _GLOBAL_LEADERBOARD_LOCK:
            if _GLOBAL_LEADERBOARD is None:
                _GLOBAL_LEADERBOARD = TrustGradeLeaderboard()
    return _GLOBAL_LEADERBOARD


def crawl_x402_directory(
    directory_urls_or_entries: List[Any],
    *,
    leaderboard: Optional[TrustGradeLeaderboard] = None,
    allow_loopback_for_tests: bool = False,
    http_transport: Optional[Callable[..., Any]] = None,
    rpc_transport: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """
    Passively grades a list of seller URLs or Bazaar JSON catalog entries
    and updates the leaderboard store.
    """
    store = leaderboard or get_global_leaderboard()
    results: List[Dict[str, Any]] = []

    for item in directory_urls_or_entries:
        target_url = ""
        if isinstance(item, str):
            target_url = item.strip()
        elif isinstance(item, dict):
            target_url = (
                item.get("resource")
                or item.get("url")
                or item.get("seller_url")
                or item.get("domain", "")
            ).strip()

        if target_url and not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

        if not target_url:
            continue

        try:
            graded = score_x402_seller(
                target_url,
                allow_loopback_for_tests=allow_loopback_for_tests,
                http_transport=http_transport,
                rpc_transport=rpc_transport,
            )
            store.upsert(
                domain=graded["domain"],
                seller_url=graded["target_url"],
                grade=graded["grade"],
                score=graded["score"],
                agent_accessible=graded["agent_accessible"],
                cf_1010_detected=graded["cf_1010_detected"],
                dimension_scores=graded["dimension_scores"],
                findings_count=len(graded["findings"]),
            )
            results.append(graded)
        except Exception as exc:
            logger.warning("Failed to crawl seller %s: %s", target_url, exc)

    return results


def render_leaderboard_html(entries: List[Dict[str, Any]], base_url: str = "") -> str:
    """
    Renders a responsive, modern dark-mode HTML leaderboard page.
    """
    clean_base = base_url.rstrip("/") if base_url else ""

    table_rows = []
    for idx, e in enumerate(entries, start=1):
        domain = html.escape(e.get("domain", "unknown"), quote=True)
        seller_url = html.escape(e.get("seller_url", ""), quote=True)
        grade = html.escape(e.get("grade", "F"), quote=True)
        score = int(e.get("score", 0))
        grade_color = GRADE_COLORS.get(grade, "#6b7280")

        agent_acc = e.get("agent_accessible", True)
        cf_detected = e.get("cf_1010_detected", False)
        if agent_acc and not cf_detected:
            acc_html = '<span style="color:#10b981;font-weight:600;">&#10003; Accessible</span>'
        else:
            acc_html = '<span style="color:#ef4444;font-weight:700;">&#10007; CF 1010 Blocked</span>'

        last_checked = html.escape(str(e.get("last_checked_at", "—"))[:19], quote=True)
        findings_count = int(e.get("findings_count", 0))

        preview_link = f"{clean_base}/x402/trust-grade/preview?url={seller_url}"
        badge_link = f"{clean_base}/x402/trust-grade/badge.svg?domain={domain}"

        table_rows.append(f"""
        <tr>
            <td style="color:#94a3b8;font-weight:600;">#{idx}</td>
            <td>
                <div style="font-weight:600;color:#f8fafc;">{domain}</div>
                <div style="font-size:0.75rem;color:#64748b;">{seller_url}</div>
            </td>
            <td>
                <span class="badge" style="background:{grade_color}22;color:{grade_color};border:1px solid {grade_color}55;">
                    {grade}
                </span>
            </td>
            <td style="font-weight:700;color:#38bdf8;">{score}/100</td>
            <td>{acc_html}</td>
            <td style="color:#94a3b8;font-size:0.8rem;">{last_checked}</td>
            <td style="color:#94a3b8;">{findings_count}</td>
            <td>
                <a href="{preview_link}" class="action-btn" target="_blank" rel="noopener">Preview Audit</a>
                <a href="{badge_link}" class="action-btn badge-btn" target="_blank" rel="noopener">Badge</a>
            </td>
        </tr>
        """)

    rows_html = "\n".join(table_rows)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>x402 Trust Grade Leaderboard & Seller Directory</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: #090d16;
            color: #f1f5f9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
            line-height: 1.5;
            padding: 2rem 1rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ margin-bottom: 2rem; border-bottom: 1px solid #1e293b; padding-bottom: 1.5rem; }}
        h1 {{ font-size: 2rem; font-weight: 800; color: #f8fafc; display: flex; align-items: center; gap: 0.75rem; }}
        h1 span.logo-tag {{ font-size: 0.85rem; background: #0284c7; color: #fff; padding: 0.2rem 0.6rem; border-radius: 9999px; }}
        p.subtitle {{ color: #94a3b8; font-size: 1.05rem; margin-top: 0.5rem; }}
        
        .grid-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.25rem; margin-bottom: 2rem; }}
        .card {{
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 12px;
            padding: 1.25rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
        }}
        .card h3 {{ font-size: 1.15rem; color: #38bdf8; margin-bottom: 0.5rem; }}
        .card p {{ font-size: 0.9rem; color: #94a3b8; margin-bottom: 1rem; }}
        .cta-btn {{
            display: inline-block;
            background: #0284c7;
            color: #fff;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            font-size: 0.85rem;
            transition: background 0.15s;
        }}
        .cta-btn:hover {{ background: #0369a1; }}
        
        .search-box {{
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 12px;
            padding: 1rem 1.25rem;
            margin-bottom: 2rem;
            display: flex;
            gap: 0.75rem;
            align-items: center;
        }}
        .search-box input {{
            flex: 1;
            background: #0b0f19;
            border: 1px solid #374151;
            border-radius: 8px;
            padding: 0.6rem 0.85rem;
            color: #fff;
            font-size: 0.95rem;
        }}
        .search-box button {{
            background: #10b981;
            color: #0b0f19;
            border: none;
            border-radius: 8px;
            padding: 0.65rem 1.25rem;
            font-weight: 700;
            cursor: pointer;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #111827;
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid #1f2937;
        }}
        th, td {{ padding: 0.85rem 1rem; text-align: left; font-size: 0.9rem; }}
        th {{ background: #1f2937; color: #cbd5e1; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
        tr:not(:last-child) td {{ border-bottom: 1px solid #1f2937; }}
        tr:hover td {{ background: #162032; }}
        
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.55rem;
            border-radius: 6px;
            font-weight: 700;
            font-size: 0.8rem;
        }}
        .action-btn {{
            display: inline-block;
            background: #1e293b;
            color: #38bdf8;
            padding: 0.35rem 0.65rem;
            border-radius: 6px;
            text-decoration: none;
            font-size: 0.75rem;
            font-weight: 600;
            border: 1px solid #334155;
            margin-right: 0.3rem;
        }}
        .action-btn:hover {{ background: #334155; }}
        .badge-btn {{ color: #10b981; }}
        
        .embed-section {{
            margin-top: 2rem;
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 12px;
            padding: 1.25rem;
        }}
        .embed-section h4 {{ font-size: 1rem; color: #f8fafc; margin-bottom: 0.5rem; }}
        code {{
            display: block;
            background: #090d16;
            padding: 0.75rem;
            border-radius: 8px;
            color: #38bdf8;
            font-family: monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            border: 1px solid #1e293b;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>
                x402 Trust Grade Leaderboard
                <span class="logo-tag">Passive Security</span>
            </h1>
            <p class="subtitle">
                Automated Bot-Block (Cloudflare 1010) Detection, MCP Discovery, and On-Chain Base Settlement Transparency for AI Agents
            </p>
        </header>

        <div class="grid-cards">
            <div class="card">
                <h3>$49 Audit &amp; Listing Fix</h3>
                <p>Cloudflare WAF Custom Rule (Skip BIC), Model Context Protocol (MCP) registration, and CORS fix delivered in 24 hours.</p>
                <a href="https://stealthmark.io/pricing?service=fix49" class="cta-btn" target="_blank" rel="noopener">Request $49 Remediation</a>
            </div>
            <div class="card">
                <h3>$19/mo Badge &amp; Synthetic Monitor</h3>
                <p>5-minute continuous probe simulating LangChain/CrewAI Python buyers with dynamic Shields badge CDN &amp; instant alerts.</p>
                <a href="https://stealthmark.io/pricing?service=monitor19" class="cta-btn" target="_blank" rel="noopener">Subscribe for $19/mo</a>
            </div>
        </div>

        <form class="search-box" action="{clean_base}/x402/trust-grade/preview" method="GET">
            <input type="url" name="url" placeholder="Enter seller HTTPS target (e.g. https://gateway.stealthmark.io)" required />
            <button type="submit">Audit Seller</button>
        </form>

        <table>
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>Seller Domain</th>
                    <th>Grade</th>
                    <th>Score</th>
                    <th>Agent Accessible</th>
                    <th>Last Checked</th>
                    <th>Issues</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>

        <div class="embed-section">
            <h4>Embed Trust Grade Dynamic Badge in your README.md:</h4>
            <code>[![x402 Trust Grade]({clean_base}/x402/trust-grade/badge.svg?domain=gateway.stealthmark.io)](https://gateway.stealthmark.io)</code>
        </div>
    </div>
</body>
</html>
"""
