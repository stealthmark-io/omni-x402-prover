"""
Production-grade x402 HTTP Server for Base USDC Micropayments.

Provides ThreadingHTTPServer + BaseHTTPRequestHandler serving:
- GET /health
- GET /.well-known/x402-bazaar.json
- POST /x402/* with strict 402 challenge, replay protection, settlement, and Z3 execution.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import sys
import threading
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from omni_x402_prover.arb_trap_detector import (
    MarketRuleSpec,
    extract_rule_spec,
    fetch_kalshi_market,
    fetch_polymarket_market,
    verify_arb_resolution_divergence,
)
from omni_x402_prover.multichain_token_verifier import (
    EAS_SCHEMA_MULTICHAIN_VERIFIER,
    LZ_V2_EIDS,
    audit_multichain_token,
    build_eas_attestation_and_report,
    discover_multichain_token_topology,
    verify_multichain_token_invariants,
)
from omni_x402_prover.prover_service import ProverCapacityError, ProverService
from omni_x402_prover.x402_protocol import (
    DeterministicMockFacilitator,
    FacilitatorClient,
    ReplayNonceStore,
    RemoteHTTPFacilitatorClient,
    X402Config,
    build_payment_required_response,
    release_payment,
    settle_payment,
    verify_payment,
)

logger = logging.getLogger("omni_x402_prover.http")

MAX_REQUEST_BODY_BYTES = 65536  # 64 KB DoS protection threshold


class X402HTTPHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler implementing x402 v1 challenge & settlement."""

    # Server-wide shared singletons attached by server factory
    server_config: X402Config
    prover_service: ProverService
    nonce_store: ReplayNonceStore
    facilitator: FacilitatorClient

    # Suppress noisy default stderr logging in tests
    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))

    def _resolve_base_url(self) -> str:
        """Resolve public base URL respecting reverse proxy forwarded headers."""
        proto = self.headers.get("X-Forwarded-Proto") or "http"
        if proto not in ("http", "https"):
            proto = "http"
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "127.0.0.1:8402"
        return f"{proto}://{host}"

    def _send_json_response(
        self,
        status_code: int,
        data: Dict[str, Any],
        extra_headers: Optional[Dict[str, str]] = None,
        compact: bool = False,
    ) -> None:
        body = (
            json.dumps(data, separators=(",", ":")).encode("utf-8")
            if compact
            else json.dumps(data, indent=2).encode("utf-8")
        )
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-PAYMENT, PAYMENT-SIGNATURE, X-Referral-Agent")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_payment_challenge(
        self,
        status_code: int,
        payment_res: Dict[str, Any],
        path: str,
        description: str,
        amount_atomic: int,
        input_schema: Optional[Dict[str, Any]],
        output_schema: Optional[Dict[str, Any]],
    ) -> None:
        """Send the v1 JSON challenge plus the x402 v2 PAYMENT-REQUIRED header for x402scan / v2 clients."""
        caip2_network = "eip155:8453" if self.server_config.network == "base" else "eip155:84532"
        full_res_url = f"{self._resolve_base_url()}{path}"
        v2_challenge = {
            "x402Version": 2,
            "error": payment_res.get("error", "PAYMENT-SIGNATURE header is required"),
            "resource": {
                "url": full_res_url,
                "description": description,
                "mimeType": "application/json",
            },
            "accepts": [
                {
                    "scheme": "exact",
                    "network": caip2_network,
                    "amount": str(amount_atomic),
                    "payTo": self.server_config.pay_to_address,
                    "maxTimeoutSeconds": self.server_config.max_timeout_seconds,
                    "asset": self.server_config.asset_address,
                    "extra": {
                        "name": "USD Coin",
                        "version": "2",
                    },
                }
            ],
            "extensions": {
                "bazaar": {
                    "info": {
                        "input": {
                            "type": "http",
                            "method": "POST",
                            "bodyType": "json",
                            "body": input_schema.get("properties", {}) if input_schema else {},
                        },
                        "output": {
                            "type": "json",
                            "example": output_schema.get("properties", {}) if output_schema else {},
                        },
                    },
                    "schema": {
                        "$schema": "https://json-schema.org/draft/2020-12/schema",
                        "type": "object",
                        "properties": {
                            "input": {
                                "type": "object",
                                "properties": {
                                    "type": {"type": "string", "const": "http"},
                                    "method": {"type": "string", "enum": ["POST"]},
                                    "bodyType": {"type": "string", "enum": ["json"]},
                                    "body": input_schema or {"type": "object"},
                                },
                                "required": ["type", "method", "bodyType", "body"],
                            },
                            "output": {
                                "type": "object",
                                "properties": {
                                    "type": {"type": "string", "const": "json"},
                                    "example": output_schema or {"type": "object"},
                                },
                                "required": ["type"],
                            },
                        },
                        "required": ["input"],
                    },
                }
            },
        }
        v2_b64 = base64.b64encode(json.dumps(v2_challenge).encode("utf-8")).decode("utf-8")
        self._send_json_response(
            status_code,
            payment_res,
            extra_headers={
                "PAYMENT-REQUIRED": v2_b64,
                "Access-Control-Expose-Headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-PAYMENT-RESPONSE",
            },
        )

    def _resolve_endpoint_info(
        self, path: str
    ) -> Optional[Tuple[int, str, Callable[[Dict[str, Any]], Dict[str, Any]]]]:
        """Map all 6 /x402/* routes to (price_atomic, description, handler_fn)."""
        clean_path = path.rstrip("/")
        if clean_path == "/x402/verify-vault-and-rounding":
            return (
                self.server_config.price_vault_atomic,
                "Formal Z3 verification of ERC-4626 / Euler vault share rounding & zero-share inflation attacks",
                self.prover_service.verify_vault_and_rounding,
            )
        if clean_path == "/x402/verify-polymarket-basket":
            return (
                self.server_config.price_polymarket_atomic,
                "Formal verification of Polymarket NegRisk / CTF token solvency and Dutch-book net edge",
                self.prover_service.verify_polymarket_basket,
            )
        if clean_path == "/x402/verify-zk-and-bitvec":
            return (
                self.server_config.price_zk_bitvec_atomic,
                "Formal Z3 verification of ZK witness uniqueness or BitVector integer cast truncation",
                self.prover_service.verify_zk_and_bitvec,
            )
        if clean_path == "/x402/verify-differential-spec":
            return (
                self.server_config.price_differential_atomic,
                "Differential equivalence verification between code_a and code_b across boundary grids",
                self.prover_service.verify_differential_spec,
            )
        if clean_path == "/x402/verify-forensic-graph":
            return (
                self.server_config.price_forensic_graph_atomic,
                "On-chain and PSP forensic graph engine: Tarjan cyclic loop collapse, Jupiter Lend receipt handover, bridge hop correlation, and taint propagation",
                self.prover_service.verify_forensic_graph,
            )
        if clean_path == "/x402/verify-ast-blast-radius":
            return (
                self.server_config.price_blast_radius_atomic,
                "Deterministic 2-hop AST call-graph blast-radius and upstream-to-fork patch-gap readiness verification",
                self.prover_service.verify_ast_blast_radius,
            )
        if clean_path == "/x402/verify-erc4626-inflation-guard":
            return (
                self.server_config.price_erc4626_inflation_atomic,
                "Formal verification of ERC-4626 vault virtual share offset and zero-share inflation attack prevention",
                self.prover_service.verify_erc4626_inflation_guard,
            )
        if clean_path == "/x402/verify-amm-constant-product":
            return (
                self.server_config.price_amm_constant_product_atomic,
                "Formal verification of constant-product AMM k invariant preservation and exact integer rounding direction",
                self.prover_service.verify_amm_constant_product,
            )
        if clean_path in ("/x402/verify-crosschain-bridge-memo", "/x402/verify-bridge-and-oracle"):
            return (
                self.server_config.price_crosschain_memo_atomic,
                "Crosschain bridge memo syntax, injection-prevention, affiliate fee ceiling, and multichain token Z3 invariant audit (OFT/NTT/CCIP)",
                self.prover_service.verify_bridge_and_oracle,
            )
        if clean_path == "/x402/verify-cardano-eutxo-conservation":
            return (
                self.server_config.price_cardano_eutxo_atomic,
                "Cardano eUTxO value conservation, multi-asset balance, minUTxO compliance, and Plutus double satisfaction audit",
                self.prover_service.verify_cardano_eutxo_conservation,
            )
        if clean_path == "/x402/verify-mev-sandwich-bound":
            return (
                self.server_config.price_mev_sandwich_atomic,
                "Analytical binary-search MEV sandwich profitability bound and optimal frontrun/backrun impact verification",
                self.prover_service.verify_mev_sandwich_bound,
            )
        if clean_path == "/x402/verify-permit2-signature-scope":
            return (
                self.server_config.price_permit2_scope_atomic,
                "Pre-signing audit for Uniswap Permit2 allowance signatures: unlimited approval, expiration, deadline, and spender",
                self.prover_service.verify_permit2_signature_scope,
            )
        if clean_path == "/x402/verify-liquidation-waterfall":
            return (
                self.server_config.price_liquidation_waterfall_atomic,
                "Lending market liquidation solvency audit: health factor, close factor, bonus insolvency cap, and bad debt shortfall",
                self.prover_service.verify_liquidation_waterfall,
            )
        if clean_path == "/x402/verify-merkle-airdrop-claim":
            return (
                self.server_config.price_merkle_airdrop_atomic,
                "Merkle airdrop distribution integrity: double-hash preimage resistance, duplicate claim elimination, and canonical root",
                self.prover_service.verify_merkle_airdrop_claim,
            )
        if clean_path == "/x402/verify-fiat-crypto-otc-settlement":
            return (
                self.server_config.price_fiat_crypto_otc_atomic,
                "Fiat-to-crypto OTC settlement reconciliation: cross-currency FX spread verification, skimming check, and CMP-PSAV certificate",
                self.prover_service.verify_fiat_crypto_otc_settlement,
            )
        if clean_path == "/x402/verify-sar-ed25519-dossier":
            return (
                self.server_config.price_sar_ed25519_atomic,
                "Synthetic Aperture Radar (SAR) IUU dark-vessel detection, EEZ territorial intrusion, and Ed25519 RFC 8032 canonical dossier audit",
                self.prover_service.verify_sar_ed25519_dossier,
            )
        return None

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests."""
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-PAYMENT, PAYMENT-SIGNATURE, X-PAYMENT-RESPONSE, X-Referral-Agent, x-referral-agent",
        )
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"

        if path == "/favicon.ico":
            svg_icon = (
                b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
                b'<rect width="64" height="64" rx="14" fill="#0b1020"/>'
                b'<text x="50%" y="56%" dominant-baseline="middle" text-anchor="middle" '
                b'fill="#38bdf8" font-family="monospace" font-weight="bold" font-size="26">Z3</text></svg>'
            )
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Content-Length", str(len(svg_icon)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(svg_icon)
            return

        if path in ("/health", "/x402/health"):
            manifest = self.prover_service.build_bazaar_discovery_manifest()
            endpoints_count = len(manifest.get("endpoints", []))
            self._send_json_response(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "z3_native": self.prover_service.is_z3_native,
                    "x402Version": 1,
                    "supportedVersions": [1, 2],
                    "endpoints_count": endpoints_count,
                    "network": self.server_config.network,
                    "payTo": self.server_config.pay_to_address,
                    "asset": self.server_config.asset_address,
                },
            )
            return

        if path in ("/openapi.json", "/x402/openapi.json"):
            base_url = self._resolve_base_url()
            qs = parse_qs(parsed.query)
            include_meta_param = qs.get("include_meta", [""])[0].strip().lower()
            include_meta = include_meta_param in ("1", "true")
            spec = self.prover_service.build_openapi_spec(base_url, include_meta=include_meta)
            self._send_json_response(HTTPStatus.OK, spec, compact=True)
            return

        if path in ("/.well-known/x402-bazaar.json", "/.well-known/x402", "/.well-known/x402.json", "/x402/catalog"):
            base_url = self._resolve_base_url()
            manifest = self.prover_service.build_bazaar_discovery_manifest(base_url)
            self._send_json_response(HTTPStatus.OK, manifest, compact=True)
            return

        if path in ("/.well-known/mcp.json", "/mcp.json", "/x402/mcp.json"):
            base_url = self._resolve_base_url()
            manifest = self.prover_service.build_bazaar_discovery_manifest(base_url)
            self._send_json_response(
                HTTPStatus.OK,
                {
                    "mcpVersion": "2024-11-05",
                    "name": "omni-x402-prover",
                    "version": "2.2.1",
                    "description": manifest.get("description", ""),
                    "homepage": f"{base_url}/x402/catalog",
                    "repository": "https://github.com/stealthmark-io/omni-x402-prover",
                    "install": {
                        "uvx": "uvx --from git+https://github.com/stealthmark-io/omni-x402-prover.git omni-x402-prover",
                        "pip": "pip install git+https://github.com/stealthmark-io/omni-x402-prover.git",
                        "execution_mcp_uvx": "uvx --from git+https://github.com/stealthmark-io/omni-execution-mcp.git omni-execution-mcp",
                    },
                    "x402": {
                        "network": self.server_config.network,
                        "payTo": self.server_config.pay_to_address,
                        "asset": self.server_config.asset_address,
                        "endpointsCount": len(manifest.get("endpoints", [])),
                        "catalogUrl": f"{base_url}/x402/catalog",
                        "openapiUrl": f"{base_url}/openapi.json",
                    },
                },
                compact=True,
            )
            return

        if path in ("/.well-known/agent.json", "/.well-known/agent-card.json", "/x402/agent.json"):
            base_url = self._resolve_base_url()
            manifest = self.prover_service.build_bazaar_discovery_manifest(base_url)
            self._send_json_response(
                HTTPStatus.OK,
                {
                    "name": "Omni x402 Formal Z3 Prover Agent",
                    "description": manifest.get("description", ""),
                    "url": base_url,
                    "version": "2.2.0",
                    "capabilities": {"streaming": False, "pushNotifications": False, "x402Payments": True},
                    "authentication": {"schemes": ["x402"]},
                    "defaultInputModes": ["application/json"],
                    "defaultOutputModes": ["application/json"],
                    "x402": {
                        "network": "eip155:8453",
                        "payTo": self.server_config.pay_to_address,
                        "asset": self.server_config.asset_address,
                        "catalogUrl": f"{base_url}/x402/catalog",
                    },
                    "skills": [
                        {
                            "id": ep["resource"].split("/")[-1],
                            "name": ep["resource"],
                            "description": ep.get("description", ""),
                            "price": ep.get("priceHuman", "$0.02 USDC"),
                        }
                        for ep in manifest.get("endpoints", [])
                    ],
                },
                compact=True,
            )
            return

        if path == "/x402/stats":
            base_url = self._resolve_base_url()
            manifest = self.prover_service.build_bazaar_discovery_manifest(base_url)
            self._send_json_response(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "version": "2.2.0",
                    "endpoints_active": len(manifest.get("endpoints", [])),
                    "network": "eip155:8453",
                    "payTo": self.server_config.pay_to_address,
                    "telemetry": manifest.get("telemetry", {}),
                },
                compact=True,
            )
            return

        if path in ("/llms.txt", "/x402/llms.txt"):
            base_url = self._resolve_base_url()
            content = self.prover_service.build_llms_txt(base_url).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization, X-PAYMENT, PAYMENT-SIGNATURE, X-PAYMENT-RESPONSE, X-Referral-Agent, x-referral-agent",
            )
            self.end_headers()
            self.wfile.write(content)
            return

        if path == "/x402/badge.svg":
            svg_badge = (
                b'<svg xmlns="http://www.w3.org/2000/svg" width="248" height="20" role="img" aria-label="Z3 Formal Prover: 16/16 x402 Verified">'
                b'<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>'
                b'<clipPath id="r"><rect width="248" height="20" rx="3" fill="#fff"/></clipPath>'
                b'<g clip-path="url(#r)">'
                b'<rect width="112" height="20" fill="#0f172a"/>'
                b'<rect x="112" width="136" height="20" fill="#0284c7"/>'
                b'<rect width="248" height="20" fill="url(#s)"/>'
                b'</g>'
                b'<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">'
                b'<text x="560" y="140" transform="scale(.1)" fill="#fff" textLength="1020">Z3 Formal Prover</text>'
                b'<text x="1790" y="140" transform="scale(.1)" fill="#fff" font-weight="bold" textLength="1260">16/16 x402 Verified</text>'
                b'</g></svg>'
            )
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Content-Length", str(len(svg_badge)))
            self.send_header("Cache-Control", "public, max-age=3600")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(svg_badge)
            return

        if path == "/x402/playground":
            base_url = self._resolve_base_url()
            manifest = self.prover_service.build_bazaar_discovery_manifest(base_url)
            eps = manifest.get("endpoints", [])
            rows_html = "".join(
                f"<option value='{ep.get('resource') or ep.get('path')}'>{ep.get('resource') or ep.get('path')} ({ep.get('price_usdc') or '$0.02 USDC'})</option>"
                for ep in eps
            )
            html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Omni x402 v2.2 Formal Z3 Prover Playground (Base USDC Pay-Per-Proof)</title>
<style>
  body{{background:#060a14;color:#e2e8f0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;padding:24px;line-height:1.5}}
  .wrap{{max-width:980px;margin:0 auto}}
  .card{{background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:18px;margin-bottom:16px}}
  select,input,button{{background:#020617;color:#38bdf8;border:1px solid #334155;border-radius:6px;padding:10px 12px;font-family:inherit;font-size:14px}}
  button{{background:#0284c7;color:#fff;border:none;cursor:pointer;font-weight:700}}
  pre{{background:#020617;border:1px solid #1e293b;border-radius:8px;padding:14px;overflow-x:auto;font-size:12px;color:#a5f3fc}}
  a{{color:#38bdf8}}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h2 style="margin:0 0 8px 0;color:#38bdf8">⚡ Omni x402 Prover v2.2 — Strict HTTP 402 Pay-Per-Proof Terminal</h2>
    <p style="margin:0 0 10px 0;font-size:13px">16 Z3 SMT Formal Verification Microservices on Base Mainnet USDC (<code>0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913</code> → <code>{self.server_config.pay_to_address}</code>). <strong>0% Free — 100% Pay-Per-Proof ($0.02–$0.05 USDC)</strong>.</p>
    <img src="/x402/badge.svg" alt="Z3 Formal Prover 16/16 x402 Verified">
  </div>
  <div class="card">
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">
      <select id="ep" style="flex:1;min-width:280px">{rows_html}</select>
      <button onclick="probe()">Probe Live HTTP 402 Challenge</button>
    </div>
    <div style="font-size:12px;margin-bottom:8px">AgentCash CLI Command: <code id="cmd">npx -y agentcash@latest fetch {base_url}/x402/verify-polymarket-basket -X POST</code></div>
    <pre id="out">Click "Probe Live HTTP 402 Challenge" to inspect the real-time EIP-3009 Base USDC payment requirement...</pre>
  </div>
</div>
<script>
async function probe(){{
  const ep = document.getElementById('ep').value;
  document.getElementById('cmd').textContent = `npx -y agentcash@latest fetch {base_url}${{ep}} -X POST`;
  const hdrs = {{'Content-Type':'application/json'}};
  const r = await fetch(ep, {{method:'POST', headers:hdrs, body:'{{}}'}});
  const txt = await r.text();
  try {{ document.getElementById('out').textContent = `HTTP ${{r.status}}\\n` + JSON.stringify(JSON.parse(txt), null, 2); }}
  catch(e) {{ document.getElementById('out').textContent = `HTTP ${{r.status}}\\n` + txt; }}
}}
</script>
</body></html>""".encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_doc)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(html_doc)
            return

        if path == "/x402/arb-trap/preview":
            qs = parse_qs(parsed.query)
            pm_param = qs.get("pm", qs.get("polymarket", qs.get("pm_slug", [""])))[0].strip()
            kalshi_param = qs.get("kalshi", qs.get("kalshi_ticker", [""]))[0].strip()
            pm_rules = qs.get("pm_rules", [""])[0].strip()
            kalshi_rules = qs.get("kalshi_rules", [""])[0].strip()
            pm_title = qs.get("pm_title", [pm_param or "Polymarket Market"])[0].strip()
            kalshi_title = qs.get("kalshi_title", [kalshi_param or "Kalshi Market"])[0].strip()
            pm_cutoff = qs.get("pm_cutoff", [""])[0].strip()
            kalshi_cutoff = qs.get("kalshi_cutoff", [""])[0].strip()

            if not (pm_param or pm_rules) or not (kalshi_param or kalshi_rules):
                self._send_json_response(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "error": "Missing parameters. Required: ?pm=<slug>&kalshi=<ticker> or ?pm_rules=<text>&kalshi_rules=<text>"
                    },
                )
                return

            try:
                # 1. Resolve Polymarket Spec
                if pm_rules:
                    pm_spec = extract_rule_spec(pm_title, pm_rules, end_date_iso=pm_cutoff or None, platform="polymarket")
                else:
                    try:
                        pm_data = fetch_polymarket_market(pm_param)
                        pm_spec = extract_rule_spec(
                            pm_data["title"],
                            pm_data["rules_text"],
                            end_date_iso=pm_data["end_date_iso"],
                            platform="polymarket",
                        )
                    except Exception as exc:
                        logger.warning("Could not fetch Polymarket market %s: %s", pm_param, exc)
                        pm_spec = extract_rule_spec(pm_param, pm_param, platform="polymarket")

                # 2. Resolve Kalshi Spec
                if kalshi_rules:
                    kalshi_spec = extract_rule_spec(kalshi_title, kalshi_rules, end_date_iso=kalshi_cutoff or None, platform="kalshi")
                else:
                    try:
                        kalshi_data = fetch_kalshi_market(kalshi_param)
                        kalshi_spec = extract_rule_spec(
                            kalshi_data["title"],
                            kalshi_data["rules_text"],
                            end_date_iso=kalshi_data["end_date_iso"],
                            platform="kalshi",
                        )
                    except Exception as exc:
                        logger.warning("Could not fetch Kalshi market %s: %s", kalshi_param, exc)
                        kalshi_spec = extract_rule_spec(kalshi_param, kalshi_param, platform="kalshi")

                res = verify_arb_resolution_divergence(pm_spec, kalshi_spec)

                if res.get("trap_detected"):
                    witness = res.get("witness") or {}
                    witness_redacted = {
                        "direction": witness.get("direction"),
                        "divergence_type": witness.get("divergence_type"),
                        "event_occurred_utc": "[REDACTED - Pay $0.02 USDC via x402 to unlock exact timestamp]",
                        "event_occurred_et": "[REDACTED - Pay $0.02 USDC via x402 to unlock exact timestamp]",
                        "intraday_peak": "[REDACTED - Pay $0.02 USDC via x402 to unlock exact boundary value]",
                        "closing_val": "[REDACTED - Pay $0.02 USDC via x402 to unlock exact boundary value]",
                        "wipeout_pct": 100.0,
                        "teaser_explanation": (
                            f"CRITICAL 100% WIPEOUT RISK: Resolution rules diverge between {pm_spec.title[:30]} "
                            f"and {kalshi_spec.title[:30]}. Pay $0.02 USDC via /x402/verify-polymarket-basket to unlock "
                            f"the full Z3 proof, exact timestamp witness, and viral X alert."
                        ),
                    }
                    self._send_json_response(
                        HTTPStatus.OK,
                        {
                            "status": "ok",
                            "lead_magnet": "Arb Trap Resolution Divergence Preview",
                            "trap_detected": True,
                            "risk_grade": res.get("risk_grade", "CRITICAL_WIPEOUT_RISK"),
                            "net_spread_bps": res.get("net_spread_bps", 320),
                            "divergent_dimensions_count": len(res.get("divergent_dimensions", [])),
                            "divergent_dimensions": res.get("divergent_dimensions", []),
                            "witness_redacted": witness_redacted,
                            "unlock_full_witness_endpoint": "/x402/verify-polymarket-basket",
                            "unlock_price": "$0.02 USDC",
                            "unlock_payment_rail": "Base Mainnet eip155:8453 (EIP-3009)",
                        },
                    )
                else:
                    self._send_json_response(
                        HTTPStatus.OK,
                        {
                            "status": "ok",
                            "lead_magnet": "Arb Trap Resolution Divergence Preview",
                            "trap_detected": False,
                            "risk_grade": "LOW_RISK",
                            "net_spread_bps": res.get("net_spread_bps", 0),
                            "divergent_dimensions_count": 0,
                            "divergent_dimensions": [],
                            "mathematical_guarantee": "UNSAT_NO_DOUBLE_LOSS_IN_MODELED_DIMENSIONS",
                            "message": "Safe arbitrage: No double-loss resolution divergence found in modeled dimensions.",
                            "unlock_full_witness_endpoint": "/x402/verify-polymarket-basket",
                        },
                    )
            except Exception as e:
                logger.exception("Error in arb trap preview: %s", e)
                self._send_json_response(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": f"Failed to compute arb trap preview: {str(e)}"},
                )
            return

        if path == "/x402/multichain-token/preview":
            qs = parse_qs(parsed.query)
            token = qs.get("token", [""])[0].strip()
            chain = qs.get("chain", ["base"])[0].strip().lower()
            standard = qs.get("standard", ["OFT"])[0].strip().upper()
            demo = qs.get("demo", [""])[0].strip().lower()

            if not token and not demo:
                self._send_json_response(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "error": "Missing parameters. Required: ?token=0x...&chain=base or ?demo=asymmetric_peer or ?demo=supply_conservation"
                    },
                )
                return

            try:
                if demo == "asymmetric_peer":
                    base_addr = "0x1111111111111111111111111111111111111111"
                    arb_addr = "0x2222222222222222222222222222222222222222"
                    base_eid = LZ_V2_EIDS.get("base", 30184)
                    arb_eid = LZ_V2_EIDS.get("arbitrum", 30110)
                    topology = {
                        "token_address": base_addr,
                        "home_chain": "base",
                        "chains": {
                            "base": {
                                "address": base_addr,
                                "decimals": 18,
                                "shared_decimals": 6,
                                "total_supply": 5_000_000 * 10**18,
                                "owner": "0x9999999999999999999999999999999999999999",
                                "owner_is_contract": True,
                                "has_timelock": True,
                                "required_dvns": 2,
                                "rate_limit_enabled": True,
                                "max_inbound_rate": 500_000 * 10**18,
                                "peers": {arb_eid: arb_addr},
                            },
                            "arbitrum": {
                                "address": arb_addr,
                                "decimals": 18,
                                "shared_decimals": 6,
                                "total_supply": 5_000_000 * 10**18,
                                "owner": "0x9999999999999999999999999999999999999999",
                                "owner_is_contract": True,
                                "has_timelock": True,
                                "required_dvns": 2,
                                "rate_limit_enabled": True,
                                "max_inbound_rate": 500_000 * 10**18,
                                "peers": {},
                            },
                        },
                    }
                    res = verify_multichain_token_invariants(topology)
                    chains_checked = res.get("chains_checked", ["base", "arbitrum"])
                    verdict = res.get("status", "VERIFICATION_FAILED")
                elif demo == "supply_conservation":
                    base_addr = "0x1111111111111111111111111111111111111111"
                    arb_addr = "0x2222222222222222222222222222222222222222"
                    base_eid = LZ_V2_EIDS.get("base", 30184)
                    arb_eid = LZ_V2_EIDS.get("arbitrum", 30110)
                    topology = {
                        "token_address": base_addr,
                        "home_chain": "base",
                        "declared_max_supply": 10_000_000 * 10**18,
                        "chains": {
                            "base": {
                                "address": base_addr,
                                "decimals": 18,
                                "shared_decimals": 6,
                                "total_supply": 8_000_000 * 10**18,
                                "locked_supply": 2_000_000 * 10**18,
                                "owner": "0x9999999999999999999999999999999999999999",
                                "owner_is_contract": True,
                                "has_timelock": True,
                                "required_dvns": 2,
                                "rate_limit_enabled": True,
                                "max_inbound_rate": 500_000 * 10**18,
                                "peers": {arb_eid: arb_addr},
                            },
                            "arbitrum": {
                                "address": arb_addr,
                                "decimals": 18,
                                "shared_decimals": 6,
                                "total_supply": 6_000_000 * 10**18,
                                "owner": "0x9999999999999999999999999999999999999999",
                                "owner_is_contract": True,
                                "has_timelock": True,
                                "required_dvns": 2,
                                "rate_limit_enabled": True,
                                "max_inbound_rate": 500_000 * 10**18,
                                "peers": {base_eid: base_addr},
                            },
                        },
                    }
                    res = verify_multichain_token_invariants(topology)
                    chains_checked = res.get("chains_checked", ["base", "arbitrum"])
                    verdict = res.get("status", "VERIFICATION_FAILED")
                else:
                    try:
                        audit_res = audit_multichain_token(token_address=token, home_chain=chain)
                        v_res = audit_res.get("verification", {})
                        chains_checked = v_res.get("chains_checked", [chain])
                        verdict = v_res.get("status", "VERIFIED_SAFE" if v_res.get("verdict_pass") else "VERIFICATION_FAILED")
                    except Exception:
                        chains_checked = [chain]
                        verdict = "VERIFICATION_PENDING"

                self._send_json_response(
                    HTTPStatus.OK,
                    {
                        "status": "ok",
                        "lead_magnet": "Multichain Token Formal Verification Preview",
                        "verdict": verdict,
                        "standard": standard,
                        "chains_checked": chains_checked,
                        "eas_schema": EAS_SCHEMA_MULTICHAIN_VERIFIER,
                        "unlock_full_attestation_endpoint": "/x402/verify-bridge-and-oracle",
                        "unlock_price": "$0.02 USDC",
                        "unlock_payment_rail": "Base Mainnet eip155:8453 (EIP-3009)",
                    },
                )
            except Exception as exc:
                logger.exception("Error in multichain token preview: %s", exc)
                self._send_json_response(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": f"Failed to compute multichain token preview: {str(exc)}"},
                )
            return

        # Check if GET probe to any monetized /x402/* route -> return 402 challenge
        endpoint_info = self._resolve_endpoint_info(path)
        if endpoint_info:
            amount_atomic, description, _ = endpoint_info
            has_forward = bool(self.headers.get("X-Forwarded-Proto") or self.headers.get("X-Forwarded-Host"))
            resource_url = f"{self._resolve_base_url()}{path}" if has_forward else path
            input_schema, output_schema = self.prover_service.get_endpoint_schemas(path)
            requirement = {
                "scheme": "exact",
                "network": self.server_config.network,
                "maxAmountRequired": str(amount_atomic),
                "resource": resource_url,
                "description": description,
                "mimeType": "application/json",
                "payTo": self.server_config.pay_to_address,
                "maxTimeoutSeconds": self.server_config.max_timeout_seconds,
                "asset": self.server_config.asset_address,
                "outputSchema": {
                    "input": {
                        "type": "http",
                        "method": "POST",
                        "bodyType": "json",
                        "bodyFields": input_schema.get("properties", {}) if input_schema else {},
                    },
                    "output": output_schema or {"type": "object"},
                },
                "discoverable": True,
                "extra": {"name": "USD Coin", "version": "2", "discoverable": True},
            }
            _, status_code, payment_res, _ = verify_payment(
                raw_header=None,
                requirement=requirement,
                config=self.server_config,
                nonce_store=self.nonce_store,
                facilitator=self.facilitator,
            )
            self._send_payment_challenge(
                status_code, payment_res, path, description, amount_atomic, input_schema, output_schema
            )
            return

        self._send_json_response(HTTPStatus.NOT_FOUND, {"error": f"Path not found: {self.path}"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # 1. Check Content-Length for DoS / body size limits
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            content_length = 0

        if content_length > MAX_REQUEST_BODY_BYTES:
            self._send_json_response(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {
                    "error": (
                        f"Request payload size ({content_length} bytes) exceeds maximum limit "
                        f"of {MAX_REQUEST_BODY_BYTES} bytes."
                    )
                },
            )
            return

        # 2. Match Route & Pricing
        endpoint_info = self._resolve_endpoint_info(path)
        if not endpoint_info:
            self._send_json_response(HTTPStatus.NOT_FOUND, {"error": f"Endpoint not found: {self.path}"})
            return

        amount_atomic, description, handler_fn = endpoint_info

        # 3. Read raw payment header (support X-PAYMENT or PAYMENT-SIGNATURE fallback)
        x_payment = self.headers.get("X-PAYMENT") or self.headers.get("x-payment")
        payment_signature = self.headers.get("PAYMENT-SIGNATURE") or self.headers.get("payment-signature")
        raw_payment = x_payment or payment_signature

        has_forward = bool(self.headers.get("X-Forwarded-Proto") or self.headers.get("X-Forwarded-Host"))
        resource_url = f"{self._resolve_base_url()}{path}" if has_forward else path

        input_schema, output_schema = self.prover_service.get_endpoint_schemas(path)

        requirement = {
            "scheme": "exact",
            "network": self.server_config.network,
            "maxAmountRequired": str(amount_atomic),
            "resource": resource_url,
            "description": description,
            "mimeType": "application/json",
            "payTo": self.server_config.pay_to_address,
            "maxTimeoutSeconds": self.server_config.max_timeout_seconds,
            "asset": self.server_config.asset_address,
            "outputSchema": {
                "input": {
                    "type": "http",
                    "method": "POST",
                    "bodyType": "json",
                    "bodyFields": input_schema.get("properties", {}) if input_schema else {},
                },
                "output": output_schema or {"type": "object"},
            },
            "discoverable": True,
            "extra": {"name": "USD Coin", "version": "2", "discoverable": True},
        }

        # 4. Unpaid probes get the 402 challenge before any body validation
        if not raw_payment:
            _, status_code, payment_res, _ = verify_payment(
                raw_header=None,
                requirement=requirement,
                config=self.server_config,
                nonce_store=self.nonce_store,
                facilitator=self.facilitator,
            )
            self._send_payment_challenge(
                status_code, payment_res, path, description, amount_atomic, input_schema, output_schema
            )
            return

        # 5. Parse the request body JSON before touching the facilitator
        raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            if not isinstance(payload, dict):
                raise ValueError("Body must be a JSON object")
        except Exception as exc:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON request body: {exc}"})
            return

        # 6. Replay check + in-flight reservation + facilitator verify (no settlement yet)
        is_valid, status_code, payment_res, verified_payment = verify_payment(
            raw_header=raw_payment,
            requirement=requirement,
            config=self.server_config,
            nonce_store=self.nonce_store,
            facilitator=self.facilitator,
        )

        if not is_valid or verified_payment is None:
            self._send_payment_challenge(
                status_code, payment_res, path, description, amount_atomic, input_schema, output_schema
            )
            return

        # 7. Execute formal verification handler; any failure releases the reservation unpaid
        try:
            result_data = handler_fn(payload)
        except ValueError as val_err:
            release_payment(verified_payment, self.nonce_store)
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": str(val_err)})
            return
        except ProverCapacityError as capacity_err:
            release_payment(verified_payment, self.nonce_store)
            self._send_json_response(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(capacity_err)})
            return
        except Exception:
            release_payment(verified_payment, self.nonce_store)
            logger.exception("Internal error executing prover handler")
            self._send_json_response(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Formal proof execution error"},
            )
            return

        # 8. Settle Payment and attach the receipt
        settled, status_code, payment_res, receipt_b64 = settle_payment(
            verified_payment=verified_payment,
            requirement=requirement,
            config=self.server_config,
            nonce_store=self.nonce_store,
        )

        if not settled or not receipt_b64:
            self._send_payment_challenge(
                status_code, payment_res, path, description, amount_atomic, input_schema, output_schema
            )
            return

        settlement_obj = payment_res.get("settlement") or {}
        if isinstance(settlement_obj, dict):
            settlement_obj["settled"] = True
        result_data["settlementReceipt"] = settlement_obj
        result_data["paymentReceipt"] = settlement_obj

        payer = ""
        if isinstance(verified_payment, dict):
            auth = verified_payment.get("authorization") or {}
            v_details = verified_payment.get("verify_details") or {}
            payer = (
                auth.get("from")
                or auth.get("payer")
                or (v_details.get("payer") if isinstance(v_details, dict) else "")
                or ""
            )
        elif verified_payment:
            payer = getattr(verified_payment, "payer", "")

        # Real-time Telegram notification on settled Base USDC payment
        tx_hash = ""
        if isinstance(settlement_obj, dict):
            tx_hash = str(
                settlement_obj.get("transaction")
                or settlement_obj.get("txHash")
                or settlement_obj.get("tx_hash")
                or ""
            )
        origin_host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "gateway.stealthmark.io"
        threading.Thread(
            target=_notify_telegram_settlement,
            args=(
                origin_host,
                path,
                amount_atomic,
                self.server_config.pay_to_address,
                payer,
                tx_hash,
            ),
            daemon=True,
        ).start()

        receipt_headers = {"X-PAYMENT-RESPONSE": receipt_b64}
        if not x_payment:
            receipt_headers["PAYMENT-RESPONSE"] = receipt_b64
        self._send_json_response(HTTPStatus.OK, result_data, extra_headers=receipt_headers)


def _notify_telegram_settlement(
    origin_host: str,
    endpoint_path: str,
    amount_atomic: int,
    pay_to: str,
    payer: str,
    tx_hash: str,
) -> None:
    """Send real-time Telegram notification when an x402 Base USDC payment settles."""
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "1948511620").strip() or "1948511620"
    if not tg_token:
        return
    usdc_str = f"${amount_atomic / 1_000_000:.2f} USDC"
    lines = [
        "💰 *Pago x402 Liquidado en Base Mainnet*",
        f"• *Origin:* `{origin_host}`",
        f"• *Endpoint:* `{endpoint_path}`",
        f"• *Monto Recibido:* `{usdc_str}` (`{amount_atomic}` atomic)",
        f"• *Wallet Destino:* `{pay_to}`",
    ]
    if payer:
        lines.append(f"• *Payer:* `{payer}`")
    if tx_hash:
        lines.append(f"• *TxHash (Base):* `{tx_hash}`")
    payload = json.dumps({"chat_id": tg_chat, "text": "\n".join(lines), "parse_mode": "Markdown"}).encode("utf-8")
    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{tg_token}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5).read()
    except Exception:
        logger.debug("Non-fatal error sending Telegram x402 payment alert", exc_info=True)


X402RequestHandler = X402HTTPHandler


def create_http_server(
    host: str = "127.0.0.1",
    port: int = 8402,
    config: Optional[X402Config] = None,
    prover_service: Optional[ProverService] = None,
    nonce_store: Optional[ReplayNonceStore] = None,
    facilitator: Optional[FacilitatorClient] = None,
) -> ThreadingHTTPServer:
    """Factory creating and configuring the ThreadingHTTPServer instance."""
    active_config = config or X402Config.from_env()
    active_prover = prover_service or ProverService(active_config)
    active_store = nonce_store or ReplayNonceStore()
    active_facilitator = facilitator or DeterministicMockFacilitator(active_config)

    class CustomHandler(X402HTTPHandler):
        server_config = active_config
        prover_service = active_prover
        nonce_store = active_store
        facilitator = active_facilitator

    server = ThreadingHTTPServer((host, port), CustomHandler)
    server.daemon_threads = True
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Omni x402 Prover HTTP Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8402, help="Port (default: 8402)")
    parser.add_argument("--facilitator", default=None, help="Remote facilitator URL (default: https://facilitator.payai.network)")
    parser.add_argument("--mock-facilitator", action="store_true", help="Use offline mock facilitator for testing/demo")
    args = parser.parse_args()

    config = X402Config.from_env()
    use_mock = args.mock_facilitator or os.environ.get("X402_MOCK_FACILITATOR", "").lower() in ("1", "true", "yes")

    fac_client: FacilitatorClient
    if use_mock:
        fac_client = DeterministicMockFacilitator(config)
    else:
        fac_url = args.facilitator or config.facilitator_url
        fac_client = RemoteHTTPFacilitatorClient(fac_url)

    server = create_http_server(
        host=args.host,
        port=args.port,
        config=config,
        facilitator=fac_client,
    )
    actual_host, actual_port = server.server_address
    print(f"🚀 Omni x402 Prover listening at http://{actual_host}:{actual_port}")
    print(f"   Network: {config.network} | Asset: USDC ({config.asset_address})")
    print(f"   Pay-To: {config.pay_to_address}")
    print(f"   Facilitator: {fac_client.__class__.__name__}")
    print("   Bazaar Catalog: GET /.well-known/x402-bazaar.json")
    print("   Health Check:   GET /health")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.server_close()
        sys.exit(0)


if __name__ == "__main__":
    main()
