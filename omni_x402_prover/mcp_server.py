"""
Omni x402 Prover Model Context Protocol (MCP) Server.

Implements JSON-RPC 2.0 stdio MCP server compatible with Coinbase Payments MCP.
Exposes formal verification tools with automatic x402 Payment Required challenges,
replay-resistant settlement, and verifiable cryptographic proof results.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

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

SERVER_NAME = "omni-x402-prover"
SERVER_VERSION = "2.2.0"
PROTOCOL_VERSION = "2024-11-05"

logger = logging.getLogger("omni_x402_prover.mcp")


def get_tools_registry(config: X402Config) -> List[Dict[str, Any]]:
    """Return JSON schemas for the 5 MCP tools."""
    return [
        {
            "name": "x402_bazaar_catalog",
            "description": (
                "Free discovery tool: returns the Coinbase x402 Bazaar semantic catalog, "
                "available verification endpoints, pricing in Base USDC, and schema definitions."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        {
            "name": "x402_verify_vault_rounding",
            "description": (
                f"Paid tool ({config.price_vault_atomic} Base USDC atomic): Formal Z3 verification "
                "of ERC-4626 / Euler / Meteora vault share rounding, donation attacks, "
                "and zero-share inflation vulnerabilities."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "deposit_fn_code": {
                        "type": "string",
                        "description": "Python snippet or AST defining preview_deposit(deposit, total_assets, total_shares)",
                    },
                    "redeem_fn_code": {
                        "type": "string",
                        "description": "Python snippet or AST defining preview_redeem(shares, total_assets, total_shares)",
                    },
                    "max_assets": {"type": "integer", "default": 10000},
                    "max_shares": {"type": "integer", "default": 10000},
                    "check_zero_share_mint": {"type": "boolean", "default": False},
                    "paymentHeader": {
                        "type": "string",
                        "description": "x402 Base64 or JSON payment authorization string (if not in _meta.x402Payment)",
                    },
                },
                "required": ["deposit_fn_code", "redeem_fn_code"],
            },
        },
        {
            "name": "x402_verify_polymarket_basket",
            "description": (
                f"Paid tool ({config.price_polymarket_atomic} Base USDC atomic): Formal verification "
                "of Polymarket NegRisk / Conditional Token solvency and Dutch-book net edge."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "outcome_ask_prices": {
                        "type": "array",
                        "items": {"type": "number"},
                        "description": "Best ask prices across all basket outcomes",
                    },
                    "fee_bps": {"type": "integer", "default": 0},
                    "payout_per_share": {"type": "number", "default": 10000},
                    "custom_conversion_formula": {"type": ["string", "null"]},
                    "num_outcomes": {"type": "integer"},
                    "convert_no_subset_size": {"type": "integer"},
                    "paymentHeader": {
                        "type": "string",
                        "description": "x402 Base64 or JSON payment authorization string (if not in _meta.x402Payment)",
                    },
                },
                "required": ["outcome_ask_prices"],
            },
        },
        {
            "name": "x402_verify_zk_or_bitvec",
            "description": (
                f"Paid tool ({config.price_zk_bitvec_atomic} Base USDC atomic): Formal Z3 verification "
                "of ZK circuit witness uniqueness (soundness) or BitVector integer cast truncation."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "mode": {"type": "string", "enum": ["zk", "bitvec"]},
                    "expr": {"type": "string", "description": "Expression for bitvec check (e.g. 'a + b')"},
                    "var_bitwidths": {"type": "object", "description": "Dictionary of variable bitwidths (e.g. {'a': 8, 'b': 8})"},
                    "target_bitwidth": {"type": "integer", "default": 64},
                    "preconditions": {"type": "array", "items": {"type": "string"}},
                    "public_inputs": {"type": "array", "items": {"type": "string"}},
                    "witness_vars": {"type": "array", "items": {"type": "string"}},
                    "output_var": {"type": "string"},
                    "constraints_exprs": {"type": "array", "items": {"type": "string"}},
                    "paymentHeader": {
                        "type": "string",
                        "description": "x402 Base64 or JSON payment authorization string (if not in _meta.x402Payment)",
                    },
                },
            },
        },
        {
            "name": "x402_verify_differential_spec",
            "description": (
                f"Paid tool ({config.price_differential_atomic} Base USDC atomic): Formal differential "
                "consensus equivalence verification between code_a and code_b across boundary grids."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "code_a": {"type": "string", "description": "Reference implementation source code"},
                    "code_b": {"type": "string", "description": "Candidate implementation source code"},
                    "arg_names": {"type": "array", "items": {"type": "string"}, "description": "Function argument names"},
                    "domain_bounds": {"type": "array", "items": {"type": "integer"}},
                    "fuzz_iterations": {"type": "integer", "default": 256},
                    "seed": {"type": "integer", "default": 42},
                    "unsigned_bit_width": {"type": "integer"},
                    "paymentHeader": {
                        "type": "string",
                        "description": "x402 Base64 or JSON payment authorization string (if not in _meta.x402Payment)",
                    },
                },
                "required": ["code_a", "code_b", "arg_names"],
            },
        },
        {
            "name": "x402_verify_forensic_graph",
            "description": (
                f"Paid tool ({config.price_forensic_graph_atomic} Base USDC atomic): On-chain "
                "and PSP forensic graph engine: Tarjan cyclic loop collapse, Jupiter Lend receipt handover, "
                "bridge hop correlation, and taint propagation."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "transactions": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "List of transaction edges",
                    },
                    "tainted_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Seed exploit or tainted wallet addresses",
                    },
                    "protocol_nodes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Known protocol/vault/bridge nodes excluded from cyclic collapse",
                    },
                    "bridge_nodes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Privacy bridge/swap nodes for entry-exit correlation",
                    },
                    "max_window_seconds": {"type": "integer", "default": 259200},
                    "amount_tolerance": {"type": "number", "default": 0.05},
                    "bridge_max_window_seconds": {"type": "integer", "default": 7200},
                    "bridge_fee_tolerance": {"type": "number", "default": 0.05},
                    "task": {"type": "object", "description": "Optional SwarmTaskV2 payload"},
                    "paymentHeader": {
                        "type": "string",
                        "description": "x402 Base64 or JSON payment authorization string (if not in _meta.x402Payment)",
                    },
                },
            },
        },
        {
            "name": "x402_verify_ast_blast_radius",
            "description": (
                f"Paid tool ({config.price_blast_radius_atomic} Base USDC atomic): Deterministic "
                "2-hop AST call-graph blast-radius and upstream-to-fork patch-gap readiness verification."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "patch_text": {"type": "string", "description": "Unified git diff of the patch"},
                    "modified_symbols": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Explicit list of modified symbol names",
                    },
                    "graph_data": {"type": "object", "description": "NetworkX/Graphify node-link format graph data"},
                    "source_code": {"type": "string", "description": "Python source code to extract call-graph from"},
                    "fork_code": {"type": "string", "description": "Fork repository source code"},
                    "upstream_patch_spec": {"type": "object", "description": "Upstream security patch specification"},
                    "paymentHeader": {
                        "type": "string",
                        "description": "x402 Base64 or JSON payment authorization string (if not in _meta.x402Payment)",
                    },
                },
            },
        },
        {
            "name": "x402_verify_erc4626_inflation_guard",
            "description": (
                f"Paid tool ({config.price_erc4626_inflation_atomic} Base USDC atomic): Formal verification "
                "of ERC-4626 vault virtual share offset and zero-share inflation attack prevention."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "virtual_shares_offset": {"type": "integer", "default": 0},
                    "virtual_assets_offset": {"type": "integer", "default": 0},
                    "attacker_initial_deposit": {"type": "integer", "default": 1},
                    "attacker_donation": {"type": "integer", "default": 10000},
                    "victim_deposit": {"type": "integer", "default": 9999},
                    "deposit_fn_code": {"type": "string"},
                    "redeem_fn_code": {"type": "string"},
                    "paymentHeader": {"type": "string"},
                },
            },
        },
        {
            "name": "x402_verify_amm_constant_product",
            "description": (
                f"Paid tool ({config.price_amm_constant_product_atomic} Base USDC atomic): Formal verification "
                "of constant-product AMM k invariant preservation and exact integer rounding direction."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "reserve_x": {"type": "integer"},
                    "reserve_y": {"type": "integer"},
                    "amount_in": {"type": "integer"},
                    "amount_out": {"type": "integer"},
                    "fee_bps": {"type": "integer", "default": 30},
                    "rounding_direction": {"type": "string", "enum": ["down", "up"], "default": "down"},
                    "paymentHeader": {"type": "string"},
                },
                "required": ["reserve_x", "reserve_y"],
            },
        },
        {
            "name": "x402_verify_crosschain_bridge_memo",
            "description": (
                f"Paid tool ({config.price_crosschain_memo_atomic} Base USDC atomic): Crosschain bridge "
                "memo syntax, injection-prevention, and affiliate fee ceiling audit (THORChain/Maya)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "memo": {"type": "string"},
                    "max_affiliate_bps": {"type": "integer", "default": 100},
                    "require_slippage_limit": {"type": "boolean", "default": True},
                    "paymentHeader": {"type": "string"},
                },
                "required": ["memo"],
            },
        },
        {
            "name": "x402_verify_cardano_eutxo_conservation",
            "description": (
                f"Paid tool ({config.price_cardano_eutxo_atomic} Base USDC atomic): Cardano eUTxO value "
                "conservation, multi-asset balance, minUTxO compliance, and Plutus double satisfaction audit."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "inputs": {"type": "array", "items": {"type": "object"}},
                    "outputs": {"type": "array", "items": {"type": "object"}},
                    "minted": {"type": "object"},
                    "fee_lovelace": {"type": "integer", "default": 200000},
                    "min_utxo_lovelace": {"type": "integer", "default": 1000000},
                    "paymentHeader": {"type": "string"},
                },
                "required": ["inputs", "outputs"],
            },
        },
        {
            "name": "x402_verify_mev_sandwich_bound",
            "description": (
                f"Paid tool ({config.price_mev_sandwich_atomic} Base USDC atomic): Analytical binary-search "
                "MEV sandwich profitability bound and optimal frontrun/backrun impact verification."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "reserve_in": {"type": "integer"},
                    "reserve_out": {"type": "integer"},
                    "user_amount_in": {"type": "integer"},
                    "slippage_bps": {"type": "integer", "default": 100},
                    "fee_bps": {"type": "integer", "default": 30},
                    "attacker_gas_cost_in": {"type": "integer", "default": 0},
                    "paymentHeader": {"type": "string"},
                },
                "required": ["reserve_in", "reserve_out", "user_amount_in"],
            },
        },
        {
            "name": "x402_verify_permit2_signature_scope",
            "description": (
                f"Paid tool ({config.price_permit2_scope_atomic} Base USDC atomic): Pre-signing audit "
                "for Uniswap Permit2 allowance signatures: unlimited approval, expiration, deadline, and spender."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "spender": {"type": "string"},
                    "amount": {"type": ["integer", "string"]},
                    "expiration": {"type": "integer"},
                    "sig_deadline": {"type": "integer"},
                    "chain_id": {"type": "integer", "default": 8453},
                    "current_timestamp": {"type": "integer"},
                    "max_requested_amount": {"type": "integer"},
                    "trusted_spenders": {"type": "array", "items": {"type": "string"}},
                    "paymentHeader": {"type": "string"},
                },
                "required": ["spender", "amount", "expiration", "sig_deadline"],
            },
        },
        {
            "name": "x402_verify_liquidation_waterfall",
            "description": (
                f"Paid tool ({config.price_liquidation_waterfall_atomic} Base USDC atomic): Lending market "
                "liquidation solvency audit: health factor, close factor, bonus insolvency cap, and bad debt shortfall."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "collateral_value": {"type": "integer"},
                    "debt_value": {"type": "integer"},
                    "liquidation_threshold_bps": {"type": "integer", "default": 8500},
                    "liquidation_bonus_bps": {"type": "integer", "default": 500},
                    "close_factor_bps": {"type": "integer", "default": 5000},
                    "insurance_fund_balance": {"type": "integer", "default": 0},
                    "paymentHeader": {"type": "string"},
                },
                "required": ["collateral_value", "debt_value"],
            },
        },
        {
            "name": "x402_verify_merkle_airdrop_claim",
            "description": (
                f"Paid tool ({config.price_merkle_airdrop_atomic} Base USDC atomic): Merkle airdrop distribution "
                "integrity: double-hash preimage resistance, duplicate claim elimination, and canonical root."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "claims": {"type": "array", "items": {"type": "object"}},
                    "leaf_hash_mode": {"type": "string", "enum": ["double_hash", "single_hash", "raw_64_bytes"], "default": "double_hash"},
                    "paymentHeader": {"type": "string"},
                },
                "required": ["claims"],
            },
        },
        {
            "name": "x402_verify_fiat_crypto_otc_settlement",
            "description": (
                f"Paid tool ({config.price_fiat_crypto_otc_atomic} Base USDC atomic): Fiat-to-crypto OTC "
                "settlement reconciliation: cross-currency FX spread verification, skimming check, and CMP-PSAV certificate."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "fiat_legs": {"type": "array", "items": {"type": ["object", "integer"]}},
                    "crypto_legs": {"type": "array", "items": {"type": ["object", "integer"]}},
                    "agreed_fx_ars_per_usd": {"type": "number"},
                    "max_spread_bps": {"type": "integer", "default": 50},
                    "fee_bps": {"type": "integer", "default": 0},
                    "paymentHeader": {"type": "string"},
                },
                "required": ["fiat_legs", "crypto_legs", "agreed_fx_ars_per_usd"],
            },
        },
        {
            "name": "x402_verify_sar_ed25519_dossier",
            "description": (
                f"Paid tool ({config.price_sar_ed25519_atomic} Base USDC atomic): Synthetic Aperture Radar (SAR) "
                "IUU dark-vessel detection, EEZ territorial intrusion, and Ed25519 RFC 8032 canonical dossier audit."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vessel_id": {"type": "string", "default": "UNKNOWN"},
                    "lat": {"type": "number"},
                    "lon": {"type": "number"},
                    "rcs_db": {"type": "number", "default": 50.0},
                    "ais_active": {"type": "boolean", "default": False},
                    "eez_lat_range": {"type": "array", "items": {"type": "number"}, "default": [-60.0, -40.0]},
                    "eez_lon_range": {"type": "array", "items": {"type": "number"}, "default": [-68.0, -50.0]},
                    "ed25519_pubkey_hex": {"type": "string"},
                    "ed25519_signature_hex": {"type": "string"},
                    "dossier_payload": {"type": ["object", "string"]},
                    "paymentHeader": {"type": "string"},
                },
                "required": ["lat", "lon"],
            },
        },
    ]


get_mcp_tools = get_tools_registry


def handle_jsonrpc_message(
    req: Dict[str, Any],
    config: X402Config,
    prover_service: ProverService,
    nonce_store: ReplayNonceStore,
    facilitator: Optional[FacilitatorClient] = None,
) -> Optional[Dict[str, Any]]:
    """Process a single JSON-RPC 2.0 message."""
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params", {}) or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                },
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": get_tools_registry(config),
            },
        }

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {}) or {}
        meta = params.get("_meta", {}) or {}

        # 1. Free discovery tool
        if tool_name == "x402_bazaar_catalog":
            manifest = prover_service.build_bazaar_discovery_manifest()
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps(manifest, indent=2)}],
                },
            }

        # 2. Match Paid Tools
        tool_pricing_map = {
            "x402_verify_vault_rounding": (
                config.price_vault_atomic,
                "/x402/verify-vault-and-rounding",
                "Formal Z3 verification of ERC-4626 / Euler vault share rounding",
                prover_service.verify_vault_and_rounding,
            ),
            "x402_verify_polymarket_basket": (
                config.price_polymarket_atomic,
                "/x402/verify-polymarket-basket",
                "Formal verification of Polymarket NegRisk / CTF token solvency and Dutch-book edge",
                prover_service.verify_polymarket_basket,
            ),
            "x402_verify_zk_or_bitvec": (
                config.price_zk_bitvec_atomic,
                "/x402/verify-zk-and-bitvec",
                "Formal Z3 verification of ZK witness uniqueness or BitVector integer cast truncation",
                prover_service.verify_zk_and_bitvec,
            ),
            "x402_verify_differential_spec": (
                config.price_differential_atomic,
                "/x402/verify-differential-spec",
                "Differential equivalence verification between code_a and code_b across boundary grids",
                prover_service.verify_differential_spec,
            ),
            "x402_verify_forensic_graph": (
                config.price_forensic_graph_atomic,
                "/x402/verify-forensic-graph",
                "On-chain and PSP forensic graph engine: Tarjan cyclic loop collapse, Jupiter Lend receipt handover, bridge hop correlation, and taint propagation",
                prover_service.verify_forensic_graph,
            ),
            "x402_verify_ast_blast_radius": (
                config.price_blast_radius_atomic,
                "/x402/verify-ast-blast-radius",
                "Deterministic 2-hop AST call-graph blast-radius and upstream-to-fork patch-gap readiness verification",
                prover_service.verify_ast_blast_radius,
            ),
            "x402_verify_erc4626_inflation_guard": (
                config.price_erc4626_inflation_atomic,
                "/x402/verify-erc4626-inflation-guard",
                "Formal verification of ERC-4626 vault virtual share offset and zero-share inflation attack prevention",
                prover_service.verify_erc4626_inflation_guard,
            ),
            "x402_verify_amm_constant_product": (
                config.price_amm_constant_product_atomic,
                "/x402/verify-amm-constant-product",
                "Formal verification of constant-product AMM k invariant preservation and exact integer rounding direction",
                prover_service.verify_amm_constant_product,
            ),
            "x402_verify_crosschain_bridge_memo": (
                config.price_crosschain_memo_atomic,
                "/x402/verify-crosschain-bridge-memo",
                "Crosschain bridge memo syntax, injection-prevention, and affiliate fee ceiling audit (THORChain/Maya)",
                prover_service.verify_crosschain_bridge_memo,
            ),
            "x402_verify_cardano_eutxo_conservation": (
                config.price_cardano_eutxo_atomic,
                "/x402/verify-cardano-eutxo-conservation",
                "Cardano eUTxO value conservation, multi-asset balance, minUTxO compliance, and Plutus double satisfaction audit",
                prover_service.verify_cardano_eutxo_conservation,
            ),
            "x402_verify_mev_sandwich_bound": (
                config.price_mev_sandwich_atomic,
                "/x402/verify-mev-sandwich-bound",
                "Analytical binary-search MEV sandwich profitability bound and optimal frontrun/backrun impact verification",
                prover_service.verify_mev_sandwich_bound,
            ),
            "x402_verify_permit2_signature_scope": (
                config.price_permit2_scope_atomic,
                "/x402/verify-permit2-signature-scope",
                "Pre-signing audit for Uniswap Permit2 allowance signatures: unlimited approval, expiration, deadline, and spender",
                prover_service.verify_permit2_signature_scope,
            ),
            "x402_verify_liquidation_waterfall": (
                config.price_liquidation_waterfall_atomic,
                "/x402/verify-liquidation-waterfall",
                "Lending market liquidation solvency audit: health factor, close factor, bonus insolvency cap, and bad debt shortfall",
                prover_service.verify_liquidation_waterfall,
            ),
            "x402_verify_merkle_airdrop_claim": (
                config.price_merkle_airdrop_atomic,
                "/x402/verify-merkle-airdrop-claim",
                "Merkle airdrop distribution integrity: double-hash preimage resistance, duplicate claim elimination, and canonical root",
                prover_service.verify_merkle_airdrop_claim,
            ),
            "x402_verify_fiat_crypto_otc_settlement": (
                config.price_fiat_crypto_otc_atomic,
                "/x402/verify-fiat-crypto-otc-settlement",
                "Fiat-to-crypto OTC settlement reconciliation: cross-currency FX spread verification, skimming check, and CMP-PSAV certificate",
                prover_service.verify_fiat_crypto_otc_settlement,
            ),
            "x402_verify_sar_ed25519_dossier": (
                config.price_sar_ed25519_atomic,
                "/x402/verify-sar-ed25519-dossier",
                "Synthetic Aperture Radar (SAR) IUU dark-vessel detection, EEZ territorial intrusion, and Ed25519 RFC 8032 canonical dossier audit",
                prover_service.verify_sar_ed25519_dossier,
            ),
        }

        if tool_name not in tool_pricing_map:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown tool: '{tool_name}'"},
            }

        price_atomic, resource_path, desc, handler_fn = tool_pricing_map[tool_name]

        # Extract payment header
        raw_payment = (
            meta.get("x402Payment")
            or meta.get("paymentHeader")
            or arguments.get("paymentHeader")
            or arguments.get("_x402_payment")
        )

        requirement = {
            "scheme": "exact",
            "network": config.network,
            "maxAmountRequired": str(price_atomic),
            "resource": resource_path,
            "description": desc,
            "mimeType": "application/json",
            "payTo": config.pay_to_address,
            "maxTimeoutSeconds": config.max_timeout_seconds,
            "asset": config.asset_address,
            "extra": {"name": "USD Coin", "version": "2"},
        }

        # Verify payment (settlement waits until the handler succeeds)
        is_valid, status_code, payment_res, verified_payment = verify_payment(
            raw_header=str(raw_payment) if raw_payment else None,
            requirement=requirement,
            config=config,
            nonce_store=nonce_store,
            facilitator=facilitator,
        )
        challenge = build_payment_required_response(
            config=config,
            resource_path=resource_path,
            description=desc,
            amount_atomic=price_atomic,
        )

        if not is_valid or verified_payment is None:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                f"Payment Required (x402 HTTP 402): Tool '{tool_name}' requires "
                                f"{price_atomic} atomic Base USDC. Provide EIP-3009 payment authorization "
                                f"in '_meta.x402Payment' or 'arguments.paymentHeader'."
                            ),
                        }
                    ],
                    "_meta": {
                        "x402": challenge,
                        "paymentError": payment_res.get("error"),
                    },
                },
            }

        # Clean tool arguments (strip payment fields before passing to handler)
        clean_args = {k: v for k, v in arguments.items() if k not in ("paymentHeader", "_x402_payment")}

        try:
            proof_result = handler_fn(clean_args)
        except (ValueError, ProverCapacityError) as exc:
            release_payment(verified_payment, nonce_store)
            http_status = 503 if isinstance(exc, ProverCapacityError) else 400
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": f"Error executing verification tool '{tool_name}' (HTTP {http_status}): {exc}",
                        }
                    ],
                    "_meta": {"httpStatus": http_status, "charged": False},
                },
            }
        except Exception:
            release_payment(verified_payment, nonce_store)
            logger.exception("Internal error executing MCP prover tool")
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": f"Error executing verification tool '{tool_name}' (HTTP 500): internal proof error",
                        }
                    ],
                    "_meta": {"httpStatus": 500, "charged": False},
                },
            }

        settled, status_code, payment_res, receipt_b64 = settle_payment(
            verified_payment=verified_payment,
            requirement=requirement,
            config=config,
            nonce_store=nonce_store,
        )
        if not settled or not receipt_b64:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": f"Payment settlement failed for tool '{tool_name}': {payment_res.get('error')}",
                        }
                    ],
                    "_meta": {
                        "x402": challenge,
                        "paymentError": payment_res.get("error"),
                    },
                },
            }

        proof_result["settlementReceipt"] = payment_res.get("settlement")
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "isError": False,
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(proof_result, indent=2),
                    }
                ],
                "_meta": {
                    "x402PaymentResponse": receipt_b64,
                    "settlement": payment_res.get("settlement"),
                },
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: '{method}'"},
    }


def main() -> None:
    """Standard IO server loop for MCP."""
    parser = argparse.ArgumentParser(description="Omni x402 Prover MCP Server")
    parser.add_argument("--facilitator", default=None, help="Remote facilitator URL (default: https://facilitator.payai.network)")
    parser.add_argument("--mock-facilitator", action="store_true", help="Use offline mock facilitator for testing/demo")
    args, _ = parser.parse_known_args()

    config = X402Config.from_env()
    prover_service = ProverService(config)
    nonce_store = ReplayNonceStore()

    use_mock = args.mock_facilitator or os.environ.get("X402_MOCK_FACILITATOR", "").lower() in ("1", "true", "yes")
    facilitator: FacilitatorClient
    if use_mock:
        facilitator = DeterministicMockFacilitator(config)
    else:
        fac_url = args.facilitator or config.facilitator_url
        facilitator = RemoteHTTPFacilitatorClient(fac_url)

    for line in sys.stdin:
        line_str = line.strip()
        if not line_str:
            continue
        try:
            req = json.loads(line_str)
        except json.JSONDecodeError as err:
            resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {err}"},
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue

        resp = handle_jsonrpc_message(
            req,
            config=config,
            prover_service=prover_service,
            nonce_store=nonce_store,
            facilitator=facilitator,
        )
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
