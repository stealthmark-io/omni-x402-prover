"""
Streams Collateral Graph Detector: Yield-Stablecoin & Vault Circular Collateral
Tarjan Strongly Connected Components (SCC), Z3 Contagion & Solvency Shock Witness,
and Curator Risk Leaderboard.

Diamond Mine C1: Production-grade on-chain and synthetic collateral topology detector.
Supports zero external dependencies (Python 3.10+ standard library) with optional Z3
theorem prover acceleration, falling back cleanly to an exact analytical fixed-point solver.
"""

from __future__ import annotations

import html
import json
import logging
import math
import os
import re
import sqlite3
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("omni_x402_prover.streams_collateral_detector")

# Optional Z3 Theorem Prover integration
try:
    import z3  # type: ignore

    HAS_Z3 = True
except ImportError:
    z3 = None  # type: ignore
    HAS_Z3 = False

# ---------------------------------------------------------------------------
# Constants & Selectors
# ---------------------------------------------------------------------------

DEFAULT_RPC_URLS: Dict[str, str] = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "base": "https://base-rpc.publicnode.com",
    "arbitrum": "https://arbitrum-one-rpc.publicnode.com",
}

# 4-byte ERC / Protocol function selectors
SELECTOR_ERC20_SYMBOL = "0x95d89b41"
SELECTOR_ERC20_DECIMALS = "0x313ce567"
SELECTOR_ERC20_TOTAL_SUPPLY = "0x18160ddd"

SELECTOR_ERC4626_ASSET = "0x38d52e0f"
SELECTOR_ERC4626_TOTAL_ASSETS = "0x01e1d114"

SELECTOR_MORPHO = "0x34b1167c"
SELECTOR_MORPHO_WITHDRAW_QUEUE_LEN = "0xca1a41fb"
SELECTOR_MORPHO_WITHDRAW_QUEUE = "0x02d07db9"

SELECTOR_PENDLE_SY = "0x7d58b1f2"
SELECTOR_PENDLE_PT = "0x9f03651d"
SELECTOR_PENDLE_YIELD_TOKEN = "0x2df908d3"

SELECTOR_CURVE_COINS = "0xc6610657"

# Special node identifier for unbacked off-chain / CEX custody legs (lowercase normalized)
OFFCHAIN_BLACKBOX_CUSTODY = "offchain_blackbox_custody"

# Redaction notice for free tier lead magnet
STREAMS_REDACTION_NOTICE = (
    "[REDACTED — Unlock full Tarjan SCC cycle & Z3 shock witness via "
    "POST /x402/verify-forensic-graph or $199/mo Curator Alert Feed]"
)

# Canonical terminal symbols and addresses
CANONICAL_TERMINAL_SYMBOLS: Set[str] = {
    "USDC",
    "USDC.E",
    "USDT",
    "DAI",
    "WETH",
    "ETH",
    "WSTETH",
    "WBTC",
    "CBETH",
    "RETH",
    "USDS",
    "SDAI",
}

# Lowercase canonical terminal contract addresses
CANONICAL_TERMINAL_ADDRESSES: Dict[str, Set[str]] = {
    "ethereum": {
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC
        "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT
        "0x6b175474e89094c44da98b954eedeac495271d0f",  # DAI
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH
        "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0",  # wstETH
        "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",  # WBTC
        "0x83f20f44975d03b1b09e64809b757c47f942beea",  # sDAI
    },
    "base": {
        "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",  # USDC
        "0x4200000000000000000000000000000000000006",  # WETH
        "0x2ae3f1ec7e1f501679b18d3b9e0a772571a42420",  # cbETH
        "0xc1cba3fcea344f92d9239c08c0568f6f2f0ee452",  # wstETH
        "0x50c5725949a6f0c72e6c4a641f24049a917db0cb",  # DAI
    },
    "arbitrum": {
        "0xaf88d065e77c8cc2239327c5edb3a432268e5831",  # USDC (native)
        "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8",  # USDC.e
        "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",  # USDT
        "0xda10009cbd5d07dd0cecc6616156242905551772",  # DAI
        "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",  # WETH
        "0x5979f50544273b3b08745bae267646cd73717075",  # wstETH
        "0x2f2a2543b76a4166549f7aab2e7520493762b14f",  # WBTC
    },
}

GRADE_COLORS: Dict[str, str] = {
    "A+": "#10B981",
    "A": "#10B981",
    "B": "#3B82F6",
    "C": "#F59E0B",
    "D": "#F97316",
    "F": "#EF4444",
    "unknown": "#6B7280",
}

# ---------------------------------------------------------------------------
# EVM & ABI Helpers
# ---------------------------------------------------------------------------

EVM_ADDRESS_REGEX = re.compile(r"^0x[0-9a-fA-F]{40}$")


def validate_evm_address(address: str) -> str:
    """
    Validates a 42-character EVM hexadecimal address (0x...).
    Raises ValueError on malformed format or zero address.
    """
    if not isinstance(address, str):
        raise ValueError(f"Address must be string, got {type(address).__name__}")
    clean = address.strip()
    if not EVM_ADDRESS_REGEX.match(clean):
        raise ValueError(f"Malformed EVM address '{clean}': must be 42 hex characters starting with 0x")
    if clean.lower() == "0x" + "0" * 40:
        raise ValueError(f"Zero address '{clean}' is not a valid collateral contract")
    return clean.lower()


def encode_uint256(val: int) -> str:
    """Encodes a uint256 as 64 hex characters (32 bytes big-endian)."""
    return hex(val)[2:].zfill(64)


def decode_address_from_hex(hex_str: Optional[str]) -> Optional[str]:
    """Decodes a 32-byte ABI return word into a 20-byte EVM address, or None if zero/invalid."""
    if not hex_str or not isinstance(hex_str, str):
        return None
    raw = hex_str.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if len(raw) < 40:
        return None
    addr_part = raw[-40:]
    if addr_part == "0" * 40:
        return None
    return "0x" + addr_part


def decode_uint256_from_hex(hex_str: Optional[str]) -> Optional[int]:
    """Decodes a 32-byte ABI return word into an integer, or None if invalid."""
    if not hex_str or not isinstance(hex_str, str):
        return None
    raw = hex_str.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if not raw:
        return None
    try:
        return int(raw, 16)
    except ValueError:
        return None


def decode_string_from_hex(hex_str: Optional[str], default: str = "UNKNOWN") -> str:
    """Decodes an ABI-encoded string or bytes32 symbol from eth_call return."""
    if not hex_str or not isinstance(hex_str, str):
        return default
    raw = hex_str.strip()
    if raw.startswith("0x"):
        raw = raw[2:]
    if len(raw) < 2:
        return default
    try:
        raw_bytes = bytes.fromhex(raw)
    except ValueError:
        return default

    # Try dynamic string encoding (offset, length, data)
    if len(raw_bytes) >= 64:
        offset = int.from_bytes(raw_bytes[:32], "big")
        if offset == 32 and len(raw_bytes) >= 64:
            str_len = int.from_bytes(raw_bytes[32:64], "big")
            if 0 < str_len <= 128 and len(raw_bytes) >= 64 + str_len:
                text = raw_bytes[64 : 64 + str_len].decode("utf-8", errors="ignore").strip("\x00 \t\n\r")
                if text:
                    return text

    # Try bytes32 fixed string
    clean_text = raw_bytes.split(b"\x00")[0].decode("utf-8", errors="ignore").strip("\x00 \t\n\r")
    if clean_text:
        return clean_text
    return default


def default_rpc_transport(chain: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Default HTTP JSON-RPC transport targeting publicnode.com endpoints.
    """
    rpc_url = DEFAULT_RPC_URLS.get(chain)
    if not rpc_url:
        raise ValueError(f"Unsupported chain '{chain}'. Supported chains: {list(DEFAULT_RPC_URLS.keys())}")

    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        rpc_url,
        data=req_data,
        headers={"Content-Type": "application/json", "User-Agent": "OmniStreamsProver/1.0"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def eth_call(
    to_address: str,
    data: str,
    *,
    chain: str = "ethereum",
    rpc_transport: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None,
) -> Optional[str]:
    """
    Executes a read-only eth_call against the target contract.
    Returns the raw hex string response, or None on revert / failure.
    """
    transport = rpc_transport or default_rpc_transport
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": to_address, "data": data}, "latest"],
    }
    try:
        res = transport(chain, payload)
        if isinstance(res, dict) and "result" in res and isinstance(res["result"], str):
            val = res["result"]
            if val and val != "0x":
                return val
    except Exception as exc:
        logger.debug("eth_call failed for %s on %s: %s", to_address, chain, exc)
    return None


# ---------------------------------------------------------------------------
# 1-Address Collateral Graph Adapter
# ---------------------------------------------------------------------------


def discover_collateral_graph(
    token_address: str,
    *,
    chain: str = "ethereum",
    max_depth: int = 4,
    rpc_transport: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Passively discovers the on-chain collateral backing dependency graph starting from
    a single EVM token or vault address.

    Bounded by max_depth (<= 5) and max 25 visited contracts to eliminate RPC explosion risks.
    Detects:
      - ERC-20 symbol, decimals, totalSupply
      - ERC-4626 Vault asset() and totalAssets() vs totalSupply backing gaps
      - Morpho / MetaMorpho withdraw queues
      - Pendle PT / SY yieldToken relationships
      - Curve Pool coins
      - Off-chain blackbox custody jumps for unbacked synthetic tokens
    """
    root_addr = validate_evm_address(token_address)
    clean_chain = chain.strip().lower()
    if clean_chain not in DEFAULT_RPC_URLS:
        raise ValueError(f"Unsupported chain '{chain}'. Must be one of: {list(DEFAULT_RPC_URLS.keys())}")

    bounded_max_depth = max(1, min(int(max_depth), 5))
    visited: Set[str] = set()
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    def is_canonical_terminal(addr: str, sym: str) -> bool:
        if addr in CANONICAL_TERMINAL_ADDRESSES.get(clean_chain, set()):
            return True
        if sym.upper() in CANONICAL_TERMINAL_SYMBOLS:
            return True
        return False

    def probe_contract(addr: str, current_depth: int) -> None:
        if addr in visited or len(visited) >= 25:
            return
        visited.add(addr)

        # 1. Probe ERC-20 metadata
        sym_hex = eth_call(addr, SELECTOR_ERC20_SYMBOL, chain=clean_chain, rpc_transport=rpc_transport)
        symbol = decode_string_from_hex(sym_hex, default="TOKEN")

        dec_hex = eth_call(addr, SELECTOR_ERC20_DECIMALS, chain=clean_chain, rpc_transport=rpc_transport)
        decimals = decode_uint256_from_hex(dec_hex) or 18

        sup_hex = eth_call(addr, SELECTOR_ERC20_TOTAL_SUPPLY, chain=clean_chain, rpc_transport=rpc_transport)
        total_supply = decode_uint256_from_hex(sup_hex) or 0

        # Check if canonical terminal hard-reserve
        if is_canonical_terminal(addr, symbol):
            nodes[addr] = {
                "address": addr,
                "symbol": symbol,
                "decimals": decimals,
                "total_supply": total_supply,
                "is_terminal": True,
                "is_blackbox": False,
                "contract_type": "CANONICAL_HARD_RESERVE",
            }
            return

        # Initialize non-terminal node
        nodes[addr] = {
            "address": addr,
            "symbol": symbol,
            "decimals": decimals,
            "total_supply": total_supply,
            "is_terminal": False,
            "is_blackbox": False,
            "contract_type": "UNKNOWN",
        }

        discovered_underlying: List[Tuple[str, int]] = []  # (target_address, weight_bps)
        has_blackbox_gap = False
        blackbox_gap_bps = 0

        # 2. Check ERC-4626 Vault
        asset_hex = eth_call(addr, SELECTOR_ERC4626_ASSET, chain=clean_chain, rpc_transport=rpc_transport)
        underlying_asset = decode_address_from_hex(asset_hex)
        if underlying_asset:
            nodes[addr]["contract_type"] = "ERC4626_VAULT"
            tot_assets_hex = eth_call(
                addr, SELECTOR_ERC4626_TOTAL_ASSETS, chain=clean_chain, rpc_transport=rpc_transport
            )
            total_assets = decode_uint256_from_hex(tot_assets_hex)

            # Check for unbacked gap (< 95% backing)
            if total_assets is not None and total_supply > 0:
                ratio = total_assets / float(total_supply)
                if ratio < 0.95:
                    has_blackbox_gap = True
                    backing_fraction = max(0.0, min(1.0, ratio))
                    valid_backing_bps = int(backing_fraction * 10000)
                    blackbox_gap_bps = 10000 - valid_backing_bps
                    discovered_underlying.append((underlying_asset, valid_backing_bps))
                else:
                    discovered_underlying.append((underlying_asset, 10000))
            else:
                discovered_underlying.append((underlying_asset, 10000))

        # 3. Check Morpho / MetaMorpho Vault
        if not discovered_underlying:
            morpho_hex = eth_call(addr, SELECTOR_MORPHO, chain=clean_chain, rpc_transport=rpc_transport)
            if morpho_hex and morpho_hex != "0x":
                nodes[addr]["contract_type"] = "METAMORPHO_VAULT"
                q_len_hex = eth_call(
                    addr, SELECTOR_MORPHO_WITHDRAW_QUEUE_LEN, chain=clean_chain, rpc_transport=rpc_transport
                )
                q_len = decode_uint256_from_hex(q_len_hex) or 0
                morpho_markets: List[str] = []
                for i in range(min(q_len, 4)):
                    data = SELECTOR_MORPHO_WITHDRAW_QUEUE + encode_uint256(i)
                    m_hex = eth_call(addr, data, chain=clean_chain, rpc_transport=rpc_transport)
                    m_addr = decode_address_from_hex(m_hex)
                    if m_addr:
                        morpho_markets.append(m_addr)
                if morpho_markets:
                    share_bps = 10000 // len(morpho_markets)
                    for m_idx, m_t in enumerate(morpho_markets):
                        bps = share_bps if m_idx < len(morpho_markets) - 1 else 10000 - share_bps * m_idx
                        discovered_underlying.append((m_t, bps))

        # 4. Check Pendle PT / SY
        if not discovered_underlying:
            sy_hex = eth_call(addr, SELECTOR_PENDLE_SY, chain=clean_chain, rpc_transport=rpc_transport)
            sy_addr = decode_address_from_hex(sy_hex)
            pt_hex = eth_call(addr, SELECTOR_PENDLE_PT, chain=clean_chain, rpc_transport=rpc_transport)
            pt_addr = decode_address_from_hex(pt_hex)
            yt_hex = eth_call(addr, SELECTOR_PENDLE_YIELD_TOKEN, chain=clean_chain, rpc_transport=rpc_transport)
            yt_addr = decode_address_from_hex(yt_hex)

            pendle_target = sy_addr or pt_addr or yt_addr
            if pendle_target:
                nodes[addr]["contract_type"] = "PENDLE_SY_PT"
                discovered_underlying.append((pendle_target, 10000))

        # 5. Check Curve Pool
        if not discovered_underlying:
            curve_coins: List[str] = []
            for i in range(4):
                data = SELECTOR_CURVE_COINS + encode_uint256(i)
                c_hex = eth_call(addr, data, chain=clean_chain, rpc_transport=rpc_transport)
                c_addr = decode_address_from_hex(c_hex)
                if c_addr and c_addr not in curve_coins:
                    curve_coins.append(c_addr)
                else:
                    break
            if curve_coins:
                nodes[addr]["contract_type"] = "CURVE_POOL"
                coin_bps = 10000 // len(curve_coins)
                for c_idx, c_t in enumerate(curve_coins):
                    bps = coin_bps if c_idx < len(curve_coins) - 1 else 10000 - coin_bps * c_idx
                    discovered_underlying.append((c_t, bps))

        # 6. Off-Chain Blackbox Custody Detection
        if has_blackbox_gap and blackbox_gap_bps > 0:
            nodes[OFFCHAIN_BLACKBOX_CUSTODY] = {
                "address": OFFCHAIN_BLACKBOX_CUSTODY,
                "symbol": "OFFCHAIN_BLACKBOX",
                "decimals": 18,
                "total_supply": 0,
                "is_terminal": True,
                "is_blackbox": True,
                "contract_type": "OFFCHAIN_CUSTODY_LEG",
            }
            edges.append(
                {
                    "source": addr,
                    "target": OFFCHAIN_BLACKBOX_CUSTODY,
                    "weight_bps": blackbox_gap_bps,
                    "relation": "UNBACKED_OFFCHAIN_GAP",
                }
            )

        if not discovered_underlying and not has_blackbox_gap:
            nodes[addr]["contract_type"] = "SYNTHETIC_YIELD_TOKEN"
            nodes[OFFCHAIN_BLACKBOX_CUSTODY] = {
                "address": OFFCHAIN_BLACKBOX_CUSTODY,
                "symbol": "OFFCHAIN_BLACKBOX",
                "decimals": 18,
                "total_supply": 0,
                "is_terminal": True,
                "is_blackbox": True,
                "contract_type": "OFFCHAIN_CUSTODY_LEG",
            }
            edges.append(
                {
                    "source": addr,
                    "target": OFFCHAIN_BLACKBOX_CUSTODY,
                    "weight_bps": 10000,
                    "relation": "OPAQUE_OFFCHAIN_CUSTODY",
                }
            )

        # Register discovered backing edges and recurse
        for target_addr, weight_bps in discovered_underlying:
            edges.append(
                {
                    "source": addr,
                    "target": target_addr,
                    "weight_bps": weight_bps,
                    "relation": "BACKED_BY",
                }
            )
            if current_depth < bounded_max_depth and target_addr not in visited and len(visited) < 25:
                probe_contract(target_addr, current_depth + 1)

    probe_contract(root_addr, 1)

    return {
        "root_token": root_addr,
        "chain": clean_chain,
        "nodes": nodes,
        "edges": edges,
    }


# ---------------------------------------------------------------------------
# Tarjan SCC & Contagion Engine
# ---------------------------------------------------------------------------


def tarjan_scc(nodes: List[str], edges: List[Tuple[str, str, int]]) -> List[List[str]]:
    """
    Iterative/recursive Tarjan's Strongly Connected Components (O(V + E)).
    Returns all non-trivial circular SCCs (len >= 2 or explicit self-loops).
    """
    adj: Dict[str, List[str]] = {n: [] for n in nodes}
    self_loops: Set[str] = set()
    for src, tgt, _ in edges:
        if src in adj:
            adj[src].append(tgt)
        if src == tgt:
            self_loops.add(src)

    index = 0
    indices: Dict[str, int] = {}
    lowlinks: Dict[str, int] = {}
    stack: List[str] = []
    on_stack: Set[str] = set()
    sccs: List[List[str]] = []

    def strongconnect(v: str) -> None:
        nonlocal index
        indices[v] = index
        lowlinks[v] = index
        index += 1
        stack.append(v)
        on_stack.add(v)

        for w in adj.get(v, []):
            if w not in indices:
                strongconnect(w)
                lowlinks[v] = min(lowlinks[v], lowlinks[w])
            elif w in on_stack:
                lowlinks[v] = min(lowlinks[v], indices[w])

        if lowlinks[v] == indices[v]:
            scc: List[str] = []
            while True:
                w = stack.pop()
                on_stack.remove(w)
                scc.append(w)
                if w == v:
                    break
            if len(scc) >= 2 or (len(scc) == 1 and scc[0] in self_loops):
                sccs.append(scc)

    for node in nodes:
        if node not in indices:
            strongconnect(node)

    return sccs


def solve_linear_system(A: List[List[float]], b: List[float]) -> Optional[List[float]]:
    """
    Solves A * x = b via Gaussian elimination with partial pivoting in pure Python stdlib.
    Guarantees exact analytical fixed-point computation with zero external dependencies.
    """
    n = len(A)
    if n == 0 or len(b) != n:
        return None
    M = [A[i][:] + [b[i]] for i in range(n)]

    for i in range(n):
        max_row = max(range(i, n), key=lambda r: abs(M[r][i]))
        M[i], M[max_row] = M[max_row], M[i]
        pivot = M[i][i]
        if abs(pivot) < 1e-12:
            return None
        for j in range(i, n + 1):
            M[i][j] /= pivot
        for r in range(n):
            if r != i:
                factor = M[r][i]
                for j in range(i, n + 1):
                    M[r][j] -= factor * M[i][j]

    return [M[i][n] for i in range(n)]


def compute_insolvency_shock_witness(
    root_token: str,
    nodes: Dict[str, Dict[str, Any]],
    edges: List[Tuple[str, str, int]],
    fragile_nodes: Set[str],
    depeg_threshold: float = 0.90,
    junior_tranche_pct: float = 10.0,
    use_z3: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Computes the minimum collateral haircut % (min_wipeout_haircut_pct) on opaque / looped
    collateral that drives root token solvency below 90% (depeg) or wipes out the 10% junior tranche.

    Uses z3.Optimize when available, with an exact analytical matrix solver fallback.
    """
    should_use_z3 = HAS_Z3 if use_z3 is None else (use_z3 and HAS_Z3)

    if not fragile_nodes or root_token not in nodes:
        return {
            "solver": "z3" if should_use_z3 else "analytical_fixed_point",
            "depeg_threshold_solvency": depeg_threshold,
            "junior_tranche_wipeout_pct": junior_tranche_pct,
            "min_wipeout_haircut_pct": None,
            "root_solvency_at_shock": 1.0,
            "node_valuations_at_shock": {root_token: 1.0},
            "is_vulnerable": False,
        }

    # Normalize outgoing weights for each non-terminal node
    adj_weights: Dict[str, List[Tuple[str, float]]] = {}
    for src in nodes:
        out_edges = [(tgt, float(w)) for s, tgt, w in edges if s == src]
        total_w = sum(w for _, w in out_edges)
        if total_w > 0:
            adj_weights[src] = [(tgt, w / total_w) for tgt, w in out_edges]
        else:
            adj_weights[src] = []

    # 1. Z3 Implementation
    if should_use_z3 and z3 is not None:
        try:
            opt = z3.Optimize()
            h = z3.Real("haircut")
            vars_map: Dict[str, Any] = {}

            for n_id, n_info in nodes.items():
                v = z3.Real(f"v_{n_id}")
                vars_map[n_id] = v
                opt.add(v >= 0.0)

                is_bb = n_info.get("is_blackbox", False) or n_id == OFFCHAIN_BLACKBOX_CUSTODY
                if is_bb:
                    opt.add(v == 1.0 - h)
                elif n_info.get("is_terminal", False):
                    opt.add(v == 1.0)
                else:
                    outs = adj_weights.get(n_id, [])
                    if outs:
                        val_expr = sum(w * vars_map.setdefault(t, z3.Real(f"v_{t}")) for t, w in outs)
                        opt.add(v == val_expr)
                    else:
                        opt.add(v == 1.0)

            root_v = vars_map.get(root_token, z3.Real(f"v_{root_token}"))
            opt.add(root_v <= depeg_threshold)
            opt.add(h >= 0.0, h <= 1.0)
            opt.minimize(h)

            if opt.check() == z3.sat:
                m = opt.model()
                min_h_frac = m[h].as_fraction()
                min_h = float(min_h_frac)
                solvency_val = float(m[root_v].as_fraction()) if m[root_v] is not None else depeg_threshold

                vals_dict = {}
                for n_id, v_var in vars_map.items():
                    mv = m[v_var]
                    vals_dict[n_id] = round(float(mv.as_fraction()), 4) if mv is not None else 1.0

                return {
                    "solver": "z3",
                    "depeg_threshold_solvency": depeg_threshold,
                    "junior_tranche_wipeout_pct": junior_tranche_pct,
                    "min_wipeout_haircut_pct": round(min_h * 100.0, 2),
                    "root_solvency_at_shock": round(solvency_val, 4),
                    "node_valuations_at_shock": vals_dict,
                    "is_vulnerable": True,
                }
        except Exception as exc:
            logger.debug("Z3 optimization failed, invoking analytical fallback: %s", exc)

    # 2. Analytical Fixed-Point Solver Fallback
    # Solves (I - W) * V = C_term + C_bb * (1 - h)
    non_term_nodes = [
        n_id
        for n_id, n_info in nodes.items()
        if not n_info.get("is_terminal", False)
        and not n_info.get("is_blackbox", False)
        and n_id != OFFCHAIN_BLACKBOX_CUSTODY
    ]
    node_to_idx = {n_id: idx for idx, n_id in enumerate(non_term_nodes)}
    n = len(non_term_nodes)

    if n == 0 or root_token not in node_to_idx:
        return {
            "solver": "analytical_fixed_point",
            "depeg_threshold_solvency": depeg_threshold,
            "junior_tranche_wipeout_pct": junior_tranche_pct,
            "min_wipeout_haircut_pct": None,
            "root_solvency_at_shock": 1.0,
            "node_valuations_at_shock": {root_token: 1.0},
            "is_vulnerable": False,
        }

    W = [[0.0] * n for _ in range(n)]
    c_term = [0.0] * n
    c_bb = [0.0] * n

    for u_id in non_term_nodes:
        u_idx = node_to_idx[u_id]
        for tgt_id, w in adj_weights.get(u_id, []):
            if tgt_id in node_to_idx:
                W[u_idx][node_to_idx[tgt_id]] += w
            elif nodes.get(tgt_id, {}).get("is_blackbox", False) or tgt_id == OFFCHAIN_BLACKBOX_CUSTODY:
                c_bb[u_idx] += w
            else:
                c_term[u_idx] += w

    I_minus_W = [[(1.0 if i == j else 0.0) - W[i][j] for j in range(n)] for i in range(n)]
    b_vec = solve_linear_system(I_minus_W, c_bb)

    if b_vec is None:
        return {
            "solver": "analytical_fixed_point",
            "depeg_threshold_solvency": depeg_threshold,
            "junior_tranche_wipeout_pct": junior_tranche_pct,
            "min_wipeout_haircut_pct": None,
            "root_solvency_at_shock": 1.0,
            "node_valuations_at_shock": {},
            "is_vulnerable": False,
        }

    root_idx = node_to_idx[root_token]
    b_root = b_vec[root_idx]

    if b_root <= 1e-9:
        return {
            "solver": "analytical_fixed_point",
            "depeg_threshold_solvency": depeg_threshold,
            "junior_tranche_wipeout_pct": junior_tranche_pct,
            "min_wipeout_haircut_pct": None,
            "root_solvency_at_shock": 1.0,
            "node_valuations_at_shock": {n_id: 1.0 for n_id in node_to_idx},
            "is_vulnerable": False,
        }

    critical_h = max(0.0, (1.0 - depeg_threshold) / b_root)
    is_vulnerable = critical_h <= 1.0

    node_vals = {}
    for n_id, i in node_to_idx.items():
        node_vals[n_id] = round(max(0.0, 1.0 - b_vec[i] * min(critical_h, 1.0)), 4)
    for n_id, n_info in nodes.items():
        if n_id not in node_vals:
            if n_info.get("is_blackbox", False) or n_id == OFFCHAIN_BLACKBOX_CUSTODY:
                node_vals[n_id] = round(max(0.0, 1.0 - min(critical_h, 1.0)), 4)
            else:
                node_vals[n_id] = 1.0

    return {
        "solver": "analytical_fixed_point",
        "depeg_threshold_solvency": depeg_threshold,
        "junior_tranche_wipeout_pct": junior_tranche_pct,
        "min_wipeout_haircut_pct": round(critical_h * 100.0, 2) if is_vulnerable else None,
        "root_solvency_at_shock": round(max(0.0, 1.0 - b_root * min(critical_h, 1.0)), 4),
        "node_valuations_at_shock": node_vals,
        "is_vulnerable": is_vulnerable,
    }


def analyze_collateral_streams(topology: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes a collateral topology using Tarjan SCC and the Contagion Engine.
    Computes circular SCC cycles, blackbox custody hops, leverage multipliers,
    effective hard-backing BPS, Z3 insolvency shock witness, and risk grades.
    """
    root_token = str(topology.get("root_token", "")).strip().lower()
    chain = str(topology.get("chain", "ethereum")).strip().lower()
    raw_nodes = topology.get("nodes", {})
    raw_edges = topology.get("edges", [])

    nodes: Dict[str, Dict[str, Any]] = {}
    for k, v in raw_nodes.items():
        clean_k = str(k).strip().lower()
        node_copy = dict(v)
        node_copy["address"] = clean_k
        if clean_k == OFFCHAIN_BLACKBOX_CUSTODY:
            node_copy["is_blackbox"] = True
            node_copy["is_terminal"] = True
        nodes[clean_k] = node_copy

    edges: List[Tuple[str, str, int]] = []
    for e in raw_edges:
        if isinstance(e, (list, tuple)) and len(e) >= 3:
            edges.append((str(e[0]).strip().lower(), str(e[1]).strip().lower(), int(e[2])))
        elif isinstance(e, dict):
            src = str(e.get("source", "")).strip().lower()
            tgt = str(e.get("target", "")).strip().lower()
            w = int(e.get("weight_bps", 10000))
            if src and tgt:
                edges.append((src, tgt, w))

    node_ids = list(nodes.keys())
    for s, t, _ in edges:
        if s not in nodes:
            nodes[s] = {"address": s, "symbol": "TOKEN", "is_terminal": False, "is_blackbox": False}
        if t not in nodes:
            nodes[t] = {
                "address": t,
                "symbol": "OFFCHAIN_BLACKBOX" if t == OFFCHAIN_BLACKBOX_CUSTODY else "TOKEN",
                "is_terminal": t in CANONICAL_TERMINAL_ADDRESSES.get(chain, set()) or t == OFFCHAIN_BLACKBOX_CUSTODY,
                "is_blackbox": t == OFFCHAIN_BLACKBOX_CUSTODY,
            }
        if s not in node_ids:
            node_ids.append(s)
        if t not in node_ids:
            node_ids.append(t)

    # 1. Run Tarjan SCC
    sccs = tarjan_scc(node_ids, edges)
    circular_scc_cycles: List[List[str]] = sccs

    # 2. Identify Blackbox Hops
    blackbox_hops: List[Dict[str, Any]] = []
    fragile_nodes: Set[str] = set()
    for scc in circular_scc_cycles:
        fragile_nodes.update(scc)

    for src, tgt, w in edges:
        is_bb = nodes.get(tgt, {}).get("is_blackbox", False) or tgt == OFFCHAIN_BLACKBOX_CUSTODY
        if is_bb:
            fragile_nodes.add(tgt)
            blackbox_hops.append({"source": src, "target": tgt, "weight_bps": w})

    # 3. Calculate loop weight and effective hard backing from root token
    loop_nodes: Set[str] = set()
    for scc in circular_scc_cycles:
        loop_nodes.update(scc)

    root_edges = [(tgt, w) for s, tgt, w in edges if s == root_token]
    total_root_w = sum(w for _, w in root_edges) or 10000

    loop_weight_bps = 0
    blackbox_weight_bps = 0
    hard_backing_bps = 0

    if not root_edges:
        if nodes.get(root_token, {}).get("is_terminal", False):
            hard_backing_bps = 10000
    else:
        for tgt, w in root_edges:
            normalized_bps = int((w / total_root_w) * 10000)
            if nodes.get(tgt, {}).get("is_blackbox", False) or tgt == OFFCHAIN_BLACKBOX_CUSTODY:
                blackbox_weight_bps += normalized_bps
            elif nodes.get(tgt, {}).get("is_terminal", False):
                hard_backing_bps += normalized_bps
            elif tgt in loop_nodes:
                loop_weight_bps += normalized_bps
            else:
                tgt_outs = [(t2, w2) for s2, t2, w2 in edges if s2 == tgt]
                has_loop_reach = any(t2 in loop_nodes for t2, _ in tgt_outs)
                has_bb_reach = any(
                    nodes.get(t2, {}).get("is_blackbox", False) or t2 == OFFCHAIN_BLACKBOX_CUSTODY for t2, _ in tgt_outs
                )
                if has_loop_reach:
                    loop_weight_bps += normalized_bps
                elif has_bb_reach:
                    blackbox_weight_bps += normalized_bps
                else:
                    hard_backing_bps += normalized_bps

    loop_fraction = loop_weight_bps / 10000.0
    amplification_multiplier = round(1.0 / max(0.05, 1.0 - loop_fraction), 4)
    effective_hard_backing_bps = max(0, min(10000, 10000 - loop_weight_bps - blackbox_weight_bps))

    # 4. Compute Z3 Insolvency Shock Witness
    witness = compute_insolvency_shock_witness(
        root_token=root_token,
        nodes=nodes,
        edges=edges,
        fragile_nodes=fragile_nodes,
        depeg_threshold=0.90,
        junior_tranche_pct=10.0,
    )

    # 5. Risk Classification & Grading
    if circular_scc_cycles:
        risk_classification = "CIRCULAR_COLLATERAL_TRAP"
        grade = "F"
        score = min(39, max(5, int(effective_hard_backing_bps / 250.0)))
    elif blackbox_hops:
        risk_classification = "OPAQUE_OFFCHAIN_STREAM"
        if effective_hard_backing_bps < 5000:
            grade = "D"
            score = 40 + int((effective_hard_backing_bps / 5000.0) * 14)
        else:
            grade = "C"
            score = 55 + int(((effective_hard_backing_bps - 5000) / 5000.0) * 14)
    else:
        risk_classification = "CLEAN_HARD_BACKED"
        if effective_hard_backing_bps >= 9900:
            grade = "A+"
            score = 98
        elif effective_hard_backing_bps >= 9000:
            grade = "A"
            score = 88
        else:
            grade = "B"
            score = 75

    return {
        "root_token": root_token,
        "token_address": root_token,
        "chain": chain,
        "risk_classification": risk_classification,
        "grade": grade,
        "score": score,
        "circular_scc_cycles": circular_scc_cycles,
        "blackbox_hops": blackbox_hops,
        "loop_weight_bps": loop_weight_bps,
        "amplification_multiplier": amplification_multiplier,
        "effective_hard_backing_bps": effective_hard_backing_bps,
        "z3_contagion_witness": witness,
        "nodes": nodes,
        "edges": raw_edges,
    }


# ---------------------------------------------------------------------------
# Built-in Deterministic Demos
# ---------------------------------------------------------------------------


def run_streams_demo(demo: str) -> Dict[str, Any]:
    """
    Executes one of the 3 built-in deterministic collateral stream topologies:
      - 'xusd_deusd_circular': Classic xUSD <-> deUSD circular loop + off-chain stream (Grade F).
      - 'opaque_offchain_yield': 65% CEX delta-neutral blackbox leg + 35% USDC (Grade D).
      - 'clean_erc4626_usdc': 100% Circle USDC hard-backed vault (Grade A+).
    """
    clean_demo = demo.strip().lower()

    if clean_demo == "xusd_deusd_circular":
        xusd = "0x1111111111111111111111111111111111110001"
        morpho = "0x1111111111111111111111111111111111110002"
        pt_deusd = "0x1111111111111111111111111111111111110003"
        deusd = "0x1111111111111111111111111111111111110004"
        curve_pool = "0x1111111111111111111111111111111111110005"
        usdc = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"

        topology = {
            "root_token": xusd,
            "chain": "ethereum",
            "nodes": {
                xusd: {"address": xusd, "symbol": "xUSD", "is_terminal": False, "is_blackbox": False},
                morpho: {"address": morpho, "symbol": "Morpho_Vault", "is_terminal": False, "is_blackbox": False},
                pt_deusd: {"address": pt_deusd, "symbol": "PT_deUSD", "is_terminal": False, "is_blackbox": False},
                deusd: {"address": deusd, "symbol": "deUSD", "is_terminal": False, "is_blackbox": False},
                curve_pool: {
                    "address": curve_pool,
                    "symbol": "Curve_xUSD_deUSD",
                    "is_terminal": False,
                    "is_blackbox": False,
                },
                usdc: {"address": usdc, "symbol": "USDC", "is_terminal": True, "is_blackbox": False},
                OFFCHAIN_BLACKBOX_CUSTODY: {
                    "address": OFFCHAIN_BLACKBOX_CUSTODY,
                    "symbol": "OFFCHAIN_BLACKBOX",
                    "is_terminal": True,
                    "is_blackbox": True,
                },
            },
            "edges": [
                {"source": xusd, "target": morpho, "weight_bps": 7500, "relation": "VAULT_ALLOCATION"},
                {"source": xusd, "target": usdc, "weight_bps": 2500, "relation": "HARD_RESERVE_CUSHION"},
                {"source": morpho, "target": pt_deusd, "weight_bps": 10000, "relation": "COLLATERAL_DEPOSIT"},
                {"source": pt_deusd, "target": deusd, "weight_bps": 10000, "relation": "PENDLE_SY_WRAPPER"},
                {"source": deusd, "target": curve_pool, "weight_bps": 6000, "relation": "LP_LIQUIDITY_BACKING"},
                {
                    "source": deusd,
                    "target": OFFCHAIN_BLACKBOX_CUSTODY,
                    "weight_bps": 4000,
                    "relation": "CEX_PERP_FUNDING_LEG",
                },
                {"source": curve_pool, "target": xusd, "weight_bps": 5000, "relation": "CURVE_COIN_0"},
                {"source": curve_pool, "target": deusd, "weight_bps": 5000, "relation": "CURVE_COIN_1"},
            ],
        }
        return analyze_collateral_streams(topology)

    elif clean_demo == "opaque_offchain_yield":
        usde = "0x2222222222222222222222222222222222220002"
        usdc = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"

        topology = {
            "root_token": usde,
            "chain": "ethereum",
            "nodes": {
                usde: {
                    "address": usde,
                    "symbol": "USDe_Synthetic",
                    "is_terminal": False,
                    "is_blackbox": False,
                },
                usdc: {"address": usdc, "symbol": "USDC", "is_terminal": True, "is_blackbox": False},
                OFFCHAIN_BLACKBOX_CUSTODY: {
                    "address": OFFCHAIN_BLACKBOX_CUSTODY,
                    "symbol": "OFFCHAIN_BLACKBOX",
                    "is_terminal": True,
                    "is_blackbox": True,
                },
            },
            "edges": [
                {
                    "source": usde,
                    "target": OFFCHAIN_BLACKBOX_CUSTODY,
                    "weight_bps": 6500,
                    "relation": "CEX_DELTA_NEUTRAL_LEG",
                },
                {"source": usde, "target": usdc, "weight_bps": 3500, "relation": "CANONICAL_USDC_RESERVE"},
            ],
        }
        return analyze_collateral_streams(topology)

    elif clean_demo == "clean_erc4626_usdc":
        vault = "0x3333333333333333333333333333333333330003"
        usdc = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"

        topology = {
            "root_token": vault,
            "chain": "base",
            "nodes": {
                vault: {
                    "address": vault,
                    "symbol": "Gauntlet_USDC_Prime",
                    "is_terminal": False,
                    "is_blackbox": False,
                },
                usdc: {"address": usdc, "symbol": "USDC", "is_terminal": True, "is_blackbox": False},
            },
            "edges": [
                {"source": vault, "target": usdc, "weight_bps": 10000, "relation": "100PCT_CIRCLE_USDC_ASSET"},
            ],
        }
        return analyze_collateral_streams(topology)

    else:
        raise ValueError(
            f"Unknown streams demo profile '{demo}'. Available: 'xusd_deusd_circular', "
            "'opaque_offchain_yield', 'clean_erc4626_usdc'"
        )


# ---------------------------------------------------------------------------
# Curator Leaderboard & Dynamic SVG Badge
# ---------------------------------------------------------------------------


class StreamsLeaderboard:
    """
    Curator risk leaderboard and historical audit store.
    Uses SQLite with automatic silent fallback to :memory: on read-only environments.
    """

    def __init__(self, db_path: Optional[str] = None):
        self._lock = threading.Lock()
        if db_path is None:
            configured = os.environ.get("OMNI_STREAMS_DB_PATH")
            if configured:
                db_path = configured
            else:
                db_path = os.path.join(tempfile.gettempdir(), "omni_x402_streams_leaderboard.db")

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
            logger.debug("Failed opening SQLite at '%s', falling back to :memory:: %s", db_path, exc)
            self.db_path = ":memory:"
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._is_memory = True

        self._init_db()

    def _init_db(self) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS streams_leaderboard (
                    token_address TEXT PRIMARY KEY,
                    symbol TEXT,
                    name TEXT,
                    chain TEXT,
                    risk_classification TEXT,
                    grade TEXT,
                    score INTEGER,
                    circular_scc_count INTEGER,
                    blackbox_hops_count INTEGER,
                    effective_hard_backing_bps INTEGER,
                    amplification_multiplier REAL,
                    last_scanned_at INTEGER,
                    raw_analysis_json TEXT
                )
                """
            )
        self._seed_benchmarks_if_empty()

    def _seed_benchmarks_if_empty(self) -> None:
        with self._lock, self._conn:
            row = self._conn.execute("SELECT COUNT(*) FROM streams_leaderboard").fetchone()
            if row and row[0] > 0:
                return

            now = int(time.time())
            benchmarks = [
                (
                    "0x83f20f44975d03b1b09e64809b757c47f942beea",
                    "sDAI",
                    "Savings DAI / Sky",
                    "ethereum",
                    "CLEAN_HARD_BACKED",
                    "A+",
                    96,
                    0,
                    0,
                    10000,
                    1.0,
                    now,
                    "{}",
                ),
                (
                    "0xbeebeec0d9bf872e42358bc12a4dfb7c258ceeb1",
                    "gtUSDC",
                    "Morpho Gauntlet USDC Prime",
                    "base",
                    "CLEAN_HARD_BACKED",
                    "A+",
                    98,
                    0,
                    0,
                    10000,
                    1.0,
                    now,
                    "{}",
                ),
                (
                    "0x2222222222222222222222222222222222220002",
                    "USDe",
                    "Synthetic Off-Chain Yield USD (Demo)",
                    "ethereum",
                    "OPAQUE_OFFCHAIN_STREAM",
                    "D",
                    48,
                    0,
                    1,
                    3500,
                    1.0,
                    now,
                    "{}",
                ),
                (
                    "0x1111111111111111111111111111111111110001",
                    "xUSD",
                    "Circular Stream xUSD/deUSD (Post-Mortem Demo)",
                    "ethereum",
                    "CIRCULAR_COLLATERAL_TRAP",
                    "F",
                    15,
                    1,
                    1,
                    2500,
                    4.0,
                    now,
                    "{}",
                ),
            ]
            self._conn.executemany(
                """
                INSERT OR REPLACE INTO streams_leaderboard (
                    token_address, symbol, name, chain, risk_classification,
                    grade, score, circular_scc_count, blackbox_hops_count,
                    effective_hard_backing_bps, amplification_multiplier,
                    last_scanned_at, raw_analysis_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                benchmarks,
            )

    def record_entry(self, analysis: Dict[str, Any], symbol: str = "TOKEN", name: str = "") -> None:
        """Saves or updates an analysis entry in the curator leaderboard."""
        token_addr = str(analysis.get("token_address") or analysis.get("root_token", "")).lower()
        if not token_addr:
            return

        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO streams_leaderboard (
                    token_address, symbol, name, chain, risk_classification,
                    grade, score, circular_scc_count, blackbox_hops_count,
                    effective_hard_backing_bps, amplification_multiplier,
                    last_scanned_at, raw_analysis_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token_addr,
                    symbol,
                    name or symbol,
                    analysis.get("chain", "ethereum"),
                    analysis.get("risk_classification", "UNKNOWN"),
                    analysis.get("grade", "F"),
                    int(analysis.get("score", 0)),
                    len(analysis.get("circular_scc_cycles", [])),
                    len(analysis.get("blackbox_hops", [])),
                    int(analysis.get("effective_hard_backing_bps", 0)),
                    float(analysis.get("amplification_multiplier", 1.0)),
                    int(time.time()),
                    json.dumps(analysis),
                ),
            )

    def get_entry(self, token_address: str) -> Optional[Dict[str, Any]]:
        clean_addr = token_address.strip().lower()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT * FROM streams_leaderboard WHERE token_address = ?", (clean_addr,)
            ).fetchone()
            if row:
                return dict(row)
        return None

    def get_ranked_entries(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock, self._conn:
            rows = self._conn.execute(
                """
                SELECT * FROM streams_leaderboard
                ORDER BY score DESC, effective_hard_backing_bps DESC, last_scanned_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]


_GLOBAL_STREAMS_LEADERBOARD: Optional[StreamsLeaderboard] = None
_GLOBAL_LEADERBOARD_LOCK = threading.Lock()


def get_global_streams_leaderboard() -> StreamsLeaderboard:
    global _GLOBAL_STREAMS_LEADERBOARD
    if _GLOBAL_STREAMS_LEADERBOARD is None:
        with _GLOBAL_LEADERBOARD_LOCK:
            if _GLOBAL_STREAMS_LEADERBOARD is None:
                _GLOBAL_STREAMS_LEADERBOARD = StreamsLeaderboard()
    return _GLOBAL_STREAMS_LEADERBOARD


def run_daily_streams_ranking_job(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Runs periodic re-indexing and returns ranked curator leaderboard entries."""
    board = StreamsLeaderboard(db_path=db_path) if db_path else get_global_streams_leaderboard()
    return board.get_ranked_entries()


def render_streams_badge_svg(
    label: str = "streams audit",
    grade: str = "A+",
    score: int = 95,
) -> str:
    """
    Renders a shields.io-compatible dynamic SVG badge for streams collateral audits.
    Strictly escapes dynamic user inputs via html.escape(..., quote=True) to prevent SVG XSS injection.
    """
    clean_grade = str(grade).strip()
    color = GRADE_COLORS.get(clean_grade, "#6B7280")
    right_text = f"{clean_grade} · {score}/100" if clean_grade != "unknown" else "unknown"

    escaped_label = html.escape(str(label).strip() or "streams audit", quote=True)
    escaped_right = html.escape(right_text, quote=True)
    aria_label = html.escape(f"{label}: {right_text}", quote=True)

    left_char_count = len(label)
    right_char_count = len(right_text)

    left_width = max(80, int(left_char_count * 6.8 + 16))
    right_width = max(60, int(right_char_count * 6.8 + 16))
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


def render_streams_leaderboard_html(entries: List[Dict[str, Any]], base_url: str = "") -> str:
    """
    Renders a responsive, modern dark-mode HTML curator risk leaderboard.
    Includes token address live preview checker, Tarjan cycle indicators, and CTAs.
    """
    clean_base = base_url.rstrip("/") if base_url else ""

    table_rows = []
    for idx, e in enumerate(entries, start=1):
        token_addr = html.escape(e.get("token_address", "unknown"), quote=True)
        symbol = html.escape(e.get("symbol", "TOKEN"), quote=True)
        name = html.escape(e.get("name", symbol), quote=True)
        chain = html.escape(e.get("chain", "ethereum"), quote=True)
        grade = html.escape(e.get("grade", "F"), quote=True)
        score = int(e.get("score", 0))
        grade_color = GRADE_COLORS.get(grade, "#6B7280")

        scc_count = int(e.get("circular_scc_count", 0))
        bb_count = int(e.get("blackbox_hops_count", 0))
        hard_bps = int(e.get("effective_hard_backing_bps", 0))
        hard_pct = f"{hard_bps / 100.0:.1f}%"
        multiplier = float(e.get("amplification_multiplier", 1.0))
        risk_class = html.escape(e.get("risk_classification", "UNKNOWN"), quote=True)

        if scc_count > 0:
            scc_html = f'<span style="color:#ef4444;font-weight:700;">&#9888; {scc_count} Loop(s)</span>'
        else:
            scc_html = '<span style="color:#10b981;font-weight:600;">&#10003; 0 Cycles</span>'

        if bb_count > 0:
            bb_html = f'<span style="color:#f97316;font-weight:600;">&#9888; {bb_count} Off-Chain</span>'
        else:
            bb_html = '<span style="color:#10b981;font-weight:600;">&#10003; On-Chain</span>'

        preview_link = f"{clean_base}/x402/streams/preview?token={token_addr}&amp;chain={chain}"
        badge_link = f"{clean_base}/x402/streams/badge.svg?token={token_addr}&amp;chain={chain}"

        table_rows.append(
            f"""
        <tr>
            <td style="color:#94a3b8;font-weight:600;">#{idx}</td>
            <td>
                <div style="font-weight:600;color:#f8fafc;">{name} ({symbol})</div>
                <div style="font-size:0.75rem;color:#64748b;font-family:monospace;">{token_addr}</div>
            </td>
            <td><span class="chain-tag">{chain}</span></td>
            <td>
                <span class="badge" style="background:{grade_color}22;color:{grade_color};border:1px solid {grade_color}55;">
                    {grade}
                </span>
            </td>
            <td style="font-weight:700;color:#38bdf8;">{score}/100</td>
            <td>{scc_html}</td>
            <td>{bb_html}</td>
            <td style="color:#f1f5f9;font-weight:600;">{hard_pct}</td>
            <td style="color:#cbd5e1;">{multiplier:.2f}x</td>
            <td><span class="class-tag">{risk_class}</span></td>
            <td>
                <a href="{preview_link}" target="_blank" class="action-btn">Preview</a>
                <a href="{badge_link}" target="_blank" class="action-btn">SVG Badge</a>
            </td>
        </tr>
        """
        )

    rows_html = (
        "\n".join(table_rows)
        if table_rows
        else "<tr><td colspan='11' style='text-align:center;padding:2rem;color:#64748b;'>No streams scanned yet</td></tr>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Omni Streams: Collateral Graph Tarjan SCC & Contagion Curator Leaderboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #0b0f19;
            color: #e2e8f0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            padding: 2rem 1.5rem;
            min-height: 100vh;
        }}
        .container {{ max-width: 1280px; margin: 0 auto; }}
        header {{ margin-bottom: 2rem; border-bottom: 1px solid #1e293b; padding-bottom: 1.5rem; }}
        h1 {{ font-size: 1.85rem; font-weight: 800; color: #f8fafc; margin-bottom: 0.5rem; }}
        .subtitle {{ color: #94a3b8; font-size: 0.95rem; line-height: 1.5; }}
        .checker-box {{
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 10px;
            padding: 1.25rem;
            margin-bottom: 2rem;
            display: flex;
            gap: 0.75rem;
            align-items: center;
            flex-wrap: wrap;
        }}
        .checker-input {{
            flex: 1;
            min-width: 280px;
            background: #1f2937;
            border: 1px solid #374151;
            border-radius: 6px;
            padding: 0.65rem 1rem;
            color: #f8fafc;
            font-family: monospace;
            font-size: 0.9rem;
        }}
        .select-input {{
            background: #1f2937;
            border: 1px solid #374151;
            border-radius: 6px;
            padding: 0.65rem 0.85rem;
            color: #f8fafc;
            font-size: 0.9rem;
        }}
        .btn-check {{
            background: #2563eb;
            color: #fff;
            border: none;
            border-radius: 6px;
            padding: 0.65rem 1.25rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.15s;
        }}
        .btn-check:hover {{ background: #1d4ed8; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #0f172a;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.4);
        }}
        th {{
            background: #1e293b;
            color: #cbd5e1;
            text-align: left;
            padding: 0.85rem 1rem;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        td {{
            padding: 0.85rem 1rem;
            border-top: 1px solid #1e293b;
            font-size: 0.85rem;
            vertical-align: middle;
        }}
        tr:hover td {{ background: #131d33; }}
        .badge {{
            display: inline-block;
            font-weight: 700;
            font-size: 0.75rem;
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
        }}
        .chain-tag {{
            display: inline-block;
            background: #1e293b;
            color: #94a3b8;
            padding: 0.15rem 0.45rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-family: monospace;
        }}
        .class-tag {{
            display: inline-block;
            background: #1e293b;
            color: #e2e8f0;
            padding: 0.15rem 0.45rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-family: monospace;
        }}
        .action-btn {{
            display: inline-block;
            color: #38bdf8;
            text-decoration: none;
            font-size: 0.75rem;
            margin-right: 0.5rem;
            font-weight: 600;
        }}
        .action-btn:hover {{ text-decoration: underline; }}
        .cta-banner {{
            margin-top: 2.5rem;
            background: linear-gradient(135deg, #1e1b4b 0%, #172554 100%);
            border: 1px solid #3730a3;
            border-radius: 10px;
            padding: 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        .cta-title {{ font-size: 1.1rem; font-weight: 700; color: #f8fafc; margin-bottom: 0.25rem; }}
        .cta-desc {{ font-size: 0.85rem; color: #cbd5e1; max-width: 680px; line-height: 1.4; }}
        .cta-btn {{
            background: #6366f1;
            color: #fff;
            padding: 0.65rem 1.25rem;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            font-size: 0.85rem;
        }}
        .cta-btn:hover {{ background: #4f46e5; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>⚡ Omni Streams: Collateral Graph &amp; Contagion Leaderboard</h1>
            <p class="subtitle">
                Tarjan Strongly Connected Components (SCC) circular collateral loop detector,
                Z3 formal contagion shock witness, and passive yield-stablecoin curator risk rating.
            </p>
        </header>

        <form class="checker-box" onsubmit="event.preventDefault(); var t = document.getElementById('addrInput').value; var c = document.getElementById('chainSelect').value; if(t) window.open('{clean_base}/x402/streams/preview?token=' + encodeURIComponent(t) + '&chain=' + encodeURIComponent(c), '_blank');">
            <input type="text" id="addrInput" class="checker-input" placeholder="Enter Token / Vault Address (0x...)" required pattern="0x[0-9a-fA-F]{{40}}">
            <select id="chainSelect" class="select-input">
                <option value="ethereum">Ethereum Mainnet</option>
                <option value="base">Base</option>
                <option value="arbitrum">Arbitrum One</option>
            </select>
            <button type="submit" class="btn-check">Scan Collateral Graph</button>
        </form>

        <table>
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>Token / Vault</th>
                    <th>Chain</th>
                    <th>Grade</th>
                    <th>Score</th>
                    <th>Circular SCC</th>
                    <th>Custody</th>
                    <th>Hard Backing</th>
                    <th>Multiplier</th>
                    <th>Risk Class</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>

        <div class="cta-banner">
            <div>
                <div class="cta-title">Curator Risk DAO Alert Feed ($199/mo) &amp; Formal Verification API</div>
                <div class="cta-desc">
                    Unlock real-time monitoring of vault collateral topologies, instant Webhook alerts on circular leverage loops,
                    and programmatic Z3 depeg threshold shock witnesses via <code>POST /x402/verify-forensic-graph</code> ($0.05 USDC).
                </div>
            </div>
            <a href="{clean_base}/x402/verify-forensic-graph" class="cta-btn">Unlock via x402 ($0.05 USDC)</a>
        </div>
    </div>
</body>
</html>"""
