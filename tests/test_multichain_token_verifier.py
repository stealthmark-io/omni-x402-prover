"""
Unit tests for Multichain Token (OFT / NTT / CCIP) Supply & DVN Quorum Z3 Verifier + EAS Attestation Generator.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure z3 and module are importable without polluting sys.path
try:
    import z3
except ImportError:
    try:
        _parents = Path(__file__).resolve().parents
        if len(_parents) > 2:
            _regalo_venv = _parents[2] / "regalo-asi" / ".venv"
            if _regalo_venv.is_dir():
                for _sp in _regalo_venv.glob("lib/python*/site-packages"):
                    _candidate = str(_sp)
                    if os.path.exists(_candidate) and _candidate not in sys.path:
                        sys.path.append(_candidate)
                        try:
                            import z3
                            sys.path.remove(_candidate)
                            break
                        except ImportError:
                            sys.path.remove(_candidate)
    except Exception:
        pass

from omni_x402_prover.multichain_token_verifier import (
    BASE_EAS_CONTRACT,
    LZ_V2_EIDS,
    SELECTOR_DECIMALS,
    SELECTOR_ENDPOINT,
    SELECTOR_NTT_THRESHOLD,
    SELECTOR_OWNER,
    SELECTOR_PEERS,
    SELECTOR_SHARED_DECIMALS,
    SELECTOR_TOTAL_SUPPLY,
    abi_decode_bytes32_address,
    abi_decode_uint256,
    abi_encode_bytes32_address,
    abi_encode_uint32,
    abi_encode_uint256,
    build_eas_attestation_and_report,
    discover_multichain_token_topology,
    encode_eas_attestation_data,
    main,
    verify_multichain_token_invariants,
)


# ---------------------------------------------------------------------------
# Test 1: Clean Symmetric Multichain OFT (VERIFIED_SAFE)
# ---------------------------------------------------------------------------

def test_clean_symmetric_multichain_oft():
    """
    Test clean symmetric multichain OFT (decimals=18, sharedDecimals=6,
    symmetric peers Base <-> Arb, quorum 2, supply conserved -> VERIFIED_SAFE).
    """
    base_addr = "0x1111111111111111111111111111111111111111"
    arb_addr = "0x2222222222222222222222222222222222222222"
    base_eid = LZ_V2_EIDS["base"]
    arb_eid = LZ_V2_EIDS["arbitrum"]

    topology = {
        "token_address": base_addr,
        "home_chain": "base",
        "declared_max_supply": 10_000_000 * 10**18,
        "chains": {
            "base": {
                "address": base_addr,
                "decimals": 18,
                "shared_decimals": 6,
                "total_supply": 6_000_000 * 10**18,
                "locked_supply": 4_000_000 * 10**18,
                "owner": "0x9999999999999999999999999999999999999999",
                "owner_is_contract": True,
                "has_timelock": True,
                "required_dvns": 2,
                "rate_limit_enabled": True,
                "max_inbound_rate": 500_000 * 10**18,
                "peers": {
                    arb_eid: arb_addr,
                },
            },
            "arbitrum": {
                "address": arb_addr,
                "decimals": 18,
                "shared_decimals": 6,
                "total_supply": 4_000_000 * 10**18,
                "owner": "0x9999999999999999999999999999999999999999",
                "owner_is_contract": True,
                "has_timelock": True,
                "required_dvns": 2,
                "rate_limit_enabled": True,
                "max_inbound_rate": 500_000 * 10**18,
                "peers": {
                    base_eid: base_addr,
                },
            },
        },
    }

    res = verify_multichain_token_invariants(topology)

    assert res["verdict_pass"] is True
    assert res["status"] == "VERIFIED_SAFE"
    assert res["invariants"]["global_supply_conservation"]["passed"] is True
    assert res["invariants"]["global_supply_conservation"]["z3_solver_result"] == "unsat"
    assert res["invariants"]["peer_symmetry"]["passed"] is True
    assert res["invariants"]["peer_symmetry"]["z3_solver_result"] == "unsat"
    assert res["invariants"]["dvn_quorum"]["passed"] is True
    assert res["invariants"]["dvn_quorum"]["z3_solver_result"] == "unsat"
    assert res["invariants"]["admin_and_rate_limits"]["passed"] is True


# ---------------------------------------------------------------------------
# Test 2: Asymmetric Peer & Phantom Mint Peer -> Z3 FAIL with Witness
# ---------------------------------------------------------------------------

def test_asymmetric_peer_phantom_mint_peer():
    """
    Test asymmetric peers(eid) phantom mint peer -> Z3 FAIL with exact asymmetric edge witness.
    """
    base_addr = "0x1111111111111111111111111111111111111111"
    arb_addr = "0x2222222222222222222222222222222222222222"
    base_eid = LZ_V2_EIDS["base"]
    arb_eid = LZ_V2_EIDS["arbitrum"]

    topology = {
        "token_address": base_addr,
        "home_chain": "base",
        "chains": {
            "base": {
                "address": base_addr,
                "decimals": 18,
                "shared_decimals": 6,
                "total_supply": 10_000_000 * 10**18,
                "owner_is_contract": True,
                "has_timelock": True,
                "required_dvns": 2,
                "rate_limit_enabled": True,
                "max_inbound_rate": 100_000 * 10**18,
                "peers": {
                    arb_eid: arb_addr,
                    99999: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",  # Rogue phantom peer!
                },
            },
            "arbitrum": {
                "address": arb_addr,
                "decimals": 18,
                "shared_decimals": 6,
                "total_supply": 2_000_000 * 10**18,
                "owner_is_contract": True,
                "has_timelock": True,
                "required_dvns": 2,
                "rate_limit_enabled": True,
                "max_inbound_rate": 100_000 * 10**18,
                "peers": {
                    base_eid: "0x0000000000000000000000000000000000000000",  # Half-wired / zero peer
                },
            },
        },
    }

    res = verify_multichain_token_invariants(topology)

    assert res["verdict_pass"] is False
    assert res["status"] == "VERIFICATION_FAILED"

    sym_inv = res["invariants"]["peer_symmetry"]
    assert sym_inv["passed"] is False
    assert sym_inv["z3_solver_result"] == "sat"

    # Verify asymmetric edge witness
    assert len(sym_inv["asymmetric_edges"]) > 0
    edge = sym_inv["asymmetric_edges"][0]
    assert {edge["chain_a"], edge["chain_b"]} == {"base", "arbitrum"}
    assert "0x0000000000000000000000000000000000000000" in (edge["peer_on_a"], edge["peer_on_b"])

    # Verify phantom peer witness
    assert len(sym_inv["phantom_peers"]) == 1
    phantom = sym_inv["phantom_peers"][0]
    assert phantom["chain"] == "base"
    assert phantom["rogue_eid_or_key"] == 99999
    assert phantom["phantom_peer"] == "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


# ---------------------------------------------------------------------------
# Test 3: Single Verifier Quorum (1/1) -> SINGLE_POINT_OF_MINT_COMPROMISE
# ---------------------------------------------------------------------------

def test_single_verifier_quorum_single_point_of_compromise():
    """
    Test 1/1 DVN/NTT single-verifier quorum -> FAIL (SINGLE_POINT_OF_MINT_COMPROMISE).
    """
    base_addr = "0x1111111111111111111111111111111111111111"

    topology = {
        "token_address": base_addr,
        "home_chain": "base",
        "chains": {
            "base": {
                "address": base_addr,
                "decimals": 18,
                "shared_decimals": 6,
                "total_supply": 1_000_000 * 10**18,
                "owner_is_contract": True,
                "has_timelock": True,
                "required_dvns": 1,  # Insecure 1/1 quorum!
                "rate_limit_enabled": True,
                "max_inbound_rate": 100_000 * 10**18,
                "peers": {},
            },
        },
    }

    res = verify_multichain_token_invariants(topology)

    assert res["verdict_pass"] is False
    assert res["status"] == "VERIFICATION_FAILED"

    dvn_inv = res["invariants"]["dvn_quorum"]
    assert dvn_inv["passed"] is False
    assert dvn_inv["z3_solver_result"] == "sat"
    assert len(dvn_inv["single_point_of_compromise_routes"]) == 1

    spoc = dvn_inv["single_point_of_compromise_routes"][0]
    assert spoc["flag"] == "SINGLE_POINT_OF_MINT_COMPROMISE"
    assert spoc["configured_quorum"] == 1


# ---------------------------------------------------------------------------
# Test 4: Supply Inflation (sum(remote_minted) > home_locked_escrow) -> Z3 SAT
# ---------------------------------------------------------------------------

def test_supply_inflation_z3_sat_counterexample():
    """
    Test supply inflation (sum(remote_minted) > home_locked_escrow) ->
    Z3 SAT counterexample proving unbacked supply excess!
    """
    base_addr = "0x1111111111111111111111111111111111111111"
    arb_addr = "0x2222222222222222222222222222222222222222"
    op_addr = "0x3333333333333333333333333333333333333333"

    topology = {
        "token_address": base_addr,
        "home_chain": "base",
        "chains": {
            "base": {
                "address": base_addr,
                "decimals": 18,
                "shared_decimals": 6,
                "total_supply": 10_000_000 * 10**18,
                "locked_supply": 1_000_000 * 10**18,  # Escrow cap = 1,000,000 tokens
                "owner_is_contract": True,
                "has_timelock": True,
                "required_dvns": 2,
                "rate_limit_enabled": True,
                "max_inbound_rate": 100_000 * 10**18,
                "peers": {
                    LZ_V2_EIDS["arbitrum"]: arb_addr,
                    LZ_V2_EIDS["optimism"]: op_addr,
                },
            },
            "arbitrum": {
                "address": arb_addr,
                "decimals": 18,
                "shared_decimals": 6,
                "total_supply": 800_000 * 10**18,
                "owner_is_contract": True,
                "has_timelock": True,
                "required_dvns": 2,
                "rate_limit_enabled": True,
                "max_inbound_rate": 100_000 * 10**18,
                "peers": {LZ_V2_EIDS["base"]: base_addr},
            },
            "optimism": {
                "address": op_addr,
                "decimals": 18,
                "shared_decimals": 6,
                "total_supply": 700_000 * 10**18,  # 800k + 700k = 1.5M > 1.0M locked
                "owner_is_contract": True,
                "has_timelock": True,
                "required_dvns": 2,
                "rate_limit_enabled": True,
                "max_inbound_rate": 100_000 * 10**18,
                "peers": {LZ_V2_EIDS["base"]: base_addr},
            },
        },
    }

    res = verify_multichain_token_invariants(topology)

    assert res["verdict_pass"] is False
    assert res["status"] == "VERIFICATION_FAILED"

    sup_inv = res["invariants"]["global_supply_conservation"]
    assert sup_inv["passed"] is False
    assert sup_inv["z3_solver_result"] == "sat"
    assert sup_inv["unbacked_excess"] == 500_000 * 10**18
    assert any("SUPPLY_INFLATION_DETECTED" in d for d in sup_inv["details"])


# ---------------------------------------------------------------------------
# Test 5: RPC Discovery Parser + Mocked Caller + EAS Attestation Generator
# ---------------------------------------------------------------------------

def test_rpc_discovery_mocked_and_eas_attestation():
    """
    Test RPC discovery parser (discover_multichain_token_topology) with mocked
    rpc_caller hex responses + EAS attestation and report output.
    """
    base_addr = "0x1111111111111111111111111111111111111111"
    arb_addr = "0x2222222222222222222222222222222222222222"
    arb_eid = LZ_V2_EIDS["arbitrum"]
    base_eid = LZ_V2_EIDS["base"]

    def mock_rpc_caller(chain: str, to: str, data_hex: str) -> str:
        clean = data_hex.lower().replace("0x", "")
        sel = clean[:8]

        if sel == SELECTOR_DECIMALS:
            return "0x" + abi_encode_uint256(18)
        if sel == SELECTOR_TOTAL_SUPPLY:
            if chain == "base":
                return "0x" + abi_encode_uint256(5_000_000 * 10**18)
            return "0x" + abi_encode_uint256(2_000_000 * 10**18)
        if sel == SELECTOR_OWNER:
            return "0x" + abi_encode_bytes32_address("0x8888888888888888888888888888888888888888")
        if sel == SELECTOR_ENDPOINT:
            return "0x" + abi_encode_bytes32_address("0x1a44076050125825900e736c501f859c50fe728c")
        if sel == SELECTOR_SHARED_DECIMALS:
            return "0x" + abi_encode_uint256(6)
        if sel == SELECTOR_NTT_THRESHOLD:
            return "0x" + abi_encode_uint256(2)
        if sel == SELECTOR_PEERS:
            eid_arg = int(clean[8:72], 16)
            if chain == "base" and eid_arg == arb_eid:
                return "0x" + abi_encode_bytes32_address(arb_addr)
            if chain == "arbitrum" and eid_arg == base_eid:
                return "0x" + abi_encode_bytes32_address(base_addr)
            return "0x" + "0" * 64
        return "0x"

    topology = discover_multichain_token_topology(
        token_address=base_addr,
        home_chain="base",
        chains=["base", "arbitrum"],
        rpc_caller=mock_rpc_caller,
    )

    assert topology["home_chain"] == "base"
    assert "base" in topology["chains"]
    assert "arbitrum" in topology["chains"]
    assert topology["chains"]["base"]["decimals"] == 18
    assert topology["chains"]["base"]["shared_decimals"] == 6
    assert topology["chains"]["base"]["peers"][arb_eid] == arb_addr
    assert topology["chains"]["arbitrum"]["peers"][base_eid] == base_addr

    # Run formal verification on discovered topology
    verif = verify_multichain_token_invariants(topology)
    assert verif["verdict_pass"] is True
    assert verif["status"] == "VERIFIED_SAFE"

    # Build EAS Attestation & B2B Pre-TGE Report
    bundle = build_eas_attestation_and_report(verif)
    eas = bundle["eas_attestation"]
    report = bundle["report"]

    assert eas["eas_contract"] == BASE_EAS_CONTRACT
    assert eas["verdict_pass"] is True
    assert eas["recipient"] == base_addr
    assert eas["raw_abi_data"].startswith("0x")
    assert len(eas["raw_abi_data"]) > 100

    assert report["verdict"] == "VERIFIED_SAFE"
    assert report["title"].startswith("B2B Pre-TGE")
    assert "invariants_summary" in report
    assert "recommendations" in report


# ---------------------------------------------------------------------------
# Test 6: Decimal Dust Loss & Truncation Vulnerability
# ---------------------------------------------------------------------------

def test_decimal_dust_rate_mismatch_sat():
    """
    Test decimal dust loss: when local decimals is 6 but sharedDecimals is 8,
    rate is fractional, producing a Z3 SAT counterexample.
    """
    base_addr = "0x1111111111111111111111111111111111111111"
    sol_addr = "0x2222222222222222222222222222222222222222"

    topology = {
        "token_address": base_addr,
        "home_chain": "base",
        "chains": {
            "base": {
                "address": base_addr,
                "decimals": 18,
                "shared_decimals": 8,
                "total_supply": 1_000_000 * 10**18,
                "owner_is_contract": True,
                "has_timelock": True,
                "required_dvns": 2,
                "rate_limit_enabled": True,
                "max_inbound_rate": 100_000 * 10**18,
                "peers": {30168: sol_addr},
            },
            "solana": {
                "address": sol_addr,
                "decimals": 6,  # 6 < shared_decimals (8)!
                "shared_decimals": 8,
                "total_supply": 0,
                "owner_is_contract": True,
                "has_timelock": True,
                "required_dvns": 2,
                "rate_limit_enabled": True,
                "max_inbound_rate": 100_000 * 10**18,
                "peers": {30184: base_addr},
            },
        },
    }

    res = verify_multichain_token_invariants(topology)

    assert res["verdict_pass"] is False
    sup_inv = res["invariants"]["global_supply_conservation"]
    assert sup_inv["passed"] is False
    assert sup_inv["z3_solver_result"] == "sat"
    assert sup_inv["dust_witness"] is not None
    assert sup_inv["dust_witness"]["type"] == "SHARED_DECIMALS_EXCEEDS_LOCAL"


# ---------------------------------------------------------------------------
# Test 7: Admin Posture (EOA Owner & Unlimited Inbound Mint Rate)
# ---------------------------------------------------------------------------

def test_admin_eoa_and_unlimited_rate_limit_flags():
    """
    Test admin posture: EOA owner and disabled rate limiting raise flags.
    """
    base_addr = "0x1111111111111111111111111111111111111111"

    topology = {
        "token_address": base_addr,
        "home_chain": "base",
        "chains": {
            "base": {
                "address": base_addr,
                "decimals": 18,
                "shared_decimals": 6,
                "total_supply": 1_000_000 * 10**18,
                "owner": "0x5555555555555555555555555555555555555555",
                "owner_is_contract": False,  # EOA without timelock!
                "has_timelock": False,
                "required_dvns": 2,
                "rate_limit_enabled": False,  # Unlimited rate!
                "max_inbound_rate": None,
                "peers": {},
            },
        },
    }

    res = verify_multichain_token_invariants(topology)

    assert res["verdict_pass"] is False
    admin_inv = res["invariants"]["admin_and_rate_limits"]
    assert admin_inv["passed"] is False

    flags = [f["flag"] for f in admin_inv["flags"]]
    assert "owner_is_eoa_without_timelock" in flags
    assert "unlimited_inbound_mint_rate" in flags


# ---------------------------------------------------------------------------
# Test 8: ABI Helpers Round-Trip
# ---------------------------------------------------------------------------

def test_abi_helpers_round_trip():
    """Test pure python ABI encoding and decoding utilities."""
    # uint32
    enc32 = abi_encode_uint32(30184)
    assert len(enc32) == 64
    assert abi_decode_uint256(enc32) == 30184

    # uint256
    val = 123456789012345678901234567890
    enc256 = abi_encode_uint256(val)
    assert len(enc256) == 64
    assert abi_decode_uint256(enc256) == val

    # EVM address bytes32
    addr = "0x1234567890123456789012345678901234567890"
    enc_addr = abi_encode_bytes32_address(addr)
    assert len(enc_addr) == 64
    dec_addr = abi_decode_bytes32_address(enc_addr)
    assert dec_addr.lower() == addr.lower()


# ---------------------------------------------------------------------------
# Test 9: CLI Main
# ---------------------------------------------------------------------------

def test_cli_main(tmp_path):
    """Test CLI main() with mocked discovery and file output."""
    out_file = str(tmp_path / "report.json")

    mock_topology = {
        "token_address": "0x1111111111111111111111111111111111111111",
        "home_chain": "base",
        "chains": {
            "base": {
                "address": "0x1111111111111111111111111111111111111111",
                "decimals": 18,
                "shared_decimals": 6,
                "total_supply": 1_000_000 * 10**18,
                "owner_is_contract": True,
                "has_timelock": True,
                "required_dvns": 2,
                "rate_limit_enabled": True,
                "max_inbound_rate": 100_000 * 10**18,
                "peers": {},
            }
        },
    }

    test_args = [
        "multichain_token_verifier.py",
        "--address", "0x1111111111111111111111111111111111111111",
        "--chain", "base",
        "--out", out_file,
    ]

    with patch.object(sys, "argv", test_args):
        with patch(
            "omni_x402_prover.multichain_token_verifier.discover_multichain_token_topology",
            return_value=mock_topology,
        ):
            code = main()
            assert code == 0

    assert os.path.exists(out_file)
    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["report"]["verdict"] == "VERIFIED_SAFE"
    assert data["eas_attestation"]["eas_contract"] == BASE_EAS_CONTRACT


# ---------------------------------------------------------------------------
# Test 10: ProverService verify_bridge_and_oracle Tests
# ---------------------------------------------------------------------------

def test_prover_service_verify_bridge_and_oracle_backward_compat():
    """Test backward compatibility: verify_bridge_and_oracle with standard bridge memo."""
    from omni_x402_prover.prover_service import ProverService
    from omni_x402_prover.x402_protocol import X402Config

    service = ProverService(X402Config())
    res = service.verify_bridge_and_oracle({
        "memo": "SWAP:ETH.ETH:0x1111111111111111111111111111111111111111:100000:omni:10",
        "max_affiliate_bps": 100,
    })
    assert res["verified"] is True
    assert res["check_type"] == "crosschain_bridge_memo"
    assert res["action"] == "SWAP"


def test_prover_service_verify_bridge_and_oracle_multichain_config_mode():
    """Test multichain token verification mode via verify_bridge_and_oracle."""
    from omni_x402_prover.prover_service import ProverService
    from omni_x402_prover.x402_protocol import X402Config

    service = ProverService(X402Config())
    base_addr = "0x1111111111111111111111111111111111111111"
    arb_addr = "0x2222222222222222222222222222222222222222"
    base_eid = LZ_V2_EIDS["base"]
    arb_eid = LZ_V2_EIDS["arbitrum"]

    chains_config = {
        "base": {
            "address": base_addr,
            "decimals": 18,
            "shared_decimals": 6,
            "total_supply": 6_000_000 * 10**18,
            "locked_supply": 4_000_000 * 10**18,
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
            "total_supply": 4_000_000 * 10**18,
            "owner": "0x9999999999999999999999999999999999999999",
            "owner_is_contract": True,
            "has_timelock": True,
            "required_dvns": 2,
            "rate_limit_enabled": True,
            "max_inbound_rate": 500_000 * 10**18,
            "peers": {base_eid: base_addr},
        },
    }

    res = service.verify_bridge_and_oracle({
        "token_address": base_addr,
        "chain": "base",
        "declared_max_supply": 10_000_000 * 10**18,
        "chains_config": chains_config,
    })

    assert res["verified"] is True
    assert "multichain_token_audit" in res
    assert "eas_attestation" in res
    assert res["multichain_token_audit"]["status"] == "VERIFIED_SAFE"
    assert res["eas_attestation"]["eas_contract"] == BASE_EAS_CONTRACT


def test_prover_service_verify_bridge_and_oracle_1_address_mode():
    """Test 1-address mode with mocked live RPC discovery."""
    from omni_x402_prover.prover_service import ProverService
    from omni_x402_prover.x402_protocol import X402Config

    service = ProverService(X402Config())
    base_addr = "0x1111111111111111111111111111111111111111"

    mock_audit_res = {
        "topology": {"token_address": base_addr, "home_chain": "base"},
        "verification": {"verdict_pass": True, "status": "VERIFIED_SAFE", "chains_checked": ["base"]},
        "report": {"verdict": "VERIFIED_SAFE"},
        "eas_attestation": {"eas_contract": BASE_EAS_CONTRACT, "verdict_pass": True},
    }

    with patch("omni_x402_prover.prover_service.audit_multichain_token", return_value=mock_audit_res):
        res = service.verify_bridge_and_oracle({
            "token_address": base_addr,
            "chain": "base",
        })

    assert res["verified"] is True
    assert "multichain_token_audit" in res
    assert res["multichain_token_audit"]["verdict_pass"] is True
    assert "eas_attestation" in res


# ---------------------------------------------------------------------------
# Test 11: HTTP GET /x402/multichain-token/preview Lead-Magnet Tests
# ---------------------------------------------------------------------------

def test_http_multichain_token_preview_routes():
    """Test GET /x402/multichain-token/preview free lead magnet route."""
    import threading
    import time
    import urllib.error
    import urllib.request
    from omni_x402_prover.http_server import create_http_server
    from omni_x402_prover.prover_service import ProverService
    from omni_x402_prover.x402_protocol import (
        DeterministicMockFacilitator,
        ReplayNonceStore,
        X402Config,
    )

    config = X402Config()
    service = ProverService(config)
    nonce_store = ReplayNonceStore()
    facilitator = DeterministicMockFacilitator(config)

    server = create_http_server(
        host="127.0.0.1",
        port=0,
        config=config,
        prover_service=service,
        nonce_store=nonce_store,
        facilitator=facilitator,
    )
    _, port = server.server_address
    base_url = f"http://127.0.0.1:{port}"

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.05)

    try:
        # 1. Asymmetric peer demo
        url_asym = f"{base_url}/x402/multichain-token/preview?demo=asymmetric_peer"
        req = urllib.request.Request(url_asym)
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"
            assert data["verdict"] == "VERIFICATION_FAILED"
            assert data["standard"] == "OFT"
            assert "base" in data["chains_checked"]
            assert data["unlock_full_attestation_endpoint"] == "/x402/verify-bridge-and-oracle"
            # Invariants witness is redacted
            assert "witness" not in data

        # 2. Supply conservation demo
        url_supply = f"{base_url}/x402/multichain-token/preview?demo=supply_conservation"
        req = urllib.request.Request(url_supply)
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"
            assert data["verdict"] == "VERIFICATION_FAILED"

        # 3. Missing params -> 400 Bad Request
        url_bad = f"{base_url}/x402/multichain-token/preview"
        req_bad = urllib.request.Request(url_bad)
        try:
            urllib.request.urlopen(req_bad)
            assert False, "Should have returned 400"
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
            body = json.loads(exc.read().decode("utf-8"))
            assert "error" in body

    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=1.0)


# ---------------------------------------------------------------------------
# Test 12: Preview hardening (offline): normalized-param cache, 503 + Retry-After, generic 500s
# ---------------------------------------------------------------------------

@pytest.fixture
def multichain_preview():
    """Loopback server whose multichain preview gate has one slot and a controllable clock."""
    import threading
    import urllib.error
    import urllib.request
    from omni_x402_prover.http_server import PreviewGate, create_http_server
    from omni_x402_prover.prover_service import ProverService
    from omni_x402_prover.x402_protocol import (
        DeterministicMockFacilitator,
        ReplayNonceStore,
        X402Config,
    )

    config = X402Config()
    server = create_http_server(
        host="127.0.0.1",
        port=0,
        config=config,
        prover_service=ProverService(config),
        nonce_store=ReplayNonceStore(),
        facilitator=DeterministicMockFacilitator(config),
    )
    now = [1000.0]
    gate = PreviewGate(max_concurrent=1, clock=lambda: now[0])
    server.RequestHandlerClass.multichain_preview_gate = gate
    url = f"http://127.0.0.1:{server.server_address[1]}/x402/multichain-token/preview"

    def get(query):
        try:
            with urllib.request.urlopen(f"{url}?{query}", timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8")), resp.headers
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8")), exc.headers

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        yield get, gate, now
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=1.0)


def test_http_multichain_token_preview_cache_and_capacity(multichain_preview):
    from omni_x402_prover.http_server import PREVIEW_CACHE_TTL_SECONDS, PREVIEW_RETRY_AFTER_SECONDS

    get, gate, now = multichain_preview
    token = "0xAbCdEf0000000000000000000000000000000001"
    audit_result = {"verification": {"status": "VERIFIED_SAFE", "chains_checked": ["base", "arbitrum"]}}
    with patch("omni_x402_prover.http_server.audit_multichain_token", return_value=audit_result) as audit:
        status, data, _ = get(f"token={token}&chain=base&standard=OFT")
        assert status == 200
        assert (data["verdict"], data["standard"], data["chains_checked"]) == ("VERIFIED_SAFE", "OFT", ["base", "arbitrum"])
        audit.assert_called_once_with(token_address=token, home_chain="base")

        status, data, _ = get(f"token={token.lower()}&chain=BASE&standard=ntt")
        assert (status, data["verdict"], data["standard"]) == (200, "VERIFIED_SAFE", "NTT")
        assert audit.call_count == 1

        assert gate.try_acquire()
        try:
            cached_status = get(f"token={token}&chain=base")[0]
            status, data, headers = get(f"token={token}&chain=arbitrum")
        finally:
            gate.release()
        assert cached_status == 200
        assert status == 503
        assert headers.get("Retry-After") == str(PREVIEW_RETRY_AFTER_SECONDS)
        assert "error" in data
        assert audit.call_count == 1

        now[0] += PREVIEW_CACHE_TTL_SECONDS
        assert get(f"token={token}&chain=base")[0] == 200
        assert audit.call_count == 2


def test_http_multichain_token_preview_errors_are_generic(multichain_preview, caplog):
    import logging

    get, gate, _ = multichain_preview
    secret = "rpc https://internal-rpc.example/v1/private-path refused"
    demo_result = {"status": "VERIFICATION_FAILED", "chains_checked": ["base", "arbitrum"]}
    caplog.set_level(logging.ERROR, logger="omni_x402_prover.http")
    with patch(
        "omni_x402_prover.http_server.verify_multichain_token_invariants",
        side_effect=[RuntimeError(secret), demo_result],
    ):
        status, data, _ = get("demo=asymmetric_peer")
        assert status == 500
        assert data == {"error": "Failed to compute multichain token preview"}
        assert any(
            r.name == "omni_x402_prover.http" and r.exc_info and str(r.exc_info[1]) == secret
            for r in caplog.records
        )
        assert gate.try_acquire()
        gate.release()

        status, data, _ = get("demo=asymmetric_peer")
        assert (status, data["verdict"]) == (200, "VERIFICATION_FAILED")
