---
name: omni-x402-formal-prover
description: Production-grade formal verification pay-per-proof engine for autonomous agents. Call via HTTP x402 with agentcash or via MCP. Covers ERC-4626 vault rounding, Polymarket solvency, ZK circuits, AMM invariants, Permit2 approvals, Merkle airdrops, and financial forensic graphs on Base USDC.
---

# Omni x402 Formal Invariant Prover

The **Omni x402 Formal Invariant Prover** provides mathematical and formal Z3 verification APIs for autonomous AI agents, smart contract auditors, algorithmic traders, and compliance engines.

Every verification endpoint is monetized with gasless **x402 micropayments** on **Base Mainnet USDC** (`eip155:8453`) settled via EIP-3009 (`transferWithAuthorization`).

---

## 1. Settlement & Discovery Endpoints

- **Live Gateways**:
  - `https://gateway.stealthmark.io`
  - `https://sentinel.oceaneye-ai.com`
- **x402scan Registrations**:
  - `https://www.x402scan.com/server/f2245b59-82c5-46ae-bb13-d88836d7910f`
  - `https://www.x402scan.com/server/4f613c20-a216-4742-be54-8cd621415701`
- **Metadata Endpoints**:
  - OpenAPI 3.1.0: `GET /openapi.json`
  - Coinbase x402 Bazaar Catalog: `GET /.well-known/x402-bazaar.json`
  - Health & Z3 Solver: `GET /x402/health`
  - Dynamic LLMs Guide: `GET /llms.txt` or `GET /x402/llms.txt`

---

## 2. How to Call Endpoints

### A. HTTP via `agentcash` CLI
Use Coinbase's `agentcash` runner to automatically handle x402 402 payment challenges and sign EIP-3009 authorizations:

```bash
npx -y agentcash@latest fetch https://gateway.stealthmark.io/x402/verify-vault-and-rounding \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "deposit_fn_code": "def preview_deposit(assets, total_assets, total_shares):\n    return (assets * total_shares) // total_assets if total_assets > 0 else assets",
    "redeem_fn_code": "def preview_redeem(shares, total_assets, total_shares):\n    return (shares * total_assets) // total_shares if total_shares > 0 else shares"
  }'
```

### B. Via Model Context Protocol (MCP)
Add `omni-x402-prover` to your MCP configuration (`claude_desktop_config.json`, Cursor, or OpenClaw):

```json
{
  "mcpServers": {
    "omni-x402-prover": {
      "command": "python",
      "args": ["-m", "omni_x402_prover.mcp_server"],
      "env": {
        "X402_PAY_TO_ADDRESS": "0xc8dc4ecb93c4c665Fad07E1261F5f7D60e3C6E0F",
        "X402_NETWORK": "base",
        "X402_ASSET_ADDRESS": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "X402_FACILITATOR_URL": "https://facilitator.payai.network"
      }
    }
  }
}
```

---

## 3. The 16 Paid Formal Verification Endpoints

### 1. `/x402/verify-vault-and-rounding` (MCP: `x402_verify_vault_rounding`)
- **Price**: $0.02 USDC (`20000` atomic units)
- **When to call**: Verifying ERC-4626 vault share rounding behavior, deposit-redeem inflation attacks, and rounding asymmetry.
- **Key Inputs**: `deposit_fn_code` (str), `redeem_fn_code` (str), optional: `max_assets`, `max_shares`, `check_zero_share_mint`.

### 2. `/x402/verify-polymarket-basket` (MCP: `x402_verify_polymarket_basket`)
- **Price**: $0.02 USDC (`20000` atomic units)
- **When to call**: Arbitrage and solvency audit across Polymarket NegRisk or conditional token market baskets.
- **Key Inputs**: `outcome_ask_prices` (list of floats), optional: `fee_bps`, `payout_per_share`, `custom_conversion_formula`.

### 3. `/x402/verify-zk-and-bitvec` (MCP: `x402_verify_zk_or_bitvec`)
- **Price**: $0.03 USDC (`30000` atomic units)
- **When to call**: Checking zero-knowledge circuit witness uniqueness (detecting under-constrained signals) or bitvector integer cast truncations.
- **Key Inputs**: `mode` ("zk" or "bitvec"), `expr` / `constraints_exprs`, `public_inputs`, `witness_vars`, `output_var`.

### 4. `/x402/verify-differential-spec` (MCP: `x402_verify_differential_spec`)
- **Price**: $0.05 USDC (`50000` atomic units)
- **When to call**: Proving mathematical equivalence between two implementations (e.g. optimized assembly vs reference spec).
- **Key Inputs**: `code_a` (str), `code_b` (str), `arg_names` (list of str), optional: `fuzz_iterations`, `seed`.

### 5. `/x402/verify-forensic-graph` (MCP: `x402_verify_forensic_graph`)
- **Price**: $0.05 USDC (`50000` atomic units)
- **When to call**: Financial crime investigation, cyclic wash-trading collapse (Tarjan algorithm), and bridge hop taint tracing.
- **Key Inputs**: `transactions` (list of objects), `tainted_sources` (list of str), optional: `protocol_nodes`, `bridge_nodes`, `max_window_seconds`.

### 6. `/x402/verify-ast-blast-radius` (MCP: `x402_verify_ast_blast_radius`)
- **Price**: $0.03 USDC (`30000` atomic units)
- **When to call**: Pre-merge patch safety audit computing 2-hop AST call-graph impact and upstream fork synchronization gaps.
- **Key Inputs**: `patch_text` (str), `modified_symbols` (list of str), optional: `source_code`, `fork_code`, `upstream_patch_spec`.

### 7. `/x402/verify-erc4626-inflation-guard` (MCP: `x402_verify_erc4626_inflation_guard`)
- **Price**: $0.03 USDC (`30000` atomic units)
- **When to call**: Auditing ERC-4626 vault virtual share/asset offset parameters against donation frontrunning exploits.
- **Key Inputs**: `virtual_shares_offset` (int), `virtual_assets_offset` (int), `attacker_initial_deposit` (int), `attacker_donation` (int), `victim_deposit` (int).

### 8. `/x402/verify-amm-constant-product` (MCP: `x402_verify_amm_constant_product`)
- **Price**: $0.03 USDC (`30000` atomic units)
- **When to call**: Verifying constant-product ($x \cdot y = k$) AMM invariant preservation and zero-loss integer rounding direction.
- **Key Inputs**: `reserve_x` (int), `reserve_y` (int), optional: `amount_in`, `amount_out`, `fee_bps`, `rounding_direction`.

### 9. `/x402/verify-crosschain-bridge-memo` (MCP: `x402_verify_crosschain_bridge_memo`)
- **Price**: $0.02 USDC (`20000` atomic units)
- **When to call**: Sanitizing and auditing THORChain or Maya Protocol cross-chain memos against injection attacks and excessive affiliate fee bps.
- **Key Inputs**: `memo` (str), optional: `max_affiliate_bps`, `require_slippage_limit`.

### 10. `/x402/verify-cardano-eutxo-conservation` (MCP: `x402_verify_cardano_eutxo_conservation`)
- **Price**: $0.03 USDC (`30000` atomic units)
- **When to call**: Validating Cardano eUTxO balance conservation, native asset preservation, and Plutus double satisfaction defenses.
- **Key Inputs**: `inputs` (list of objects), `outputs` (list of objects), optional: `minted`, `fee_lovelace`, `min_utxo_lovelace`.

### 11. `/x402/verify-mev-sandwich-bound` (MCP: `x402_verify_mev_sandwich_bound`)
- **Price**: $0.02 USDC (`20000` atomic units)
- **When to call**: Calculating analytical MEV sandwich extraction bounds and optimal frontrun/backrun impact for DEX trades.
- **Key Inputs**: `reserve_in` (int), `reserve_out` (int), `user_amount_in` (int), optional: `slippage_bps`, `fee_bps`, `attacker_gas_cost_in`.

### 12. `/x402/verify-permit2-signature-scope` (MCP: `x402_verify_permit2_signature_scope`)
- **Price**: $0.02 USDC (`20000` atomic units)
- **When to call**: Pre-signing security check for Uniswap Permit2 signature payloads to prevent indefinite allowance drain.
- **Key Inputs**: `spender` (str), `amount` (int), `expiration` (int), `sig_deadline` (int), optional: `chain_id`, `trusted_spenders`.

### 13. `/x402/verify-liquidation-waterfall` (MCP: `x402_verify_liquidation_waterfall`)
- **Price**: $0.04 USDC (`40000` atomic units)
- **When to call**: Lending market risk parameter audit (health factor, close factor, bonus cap, and bad debt shortfall).
- **Key Inputs**: `collateral_value` (int), `debt_value` (int), optional: `liquidation_threshold_bps`, `liquidation_bonus_bps`, `insurance_fund_balance`.

### 14. `/x402/verify-merkle-airdrop-claim` (MCP: `x402_verify_merkle_airdrop_claim`)
- **Price**: $0.02 USDC (`20000` atomic units)
- **When to call**: Airdrop distribution integrity check for Merkle trees to detect 64-byte preimage attacks and duplicate claims.
- **Key Inputs**: `claims` (list of objects with `account` and `amount`), optional: `leaf_hash_mode` ("double_hash" or "keccak256").

### 15. `/x402/verify-fiat-crypto-otc-settlement` (MCP: `x402_verify_fiat_crypto_otc_settlement`)
- **Price**: $0.05 USDC (`50000` atomic units)
- **When to call**: Cross-border fiat-crypto OTC trade settlement audit for FX spread conformity and skimming detection.
- **Key Inputs**: `fiat_legs` (list), `crypto_legs` (list), `agreed_fx_ars_per_usd` (float), optional: `max_spread_bps`, `fee_bps`.

### 16. `/x402/verify-sar-ed25519-dossier` (MCP: `x402_verify_sar_ed25519_dossier`)
- **Price**: $0.05 USDC (`50000` atomic units)
- **When to call**: Maritime domain awareness verification: SAR satellite dark vessel EEZ intrusion + Ed25519 RFC 8032 audit.
- **Key Inputs**: `lat` (float), `lon` (float), optional: `vessel_id`, `rcs_db`, `ais_active`, `ed25519_pubkey_hex`, `ed25519_signature_hex`.

---

## 4. Agent Integration Guides

### Claude Code & Cursor
When Claude Code or Cursor is executing auditing or DeFi tasks, invoke the formal prover to guarantee invariants before generating or reviewing code.

### OpenClaw & ElizaOS
Configure agent execution actions to call `/x402/verify-*` endpoints before executing high-value swaps, bridge transactions, or lending positions.

### Coinbase AgentKit
Use Coinbase AgentKit's built-in x402 payment client to settle micropayments directly from your agent's Base wallet with zero human intervention.
