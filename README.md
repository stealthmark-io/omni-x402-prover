## ⚡ Live x402 v2 Formal Security, DeFi & Forensic Prover (16 Base Mainnet USDC Endpoints)

- **x402scan Verified Server (OceanEye Origin — 16/16 Resources)**: [https://www.x402scan.com/server/f2245b59-82c5-46ae-bb13-d88836d7910f](https://www.x402scan.com/server/f2245b59-82c5-46ae-bb13-d88836d7910f)
- **x402scan Verified Server (StealthMark Origin — 16/16 Resources)**: [https://www.x402scan.com/server/4f613c20-a216-4742-be54-8cd621415701](https://www.x402scan.com/server/4f613c20-a216-4742-be54-8cd621415701)
- **OpenAPI 3.1 Discovery**: `https://sentinel.oceaneye-ai.com/openapi.json`
- **x402 Bazaar Manifest**: `https://sentinel.oceaneye-ai.com/.well-known/x402-bazaar.json`
- **Quick Test via AgentCash**:
  ```bash
  npx -y agentcash@latest try https://sentinel.oceaneye-ai.com
  npx -y agentcash@latest try https://gateway.stealthmark.io
  ```

---

# Omni x402 Prover: Pay-Per-Proof Formal Verification Server

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero External Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](pyproject.toml)
[![Coinbase x402 Bazaar](https://img.shields.io/badge/x402-Bazaar%20Ready-blueviolet.svg)](https://cdp.coinbase.com)
[![Network](https://img.shields.io/badge/Network-Base%20USDC-0052FF.svg)](https://base.org)

**Omni x402 Prover** is a production-grade, zero-external-dependency Python 3.10+ **x402 Pay-Per-Proof HTTP + Model Context Protocol (MCP) Server** designed for **Coinbase x402 Bazaar** (`cdp.coinbase.com` / `x402bazaar.org`).

It enables autonomous AI agents, smart contracts, and Web3 developers to execute automated, high-assurance formal cryptographic invariant verification (Z3 SMT solver and bounded algebraic solver) by paying micropayments in Base USDC per proof call.

---

## Key Highlights

- **Zero External Dependencies**: Operates exclusively using Python 3.10+ standard library (`http.server`, `urllib.request`, `ast`, `hashlib`, `dataclasses`, `json`).
- **100% Non-Custodial**: Never accepts, handles, or stores private keys. Micropayments settle directly on Base to your configured cold wallet or multisig via EIP-3009 authorizations.
- **Replay-Proof Security**: Thread-safe `ReplayNonceStore` guarantees that consumed payment authorizations and digests cannot be replayed twice.
- **Dual Verification Engines**: Seamlessly leverages `asi_engine.verifiers` (SMT-LIB2 / Z3-Solver) on the Hermes VM, with pure-Python bounded algebraic fallbacks for headless/standalone deployments.
- **Dual Interfaces**: Exposes both a standard REST/HTTP server (`ThreadingHTTPServer`) and a JSON-RPC 2.0 `stdio` MCP server compatible with **Coinbase Payments MCP**.

---

## Monetized Verification Endpoints & Pricing

All payments are settled in **Base USDC** (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, 6 decimals):

| Route / Tool | Pricing (Atomic) | Pricing (USDC) | Target Verification Domain |
|---|---|---|---|
| `/x402/verify-vault-and-rounding`<br>`x402_verify_vault_rounding` | `20000` | \$0.02 USDC | ERC-4626, Euler v2, Meteora share rounding asymmetries & zero-share donation attacks |
| `/x402/verify-polymarket-basket`<br>`x402_verify_polymarket_basket` | `20000` | \$0.02 USDC | Polymarket NegRisk / CTF conditional token solvency & Dutch-book net edge verification |
| `/x402/verify-zk-and-bitvec`<br>`x402_verify_zk_or_bitvec` | `30000` | \$0.03 USDC | ZK circuit witness uniqueness (SP1, RISC Zero, Circom) or BitVector integer cast truncation |
| `/x402/verify-differential-spec`<br>`x402_verify_differential_spec` | `50000` | \$0.05 USDC | Differential consensus equivalence between two implementations (C vs Rust, Reth vs Geth) |
| `/.well-known/x402-bazaar.json`<br>`x402_bazaar_catalog` | `0` (Free) | Free | Semantic catalog discovery manifest for automated Coinbase x402 Bazaar indexing |

---

## Architecture & Payment Flow

```
+------------------------+             +------------------------+
| Autonomous AI Agent    |             | Omni x402 Prover       |
| (or MCP Client)        |             | (HTTP / MCP Server)    |
+------------------------+             +------------------------+
            |                                       |
            | 1. POST /x402/* (without payment)     |
            |-------------------------------------->|
            |                                       | Checks payment header
            | 2. HTTP 402 Payment Required          | (missing)
            |<--------------------------------------|
            |    {x402Version: 1, accepts: [...]}   |
            |                                       |
            | 3. Signs EIP-3009 transfer authorization (Base USDC)
            |                                       |
            | 4. POST /x402/*                       |
            |    Header: X-PAYMENT: <base64_auth>   |
            |-------------------------------------->|
            |                                       | 1. Replay check (nonce store)
            |                                       | 2. Facilitator verify & settle
            |                                       | 3. Record nonce atomically
            |                                       | 4. Run Z3 formal verification
            | 5. HTTP 200 OK                        |
            |    Header: X-PAYMENT-RESPONSE: <rcpt> |
            |<--------------------------------------|
            |    Body: {verified: true/false, ...}  |
            v                                       v
```

---

## Configuration & Environment Variables

All parameters are configured via environment variables (`X402Config.from_env()`). No personal secrets or private keys are ever stored or handled:

```bash
# EVM Recipient Address on Base (Base USDC recipient)
export X402_PAY_TO_ADDRESS="0xc8dc4ecb93c4c665Fad07E1261F5f7D60e3C6E0F"

# Target Network (base or base-sepolia)
export X402_NETWORK="base"

# Base Mainnet USDC Contract Address (6 decimals)
export X402_ASSET_ADDRESS="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

# Facilitator URL for verification and on-chain settlement
# Production Base default: PayAI Network Facilitator
export X402_FACILITATOR_URL="https://facilitator.payai.network"

# Optional: Coinbase CDP Facilitator credentials for per-request EdDSA/ES256 JWT signing
# (used automatically on failover to https://api.cdp.coinbase.com/platform/v2/x402 or when CDP is primary)
# export CDP_API_KEY_ID="organizations/.../apiKeys/..."
# export CDP_API_KEY_SECRET="your_ed25519_base64_or_ec_pem_secret"

# Optional: Static Bearer token for non-Coinbase facilitators requiring static auth
# export X402_FACILITATOR_BEARER_TOKEN="your_primary_facilitator_bearer_token"

# Set to 1 for offline testing/demo mode without on-chain settlement
export X402_MOCK_FACILITATOR=0

# Maximum payment authorization window (seconds)
export X402_MAX_TIMEOUT_SECONDS=60

# Pricing in atomic units (6 decimals: 20000 = \$0.02 USDC)
export X402_PRICE_VAULT_ATOMIC=20000
export X402_PRICE_POLYMARKET_ATOMIC=20000
export X402_PRICE_ZK_BITVEC_ATOMIC=30000
export X402_PRICE_DIFFERENTIAL_ATOMIC=50000
```

---

## Running the Servers

### 1. HTTP Server (REST + OpenAPI 3.1.0 + x402 Bazaar)

#### Live Base Mainnet USDC Settlement (Default)
In production, `omni-x402-prover` connects directly to the Base Mainnet facilitator (`https://facilitator.payai.network`) to settle real Base USDC micropayments directly to your non-custodial EVM wallet (`0xc8dc4ecb93c4c665Fad07E1261F5f7D60e3C6E0F`):

```bash
python3 -m omni_x402_prover.http_server --host 127.0.0.1 --port 8402 --facilitator https://facilitator.payai.network
```

#### Alternative / Failover: Coinbase CDP Facilitator (Per-Request Signed JWT)
If utilizing the Coinbase Developer Platform Facilitator (as primary or automatic secondary failover with EdDSA/ES256 per-request JWT signing):
```bash
export CDP_API_KEY_ID="organizations/.../apiKeys/..."
export CDP_API_KEY_SECRET="your_ed25519_base64_or_ec_pem_secret"
python3 -m omni_x402_prover.http_server --host 127.0.0.1 --port 8402
```

#### Offline Demo / Local Testing Mode
To run an offline mock facilitator without on-chain settlement:
```bash
python3 -m omni_x402_prover.http_server --host 127.0.0.1 --port 8402 --mock-facilitator
# or via environment variable:
X402_MOCK_FACILITATOR=1 python3 -m omni_x402_prover.http_server
```

Endpoints available:
- `GET /health` -> Server status, Z3 engine status, network parameters.
- `GET /openapi.json` -> Full OpenAPI 3.1.0 specification with `x-x402` monetization metadata.
- `GET /.well-known/x402-bazaar.json` -> Coinbase x402 Bazaar discovery catalog.
- `POST /x402/verify-vault-and-rounding` -> Paid vault formal verification ($0.02 USDC).
- `POST /x402/verify-polymarket-basket` -> Paid Polymarket solvency verification ($0.02 USDC).
- `POST /x402/verify-zk-and-bitvec` -> Paid ZK / BitVector verification ($0.03 USDC).
- `POST /x402/verify-differential-spec` -> Paid differential consensus verification ($0.05 USDC).

### 2. Model Context Protocol (MCP) Server (`stdio`)

The MCP server connects via standard input/output (`stdio`) and integrates seamlessly with Claude Desktop, Cursor, and Coinbase Payments MCP:

```bash
# Live on-chain Base settlement:
python3 -m omni_x402_prover.mcp_server

# Offline mock testing mode:
python3 -m omni_x402_prover.mcp_server --mock-facilitator
```

In your `claude_desktop_config.json` or MCP settings:
```json
{
  "mcpServers": {
    "omni-x402-prover": {
      "command": "python3",
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

## Live Exposure & Registry Indexing

### Quick Public HTTPS with Cloudflare Quick Tunnel
Expose your local server to the public internet with a single command:
```bash
cloudflared tunnel --url http://127.0.0.1:8402
```
Cloudflare will assign an ephemeral `https://<random-id>.trycloudflare.com` URL that forwards traffic seamlessly with automatic SSL termination.

### Registering on x402scan (`x402scan.com/resources/register`)
1. Go to [x402scan.com/resources/register](https://x402scan.com/resources/register).
2. Enter your public server URL (e.g. `https://prover.yourdomain.com`).
3. Point OpenAPI registration to `https://prover.yourdomain.com/openapi.json`.
4. `x402scan` automatically parses the OpenAPI 3.1.0 spec, validates the 4 `/x402/*` routes and pricing metadata, and publishes the resource to the live registry.

### Indexing on Coinbase x402 Bazaar
1. Ensure `curl -s https://prover.yourdomain.com/.well-known/x402-bazaar.json` returns valid JSON.
2. Submit your base URL to Coinbase Developer Platform (CDP) x402 Bazaar.
3. Autonomous agents querying Bazaar discover your verifier capabilities and pay via Base USDC.

### Standalone Listing: Smithery, Glama, and mcp.so
`omni-x402-prover` is packaged for 1-click standalone listing:
- **`smithery.yaml`**: Full configuration schema and stdio startup function.
- **`mcp.json`**: Standard MCP client manifest.
- **`Dockerfile`**: Containerized deployment with Python 3.12 and Z3 solver.
- **`pyproject.toml`**: Fully pip-installable with console scripts `omni-x402-http` and `omni-x402-mcp`.

---

## Production Deployment Recipe: Hermes VM + Cloudflare Tunnel + systemd

### Step 1: Install systemd Service

On your Hermes VM, create `/etc/systemd/system/omni-x402-prover.service`:

```ini
[Unit]
Description=Omni x402 Prover Pay-Per-Proof HTTP Server
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/omni-money-suite/omni-x402-prover
EnvironmentFile=/opt/omni-money-suite/omni-x402-prover/.env
ExecStart=/usr/bin/python3 -m omni_x402_prover.http_server --host 127.0.0.1 --port 8402 --facilitator https://facilitator.payai.network
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable omni-x402-prover
sudo systemctl start omni-x402-prover
sudo systemctl status omni-x402-prover
```

### Step 2: Cloudflare Tunnel Production Setup

```bash
# 1. Install cloudflared
curl -fsSL https://pkg.cloudflare.com/cloudflared-ascii.repo | sudo tee /etc/yum.repos.d/cloudflared.repo
sudo apt-get install cloudflared || sudo yum install cloudflared

# 2. Authenticate and create named tunnel
cloudflared tunnel login
cloudflared tunnel create omni-x402

# 3. Configure routing (~/.cloudflared/config.yml)
# tunnel: <TUNNEL_UUID>
# credentials-file: /home/ubuntu/.cloudflared/<TUNNEL_UUID>.json
# ingress:
#   - hostname: prover.yourdomain.com
#     service: http://127.0.0.1:8402
#   - service: http_status:404

# 4. Route DNS and run tunnel as a service
cloudflared tunnel route dns omni-x402 prover.yourdomain.com
sudo cloudflared service install
sudo systemctl start cloudflared
```

---

## Registering on Coinbase x402 Bazaar

Once your server is live at `https://prover.yourdomain.com`:

1. **Verify Bazaar Manifest**:
   Ensure `curl -s https://prover.yourdomain.com/.well-known/x402-bazaar.json` returns valid JSON conforming to the x402 v1 specification.
2. **Submit to Coinbase Developer Platform (CDP)**:
   Navigate to [Coinbase Developer Platform](https://cdp.coinbase.com) or [x402bazaar.org](https://x402bazaar.org).
3. **Index Endpoints**:
   Provide your base URL `https://prover.yourdomain.com`. The bazaar crawler will automatically detect the 4 paid endpoints, verification capabilities, input schemas, and price per call (\$0.02 to \$0.05 USDC).
4. **Autonomous Agent Consumption**:
   Autonomous agents querying the x402 Bazaar can now discover `omni-x402-prover`, pay via Base USDC micropayments, and receive verifiable formal proofs!

---

## Running Test Suite

Omni x402 Prover includes a comprehensive test suite covering protocol compliance, replay protection, facilitator settlement, and live loopback HTTP server calls:

```bash
python3 -m unittest discover -s tests -v
```
