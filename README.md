# ingravity-security (SDK v1.3.0 · Swarm v3.13.0)

> Autonomous 5-EVM Web3 Pre-Flight Security, `$0.01` Binary Fast-Ping, `$0.04/$0.12` Direct `0x` Token Honeypot Scanner (`GET` & `POST`), `$0.04/$0.10` BigInt MEV Guard, Atomic EIP-5792 Safe-Harbor Rescue Provider & STDIO/HTTP MCP (`2025-06-18`) for **Coinbase AgentKit**, **ElizaOS**, **AgentCash / x402 v2**, **Claude Desktop**, and **Cursor** on Base (`8453`), Arbitrum (`42161`), Optimism (`10`), Polygon (`137`), and Ethereum (`1`).

Settles programmatically per-call in native USDC via **x402 v2** on Base Mainnet (`eip155:8453`) with zero subscriptions or API keys.

[![npm version](https://img.shields.io/badge/npm-1.3.0-blue.svg)](https://www.npmjs.com/package/ingravity-security)
[![Swarm](https://img.shields.io/badge/Swarm-v3.13.0-0052FF.svg)](https://red-shape-1b3b.daviddelmoral79.workers.dev/)
[![Settlement](https://img.shields.io/badge/Settlement-x402%20v2%20USDC-10B981.svg)](https://red-shape-1b3b.daviddelmoral79.workers.dev/.well-known/x402)
[![ERC-8004](https://img.shields.io/badge/ERC--8004-Agent%20%2310252-0ea5e9.svg)](https://www.8004scan.io/agents/base/10252)
[![Glama Connector](https://img.shields.io/badge/Glama-Verified%20Connector-8B5CF6.svg)](https://glama.ai/mcp/connectors/dev.workers.daviddelmoral79.red-shape-1b3b/ingravity-evm-security-mcp)

---

## Cryptographic Provenance & Zero-Custody Guarantee

* **Canonical Live Gateway:** [https://red-shape-1b3b.daviddelmoral79.workers.dev](https://red-shape-1b3b.daviddelmoral79.workers.dev)
* **GitHub Pages Docs:** [https://dms1979.github.io/ingravity-security/](https://dms1979.github.io/ingravity-security/)
* **On-Chain Agent Identity:** [ERC-8004 Agent #10252 on Base](https://www.8004scan.io/agents/base/10252)
* **Base Treasury (`PayTo`):** [`0xAA99e12320a3db0116ef56D2e19F70f6796Bad0f`](https://basescan.org/address/0xAA99e12320a3db0116ef56D2e19F70f6796Bad0f#tokentxns)
* **Base Builder Code:** `bc_i26d7owr` (ERC-8021)
* **Zero-Custody Guarantee:** Every x402 settlement uses strict USDC EIP-3009 `transferWithAuthorization` or ERC-20 `transfer(0xa9059cbb)`. Ingravity **NEVER** asks for `ERC-20 approve()` to itself.

---

## What's Live in Swarm v3.13.0 (SDK v1.3.0)

* **`$0.01` Fast-Ping & Ultra-Competitive Token/MEV Floor (`$0.04`):**
  * `GET | POST /api/v1/fast-ping`: **`$0.01 USDC`** flat (`10000` atomic units) binary `SAFE / DANGER` pre-swap check.
  * `GET | POST /api/v1/token-rug-scanner`: **`$0.04` Signal / `$0.12` Full USDC** live 5-EVM RPC bytecode honeypot, blacklist, stealth mint & EIP-1167 proxy scan.
  * `GET | POST /api/v1/defi-math-guard`: **`$0.04` Signal / `$0.10` Full USDC** 48-step BigInt AMM MEV sandwich & liquidation bounds.
* **Native `GET` + `POST` + `/agents.md` + OpenAPI 3.1:** Full typed query parameters on `fast-ping`, `token-rug-scanner`, `tx-firewall`, and `defi-math-guard`, plus machine-readable [`AGENTS.md`](./AGENTS.md) and [`openapi.json`](./openapi.json).
* **`ingravity-mcp` STDIO Bridge & Remote HTTP MCP (`2025-06-18`):** Run `npx -y --package=ingravity-security ingravity-mcp` (or build the included `Dockerfile`) or connect directly to `/mcp`.
* **Automatic `X-Ingravity-Receipt-Token` Session Cache & Strict x402 v2 Sanitization:** Reuses Durable Object HMAC receipts without double-charging and strips legacy `maxAmountRequired` from `accepted`.
* **Zero Free Verdict Leaks + Anti-Bypass Seal:** Services 2–7 seal CRITICAL/HIGH remediation coordinates until proportional `+0.15%` SLA or `5%–10%` Safe-Harbor settlement.

---

## Quickstart: AgentCash / x402 v2 CLI

```bash
npx agentcash fetch "https://red-shape-1b3b.daviddelmoral79.workers.dev/api/v1/fast-ping?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&chainId=8453"
npx agentcash fetch "https://red-shape-1b3b.daviddelmoral79.workers.dev/api/v1/token-rug-scanner?tokenAddress=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&chainId=8453&tier=ESSENTIAL"
```

---

## 1. Installation & MCP Client Integration

```bash
npm install ingravity-security
```

Remote Streamable-HTTP MCP (`2025-06-18`):

```text
https://red-shape-1b3b.daviddelmoral79.workers.dev/mcp
```

STDIO Bridge via `ingravity-mcp`:

```json
{
  "mcpServers": {
    "ingravity-evm-security": {
      "command": "npx",
      "args": ["-y", "-p", "ingravity-security@1.3.0", "ingravity-mcp"]
    }
  }
}
```

---

## 2. Coinbase AgentKit Integration

```typescript
import { Agent } from "@coinbase/agentkit";
import { IngravitySecurityActionProvider } from "ingravity-security";

const agent = new Agent({ ...agentConfig });

agent.registerProvider(
  new IngravitySecurityActionProvider({
    walletProvider: agent.walletProvider, // Signs EIP-3009 USDC settlements automatically
    maxSpendUsdc: 0.12,                   // Auto-selects Signal / Fast-Ping / Token Full within budget
    enableReceiptCache: true              // Reuses X-Ingravity-Receipt-Token automatically
  })
);
```

---

## 3. ElizaOS (ai16z) Integration

```typescript
import { ingravityElizaPlugin } from "ingravity-security";

// Registers INGRAVITY_FAST_PING ($0.01), INGRAVITY_SCAN_TOKEN_SECURITY ($0.04/$0.12), INGRAVITY_TX_FIREWALL ($0.10)
runtime.registerPlugin(ingravityElizaPlugin);
```

---

## 4. Official x402 v2 Catalog (Swarm v3.13.0)

| Service | Endpoint & Methods | Full Report | Signal / Triage | Value / Safe-Harbor Policy |
| :--- | :--- | :--- | :--- | :--- |
| **Fast-Ping Binary Gate** | `GET \| POST /api/v1/fast-ping` | **`$0.01`** | **`$0.01`** | Flat boolean `SAFE / DANGER` (`<=$0.05` bots) |
| **Pre-Flight EVM Firewall** | `GET \| POST /api/v1/tx-firewall` | **`$0.10`** | **`$0.10`** | `+0.15%` Pre-Flight / `5%–10%` Rescue Bounty |
| **DeFi Math & MEV Guard** | `GET \| POST /api/v1/defi-math-guard` | **`$0.10`** | **`$0.04`** | `+0.15%` Protected Swap SLA |
| **Token Honeypot Scanner (`0x`)** | `GET \| POST /api/v1/token-rug-scanner` | **`$0.12`** | **`$0.04`** | `+0.15%` Position SLA / `5%–10%` Rescue |
| **Solidity 24-Vector Audit** | `POST /api/v1/audit-solidity` | **`$0.85`** | **`$0.35`** | `+0.15%` Live TVL / `5%–10%` Atomic Safe-Harbor |
| **Multi-Contract Protocol Dossier** | `POST /api/v1/protocol-dossier` | **`$12.00`** | **`$3.50`** | `+0.15%` Live TVL / `5%–10%` Atomic Safe-Harbor |
| **Deep Exploit & Rescue Simulation** | `POST /api/v1/deep-exploit-bounty` | **`$45.00`** | **`$9.50`** | `5%–10%` EIP-5792 / Sequential EOA Safe-Harbor Split |

* **Network:** Base Mainnet (`eip155:8453`) + Arbitrum, Optimism, Polygon, Ethereum RPC forensics
* **Settlement Asset:** Native USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)
* **Payee:** `0xAA99e12320a3db0116ef56D2e19F70f6796Bad0f`
* **Builder Code:** `bc_i26d7owr` (ERC-8021)
* **Machine Docs:** [`/agents.md`](https://red-shape-1b3b.daviddelmoral79.workers.dev/agents.md) · [`/openapi.json`](https://red-shape-1b3b.daviddelmoral79.workers.dev/openapi.json) · [`/.well-known/x402`](https://red-shape-1b3b.daviddelmoral79.workers.dev/.well-known/x402) · [`/mcp`](https://red-shape-1b3b.daviddelmoral79.workers.dev/mcp)

© 2026 Ingravity Security Swarm.
