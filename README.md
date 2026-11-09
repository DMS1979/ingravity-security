# ingravity-security (v1.2.0)

> Autonomous Web3 Pre-Flight Security, `$0.03` Binary Fast-Ping, Direct `0x` Token Honeypot Scanner, Atomic EIP-5792 Safe-Harbor Rescue Provider & STDIO MCP Bridge for **Coinbase AgentKit**, **ElizaOS**, **LangChain**, **Claude Desktop**, and **Cursor** on Base Mainnet (`eip155:8453`).

Settles programmatically per-call in native USDC via **x402 v2** with zero subscriptions or API keys.

[![npm version](https://img.shields.io/badge/npm-1.2.0-blue.svg)](https://www.npmjs.com/package/ingravity-security)
[![Network](https://img.shields.io/badge/Network-Base%20Mainnet%20(8453)-0052FF.svg)](https://basescan.org)
[![Settlement](https://img.shields.io/badge/Settlement-x402%20v2%20USDC-10B981.svg)](https://red-shape-1b3b.daviddelmoral79.workers.dev/.well-known/x402)

---

## What's New in v1.2.0

* **`ingravity-mcp` STDIO Bridge**: Run `npx -y ingravity-security` (or `ingravity-mcp`) directly inside Claude Desktop, Cursor, Windsurf, or Cline — zero-config JSON-RPC 2.0 bridge to our Streamable-HTTP MCP server.
* **Automatic `X-Ingravity-Receipt-Token` Session Cache**: Repeat queries for the same `(route, target)` reuse HMAC-SHA256 receipt tokens returned by Cloudflare Durable Objects without re-signing or double-spending USDC.
* **Strict x402 v2 PayAI Sanitization**: Strips legacy `maxAmountRequired` from `paymentPayload.accepted` objects during EIP-3009 signing for 100% compatibility with Coinbase CDP, PayAI, and Primer facilitators.
* **ERC-8021 Base Builder Attribution Helper (`encodeErc8021Calldata`)**: Built-in idempotent calldata attribution helper tagging on-chain rescue/revoke bundles with Base Builder Code `bc_i26d7owr`.
* **EIP-5792 `wallet_sendCalls` & Sequential EOA Safe-Harbor Bundles**: B2B audit engines (`auditSolidity`, `protocolDossier`, `deepExploitBounty`) generate standard EIP-5792 / sequential EOA rescue steps (`90%–95%` to protocol treasury, `5%–10%` whitehat bounty).
* **ZK-EC Blind Wallet Self-Audit (`walletBlindAudit`)**: Check whether a Base address has an active unrevoked drainer exposure while keeping spender coordinates sealed until x402 settlement.
* **Zero Free Verdict Leaks**: 100% deterministic x402 v2 settlement across all 7 engines.

---

## Installation

```bash
npm install ingravity-security
```

---

## 1. MCP Client Integration (Claude Desktop / Cursor / Windsurf)

Remote Streamable-HTTP (Zero Install):

```text
https://red-shape-1b3b.daviddelmoral79.workers.dev/mcp
```

Or local STDIO bridge via `ingravity-mcp`:

```json
{
  "mcpServers": {
    "ingravity-evm-security": {
      "command": "npx",
      "args": ["-y", "-p", "ingravity-security@1.2.0", "ingravity-mcp"]
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
    maxSpendUsdc: 0.25,                   // Auto-selects Signal Only / Fast-Ping within budget
    enableReceiptCache: true              // Reuses X-Ingravity-Receipt-Token automatically
  })
);
```

---

## 3. ElizaOS (ai16z) Integration

```typescript
import { ingravityElizaPlugin } from "ingravity-security";

// Registers INGRAVITY_FAST_PING, INGRAVITY_SCAN_TOKEN_SECURITY, and INGRAVITY_TX_FIREWALL
runtime.registerPlugin(ingravityElizaPlugin);
```

---

## 4. Standalone M2M Usage

```javascript
const { IngravitySecurityActionProvider, encodeErc8021Calldata } = require("ingravity-security");

const provider = new IngravitySecurityActionProvider({
  walletProvider: evmWalletProvider
});

// A) $0.03 Fast-Ping for micro-budget bots:
const ping = await provider.fastPing({ address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" });

// B) Direct Base token honeypot scan by 0x address (no .sol needed):
const tokenAudit = await provider.tokenRugScanner({
  tokenAddress: "0x532f27101965dd16442e59d40670faf5ebb142e4",
  chainId: 8453
});

// C) Append Base Builder Code (bc_i26d7owr) ERC-8021 suffix to calldata:
const attributed = encodeErc8021Calldata("0x095ea7b3...");
```

---

## Official x402 v2 Catalog (Swarm v3.10.0)

| Service | Endpoint | Base Full Floor | Signal / Triage | Value / Safe-Harbor Option |
| :--- | :--- | :--- | :--- | :--- |
| **Fast-Ping Binary Gate** | `/api/v1/fast-ping` | **`$0.03`** | **`$0.03`** | Flat boolean `SAFE / DANGER` (`<= $0.05` bots) |
| **Pre-Flight EVM Firewall** | `/api/v1/tx-firewall` | **`$0.10`** | **`$0.10`** | `+0.15%` Pre-Flight / `5%–10%` Rescue Bounty |
| **DeFi Math & MEV Guard** | `/api/v1/defi-math-guard` | **`$0.15`** | **`$0.10`** | `+0.15%` Protected Swap SLA |
| **Token Honeypot Scanner (`0x`)** | `/api/v1/token-rug-scanner` | **`$0.50`** | **`$0.25`** | `+0.15%` Position SLA |
| **Solidity 24-Vector Audit** | `/api/v1/audit-solidity` | **`$0.85`** | **`$0.35`** | `+0.15%` Live TVL / `5%–10%` Atomic Safe-Harbor |
| **Multi-Contract Protocol Dossier** | `/api/v1/protocol-dossier` | **`$12.00`** | **`$3.50`** | `+0.15%` Live TVL / `5%–10%` Atomic Safe-Harbor |
| **Deep Exploit & Rescue Simulation** | `/api/v1/deep-exploit-bounty` | **`$45.00`** | **`$9.50`** | `5%–10%` EIP-5792 / Sequential EOA Safe-Harbor Split |

* **Network**: Base Mainnet (`eip155:8453`)
* **Settlement Asset**: Native USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)
* **Payee**: `0xAA99e12320a3db0116ef56D2e19F70f6796Bad0f`
* **Builder Code**: `bc_i26d7owr` (ERC-8021)
* **MCP Endpoint**: `https://red-shape-1b3b.daviddelmoral79.workers.dev/mcp`

© 2026 Ingravity Security Swarm.
