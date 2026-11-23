# Ingravity Security MCP Server (`ingravity-security`)

Self-contained, zero-dependency **Model Context Protocol (`MCP 2025-06-18`) STDIO Server** implemented in Node.js (`mcp.js`) for 5-EVM Web3 pre-flight security, EVM calldata structural decoding, ERC-8021 Base Builder attribution, live RPC token honeypot scanning, BigInt DeFi MEV slippage math, and 24-vector Solidity auditing across **Base (`8453`)**, **Arbitrum (`42161`)**, **Optimism (`10`)**, **Polygon (`137`)**, and **Ethereum (`1`)**.

[![npm version](https://img.shields.io/badge/npm-1.3.4-blue.svg)](https://www.npmjs.com/package/ingravity-security)
[![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/dms1979/ingravity-security)
[![Ingravity Autonomous EVM Security & DeFi Guard (x402 v2) MCP server](https://mcprush.com/badge/ingravity-autonomous-evm-security-defi-guard-mcp/card.svg)](https://mcprush.com/to/ingravity-autonomous-evm-security-defi-guard-mcp?ref=badge)
[![Glama MCP Server](https://glama.ai/mcp/servers/DMS1979/ingravity-security/badges/score.svg)](https://glama.ai/mcp/servers/DMS1979/ingravity-security)
[![MCP Spec](https://img.shields.io/badge/MCP-2025--06--18-6366F1.svg)](https://modelcontextprotocol.io)
[![Network](https://img.shields.io/badge/Network-Base%20Mainnet%20(8453)-0052FF.svg)](https://basescan.org)
[![Settlement](https://img.shields.io/badge/Settlement-x402%20v2%20USDC-10B981.svg)](https://www.x402.org)

---

## Architecture & Implementation

This repository contains the complete, runnable **STDIO MCP Server (`mcp.js`)** packaged with a minimal Node 22 Alpine `Dockerfile`:

* **Local MCP `2025-06-18` Protocol Engine (`mcp.js`):** Natively implements `initialize`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, and `prompts/get` over JSON-RPC 2.0 STDIO with zero external runtime dependencies.
* **Local Deterministic Web3 Tools (Zero Network Required):**
  * `ingravity_encodeErc8021Calldata` — Validates hexadecimal EVM calldata locally and idempotently appends the Base ERC-8021 attribution suffix (`bc_i26d7owr`).
  * `ingravity_decodeEvmCalldataSelector` — Structurally decodes standard 4-byte EVM selectors (`approve`, `transfer`, `transferFrom`, `setApprovalForAll`, `permit`, `Permit2`, `multicall`) and raw 32-byte ABI words locally.
* **Local Input Validation & Session Receipt Caching:** Strictly validates EVM addresses, chain IDs, and required schemas locally (`-32602` JSON-RPC errors) and caches HMAC session receipts (`X-Ingravity-Receipt-Token`) to prevent duplicate spend.
* **Ingravity x402 v2 REST API Integrations (`/api/v1/*`):** Dispatches paid security analysis calls to the Ingravity verification backend settling per-call in Native Base USDC (`eip155:8453`) with zero API keys or subscriptions.

---

## Quickstart (5-Line x402 Auto-Pay, MCP & Docker)

### Option 1: 5-Line Autonomous Bot Pre-Swap Gate (`@x402/fetch` on Base `eip155:8453`)

```js
import { wrapFetchWithPayment, x402Client } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
const client = new x402Client();
registerExactEvmScheme(client, { signer: privateKeyToAccount(process.env.EVM_PRIVATE_KEY) });
const res = await wrapFetchWithPayment(fetch, client)("https://red-shape-1b3b.daviddelmoral79.workers.dev/api/v1/fast-ping?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&chainId=8453");
```

*(Need `npm i @x402/fetch @x402/evm viem`, or use CLI `npx agentcash fetch "https://red-shape-1b3b.daviddelmoral79.workers.dev/api/v1/fast-ping?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&chainId=8453"`.)*

### Option 2: Claude Desktop / Cursor / Windsurf (`npx`)

Add this entry to your MCP client configuration (`claude_desktop_config.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "ingravity-security": {
      "command": "npx",
      "args": ["-y", "-p", "ingravity-security@1.3.4", "ingravity-mcp"],
      "env": {
        "INGRAVITY_AGENT_BUDGET": "0.10"
      }
    }
  }
}
```

### Option 3: Docker

```bash
docker build -t ingravity-security-mcp .
docker run -i --rm ingravity-security-mcp
```

### Optional Environment Variables

| Variable | Description |
| :--- | :--- |
| `INGRAVITY_API_URL` | Override the default Ingravity REST API v1 base URL. |
| `INGRAVITY_AGENT_BUDGET` | Optional maximum USDC spend cap per call (`X-Agent-Budget`). |
| `INGRAVITY_PAYMENT_SIGNATURE` | Base64 EIP-3009 x402 v2 `PAYMENT-SIGNATURE` authorization. |
| `INGRAVITY_TX_HASH` | Optional settled Base USDC transfer hash (`X-TX-HASH`). |
| `INGRAVITY_RECEIPT_TOKEN` | Optional reusable session receipt token (`X-Ingravity-Receipt-Token`). |

---

## MCP Tools Catalog (9 Tools)

### Local Deterministic Utilities (No Network Required)

| Tool Name | Execution | Description |
| :--- | :--- | :--- |
| `ingravity_encodeErc8021Calldata` | **Local** | Validates EVM hex calldata and idempotently appends Base ERC-8021 suffix (`bc_i26d7owr`). |
| `ingravity_decodeEvmCalldataSelector` | **Local** | Structurally decodes 4-byte EVM selectors and 32-byte ABI arguments (no risk verdict). |

### x402 v2 Security Verification Tools (Base Mainnet USDC)

| Tool Name | API Route | Full Tier | Essential Tier | Capabilities |
| :--- | :--- | :--- | :--- | :--- |
| `ingravity_fastPingAddressSafety` | `GET /api/v1/fast-ping` | **`$0.01`** | **`$0.01`** | Binary `SAFE / DANGER` gate across 5 EVM chains (`<= $0.05` bots). |
| `ingravity_inspectEvmTransactionFirewall` | `POST /api/v1/tx-firewall` | **`$0.10`** | **`$0.10`** | Pre-sign calldata simulation, EIP-1967/1167 proxy check & revocation bundle. |
| `ingravity_scanTokenRugpullAndHoneypot` | `POST /api/v1/token-rug-scanner` | **`$0.12`** | **`$0.04`** | Live 5-EVM RPC ERC-20 bytecode disassembly & honeypot detection. |
| `ingravity_computeDefiSlippageAndLiquidation` | `POST /api/v1/defi-math-guard` | **`$0.10`** | **`$0.04`** | 48-step exact BigInt AMM slippage, MEV sandwich & perp liquidation math. |
| `ingravity_auditSolidityContract` | `POST /api/v1/audit-solidity` | **`$0.85`** | **`$0.35`** | Deterministic 24-vector Solidity static audit with 4-gate anti-noise filter. |
| `ingravity_generateMultiContractProtocolDossier` | `POST /api/v1/protocol-dossier` | **`$12.00`** | **`$3.50`** | Multi-contract (1–20 files) cross-reentrancy & ERC-4626/oracle invariants. |
| `ingravity_simulateDeepExploitAndWhitehatBounty` | `POST /api/v1/deep-exploit-bounty` | **`$45.00`** | **`$9.50`** | Flash-loan exploit simulation, live TVL check & unsigned Safe-Harbor plan. |

---

## MCP Resources & Prompts

* **Resources:**
  * `ingravity://docs/supported-chains` — Canonical 5-EVM chain IDs and Base USDC settlement contract.
  * `ingravity://docs/x402-settlement` — Zero-custody EIP-3009 x402 v2 settlement guide.
* **Prompts:**
  * `pre_sign_transaction_check` — Structured workflow to decode and inspect EVM calldata before signing.
  * `pre_swap_token_check` — Two-step honeypot and AMM slippage checklist before swapping ERC-20 tokens.

---

## Programmatic Library Usage (Coinbase AgentKit & ElizaOS)

In addition to the standalone MCP server (`mcp.js`), the package exports `IngravitySecurityActionProvider`, `ingravityElizaPlugin`, and `encodeErc8021Calldata` from `index.js`:

```bash
npm install ingravity-security
```

```typescript
import { IngravitySecurityActionProvider } from "ingravity-security";

const provider = new IngravitySecurityActionProvider({
  walletProvider: evmWalletProvider,
  maxSpendUsdc: 0.10,
  enableReceiptCache: true
});
```

---

## Security & Verification

```bash
npm test
```

* **Zero Custody:** Never holds private keys or requests ERC-20 `approve()`.
* **Base Builder Code:** `bc_i26d7owr` (ERC-8021).
* **License:** MIT
