# Ingravity Security MCP Server & Universal Web3 SDK (`ingravity-security`)

Self-contained, zero-dependency **Model Context Protocol (`MCP 2025-06-18`) STDIO Server (`mcp.js`)** and **Universal Web3 SDK (`index.js` — Viem, Ethers v5/v6, Coinbase AgentKit, ElizaOS & raw `privateKey`)** for 5-EVM pre-flight security, EVM calldata structural decoding, ERC-8021 Base Builder attribution, live RPC token honeypot scanning, BigInt DeFi MEV slippage math, and 24-vector Solidity auditing across **Base (`8453`)**, **Arbitrum (`42161`)**, **Optimism (`10`)**, **Polygon (`137`)**, and **Ethereum (`1`)**.

[![npm version](https://img.shields.io/badge/npm-1.3.6-blue.svg)](https://www.npmjs.com/package/ingravity-security)
[![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/dms1979/ingravity-security)
[![mcprush Grade A](https://mcprush.com/badge/ingravity-autonomous-evm-security-defi-guard-mcp/compact.svg)](https://mcprush.com/to/ingravity-autonomous-evm-security-defi-guard-mcp?ref=badge)
[![DMS1979/ingravity-security MCP server](https://glama.ai/mcp/servers/DMS1979/ingravity-security/badges/score.svg)](https://glama.ai/mcp/servers/DMS1979/ingravity-security)
[![MCP Spec](https://img.shields.io/badge/MCP-2025--06--18-6366F1.svg)](https://modelcontextprotocol.io)
[![Network](https://img.shields.io/badge/Network-Base%20Mainnet%20(8453)-0052FF.svg)](https://basescan.org)
[![Settlement](https://img.shields.io/badge/Settlement-x402%20v2%20USDC-10B981.svg)](https://www.x402.org)

---

## Architecture & Key Capabilities (`v1.3.5`)

This repository contains the complete, runnable **STDIO MCP Server (`mcp.js`)**, **Universal SDK (`index.js`)**, and minimal Node 22 Alpine `Dockerfile`:

* **Zero-Dependency Local EIP-3009 Auto-Signer:** Built-in Ethereum `keccak256` + `secp256k1` RFC 6979 signer lets MCP agents (`INGRAVITY_PRIVATE_KEY`) and Node.js bots (`{ privateKey }`) settle `$0.01–$0.12 USDC` x402 challenges gaslessly in `<2ms` with zero external packages and strict per-call budget caps (`INGRAVITY_AGENT_BUDGET`).
* **Universal Wallet Compatibility (`index.js`):** Works out-of-the-box with **Viem** (`privateKeyToAccount` & `WalletClient`), **Ethers v5 & v6** (`new ethers.Wallet(...)`), **Coinbase AgentKit** (`EvmWalletProvider`), **ElizaOS**, or a raw `{ privateKey }` hex string.
* **Full `@x402/mcp` Wire Protocol (`mcp.js`):** Emits `_meta["x402/error"]` on unpaid challenges, accepts `_meta["x402/payment"]` on retries, returns `_meta["x402/payment-response"]` on settlement, and accepts both `camelCase` and `snake_case` tool names.
* **Local Deterministic Web3 Tools (Zero Network Required):**
  * `ingravity_encodeErc8021Calldata` — Validates hexadecimal EVM calldata locally and idempotently appends the Base ERC-8021 attribution suffix (`bc_i26d7owr`).
  * `ingravity_decodeEvmCalldataSelector` — Structurally decodes standard 4-byte EVM selectors (`approve`, `transfer`, `transferFrom`, `setApprovalForAll`, `permit`, `Permit2`, `multicall`) and raw 32-byte ABI words locally.

---

## Quickstart (1-Command CLI, Zero-Dep Auto-Pay, `@x402/fetch`, MCP & Docker)

### Option 0: Instant 1-Command Terminal CLI (`$0.01 USDC` Gasless Base Auto-Pay)

```bash
# Instant $0.01 USDC SAFE/DANGER check (0 ETH gas — EIP-3009 sponsored on Base)
INGRAVITY_PRIVATE_KEY=0xYOUR_BOT_KEY npx -y ingravity-security@1.3.6 ping 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913

# Direct 0x Token Honeypot Scan ($0.04 Signal / $0.12 Full) or <15ms Prepaid Pass ($1 -> 115 pings)
INGRAVITY_PRIVATE_KEY=0xYOUR_BOT_KEY npx -y ingravity-security@1.3.6 scan 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
INGRAVITY_PRIVATE_KEY=0xYOUR_BOT_KEY npx -y ingravity-security@1.3.6 pass 1
```

### Option 1: Zero-Dependency 4-Line Node.js Auto-Pay (`ingravity-security`)

```js
const { IngravitySecurityActionProvider } = require("ingravity-security");
const guard = new IngravitySecurityActionProvider({ privateKey: process.env.INGRAVITY_PRIVATE_KEY, maxSpendUsdc: 0.05 });
const ping = await guard.fastPing({ address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", chainId: 8453 }); // $0.01 USDC
console.log(ping.verdict, ping.action); // "SAFE" "PROCEED"
```

*(Also accepts `walletProvider: viemAccount | viemWalletClient | ethersWallet | agentKitWalletProvider`!)*

### Option 2: 5-Line `@x402/fetch` Auto-Pay on Base (`eip155:8453`)

```js
import { wrapFetchWithPayment, x402Client } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
const client = new x402Client();
registerExactEvmScheme(client, { signer: privateKeyToAccount(process.env.EVM_PRIVATE_KEY) });
const res = await wrapFetchWithPayment(fetch, client)("https://red-shape-1b3b.daviddelmoral79.workers.dev/api/v1/fast-ping?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&chainId=8453");
```

*(Or via CLI: `npx agentcash fetch "https://red-shape-1b3b.daviddelmoral79.workers.dev/api/v1/fast-ping?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&chainId=8453"`.)*

### Option 3: Claude Desktop / Cursor / Windsurf (`npx` with optional local Auto-Pay)

Add to `claude_desktop_config.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "ingravity-security": {
      "command": "npx",
      "args": ["-y", "-p", "ingravity-security@1.3.6", "ingravity-mcp"],
      "env": {
        "INGRAVITY_AGENT_BUDGET": "0.10",
        "INGRAVITY_PRIVATE_KEY": "0xYOUR_OPTIONAL_DEDICATED_BOT_KEY"
      }
    }
  }
}
```

*(If `INGRAVITY_PRIVATE_KEY` is omitted, the 2 local calldata tools run offline for free and the 7 API tools return standard x402 v2 payment quotes in `_meta["x402/error"]` for `@x402/mcp` clients.)*

### Option 4: Docker

```bash
docker build -t ingravity-security-mcp .
docker run -i --rm ingravity-security-mcp
```

### Optional Environment Variables (`mcp.js`)

| Variable | Description |
| :--- | :--- |
| `INGRAVITY_PRIVATE_KEY` | Optional local EVM private key (`0x...`) for automatic gasless EIP-3009 signing up to `INGRAVITY_AGENT_BUDGET` (never leaves your machine). |
| `INGRAVITY_AGENT_BUDGET` | Maximum USDC spend cap per call (`X-Agent-Budget`, default `0.12` when auto-signing). |
| `INGRAVITY_API_URL` | Override the default Ingravity REST API v1 base URL. |
| `INGRAVITY_PAYMENT_SIGNATURE` | Pre-signed Base64 EIP-3009 x402 v2 `PAYMENT-SIGNATURE` authorization. |
| `INGRAVITY_TX_HASH` | Optional settled Base USDC transfer hash (`X-TX-HASH`). |
| `INGRAVITY_RECEIPT_TOKEN` | Optional reusable session receipt token (`X-Ingravity-Receipt-Token`). |

---

## MCP Tools Catalog (9 Tools)

### Local Deterministic Utilities (No Network Required — $0.00)

| Tool Name | Execution | Description |
| :--- | :--- | :--- |
| `ingravity_encodeErc8021Calldata` | **Local** | Validates EVM hex calldata and idempotently appends Base ERC-8021 suffix (`bc_i26d7owr`). |
| `ingravity_decodeEvmCalldataSelector` | **Local** | Structurally decodes 4-byte EVM selectors and 32-byte ABI arguments (no risk verdict). |

### x402 v2 Security Verification Tools (Base Mainnet USDC)

| Tool Name (`snake_case` alias supported) | API Route | Full Tier | Essential Tier | Capabilities |
| :--- | :--- | :--- | :--- | :--- |
| `ingravity_fastPingAddressSafety` (`ingravity_fast_ping`) | `GET /api/v1/fast-ping` | **`$0.01`** | **`$0.01`** | Binary `SAFE / DANGER` gate across 5 EVM chains (`<= $0.05` bots). |
| `ingravity_inspectEvmTransactionFirewall` (`ingravity_tx_firewall`) | `POST /api/v1/tx-firewall` | **`$0.10`** | **`$0.10`** | Pre-sign calldata simulation, EIP-1967/1167 proxy check & revocation bundle. |
| `ingravity_scanTokenRugpullAndHoneypot` (`ingravity_token_rug_scanner`) | `POST /api/v1/token-rug-scanner` | **`$0.12`** | **`$0.04`** | Live 5-EVM RPC ERC-20 bytecode disassembly & honeypot detection. |
| `ingravity_computeDefiSlippageAndLiquidation` (`ingravity_defi_math_guard`) | `POST /api/v1/defi-math-guard` | **`$0.10`** | **`$0.04`** | 48-step exact BigInt AMM slippage, MEV sandwich & perp liquidation math. |
| `ingravity_auditSolidityContract` (`ingravity_audit_solidity`) | `POST /api/v1/audit-solidity` | **`$0.85`** | **`$0.35`** | Deterministic 24-vector Solidity static audit with 4-gate anti-noise filter. |
| `ingravity_generateMultiContractProtocolDossier` (`ingravity_protocol_dossier`) | `POST /api/v1/protocol-dossier` | **`$12.00`** | **`$3.50`** | Multi-contract (1–20 files) cross-reentrancy & ERC-4626/oracle invariants. |
| `ingravity_simulateDeepExploitAndWhitehatBounty` (`ingravity_deep_exploit_bounty`) | `POST /api/v1/deep-exploit-bounty` | **`$45.00`** | **`$9.50`** | Flash-loan exploit simulation, live TVL check & unsigned Safe-Harbor plan. |

---

## 10-Line Base Pre-Swap Guard (Aerodrome & Uniswap Trading Bots)

Block honeypots, hidden tax traps, and malicious approvals **before signing** on Base (`8453`) for `$0.01–$0.04 USDC` using Viem, Ethers, AgentKit, or `{ privateKey }`:

```javascript
const { IngravitySecurityActionProvider } = require("ingravity-security");

async function safeSwapOnBase(signerOrKey, tokenOut, router, swapCalldata) {
  const guard = new IngravitySecurityActionProvider(
    typeof signerOrKey === "string" ? { privateKey: signerOrKey, maxSpendUsdc: 0.05 } : { walletProvider: signerOrKey, maxSpendUsdc: 0.05 }
  );
  const ping = await guard.fastPing({ address: tokenOut, chainId: 8453 }); // $0.01 USDC
  if (ping.action === "ABORT" || ping.verdict === "DANGER") throw new Error("Blocked drainer/honeypot");
  const scan = await guard.tokenRugScanner({ tokenAddress: tokenOut, chainId: 8453, tier: "ESSENTIAL" }); // $0.04
  if (scan.action === "ABORT" || /HIGH_RUG_RISK|CRITICAL_HONEYPOT/.test(scan.verdict)) {
    throw new Error(`Swap aborted: ${scan.verdict}`);
  }
  return { safeToBroadcast: true, router, swapCalldata }; // Aerodrome 0xcF77...4E43 / Uniswap 0x2626...e481
}
```

See [examples/base_preswap_aerodrome_uniswap.js](examples/base_preswap_aerodrome_uniswap.js) for a runnable template with optional `txFirewall` calldata verification (`$0.10 USDC`).

---

## Security & Verification

```bash
npm test
```

* **Zero Custody:** Never holds private keys on remote servers or requests ERC-20 `approve()`.
* **Base Builder Code:** `bc_i26d7owr` (ERC-8021).
* **License:** MIT
