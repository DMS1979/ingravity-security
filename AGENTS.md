# Ingravity Autonomous EVM Security & DeFi Guard v3.15.1 (`ingravity-security@1.3.6`)

Machine-to-machine (M2M) pre-swap honeypot detection, transaction firewall, AMM/MEV math guard, Solidity contract auditing, M2M Prepaid Credit Passes (`<15ms`), and Safe-Harbor rescue across 5 EVM chains (`Base 8453`, `Arbitrum 42161`, `Optimism 10`, `Polygon 137`, `Ethereum 1`).

## Cryptographic Provenance & Zero-Custody Verification
- Canonical Gateway: https://red-shape-1b3b.daviddelmoral79.workers.dev
- Open-Source SDK & Verifiable Manifests Repository: https://github.com/DMS1979/ingravity-security
- Official NPM Package: https://www.npmjs.com/package/ingravity-security (`ingravity-security@1.3.6`)
- Skill Manifest (OpenClaw / ClawHub): https://red-shape-1b3b.daviddelmoral79.workers.dev/skill.md
- On-Chain Agent Identity: ERC-8004 Agent #10252 on Base (https://www.8004scan.io/agents/base/10252)
- Base Mainnet Treasury (PayTo): 0xAA99e12320a3db0116ef56D2e19F70f6796Bad0f (https://basescan.org/address/0xAA99e12320a3db0116ef56D2e19F70f6796Bad0f#tokentxns)
- Settlement Asset: Base Mainnet USDC (0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)
- Base Builder Attribution Code: bc_i26d7owr
- Zero-Custody Guarantee: Every x402 payment or Safe-Harbor settlement uses strict USDC EIP-3009 `transferWithAuthorization` or ERC-20 `transfer(0xa9059cbb)`. Ingravity NEVER requests `ERC-20 approve()` to itself.

## Quickstart (1-Command CLI + Zero-Dependency SDK + MCP)
### Option 0: Instant 1-Command Terminal Auto-Pay (`$0.01 USDC`, `$0` ETH Gas)
```bash
INGRAVITY_PRIVATE_KEY=0x... npx -y ingravity-security@1.3.6 ping 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
INGRAVITY_PRIVATE_KEY=0x... npx -y ingravity-security@1.3.6 scan 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
INGRAVITY_PRIVATE_KEY=0x... npx -y ingravity-security@1.3.6 pass 1
```

### Option 1: Zero-Dependency Node.js Auto-Pay + `<15ms` Prepaid Pass (`ingravity-security@1.3.6`)
```js
const { IngravitySecurityActionProvider } = require("ingravity-security");
const guard = new IngravitySecurityActionProvider({ privateKey: process.env.INGRAVITY_PRIVATE_KEY, maxSpendUsdc: 1.00 });
const ping = await guard.fastPing({ address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", chainId: 8453 }); // $0.01 USDC
// Optional: mint a 90-day Prepaid M2M Pass (+15% bonus credit = 115 Fast-Pings per $1 USDC, <15ms latency)
await guard.topupPass({ usdAmount: 1 });
```
*(Also supports Viem `Account`/`WalletClient`, Ethers v5/v6 `Wallet`, and Coinbase AgentKit `walletProvider`.)*

### Option 2: MCP STDIO Server (with optional local EIP-3009 auto-pay or `INGRAVITY_PASS_TOKEN`)
```bash
INGRAVITY_PRIVATE_KEY=0x... INGRAVITY_AGENT_BUDGET=0.15 npx -y -p ingravity-security@1.3.6 ingravity-mcp
```

## Monetized Endpoints (x402 v2 on Base Mainnet `eip155:8453`)
- `GET | POST /api/v1/fast-ping` — **$0.01 USDC flat**: Instant binary token honeypot / address drainer safety gate (`SAFE`/`DANGER`, zero forensic leakage). Query: `?address=0x...&chainId=8453`.
- `GET | POST /api/v1/token-rug-scanner` — **$0.04 Signal / $0.12 Full USDC** (+0.15% Position SLA / 5%-10% Safe-Harbor): 5-EVM ERC-20 bytecode honeypot, blacklist, hidden mint & EIP-1167 proxy clone scanner. Query: `?tokenAddress=0x...&chainId=8453&tier=ESSENTIAL|FULL`.
- `GET | POST /api/v1/tx-firewall` — **$0.10 USDC** (+0.15% Pre-Flight / 5%-10% Safe-Harbor): Live `eth_call` + calldata drainer & EIP-1967/Permit2 inspection + unsigned `approve(spender, 0)` rescue calldata. Query: `?to=0x...&data=0x...&chainId=8453`.
- `GET | POST /api/v1/defi-math-guard` — **$0.04 Signal / $0.10 Full USDC** (+0.15% Swap / 5%-10% Safe-Harbor): 48-step BigInt AMM MEV sandwich & liquidation bounds.
- `POST /api/v1/audit-solidity` — **$0.35 Signal / $0.85 Full USDC** (+0.15% TVL / 5%-10% Safe-Harbor): 24-vector deterministic Solidity auditor (100% unsealed on `$0` live TVL pre-deploy drafts; Anti-Bypass Seal on live TVL rescues).
- `POST /api/v1/protocol-dossier` — **$3.50 Signal / $12.00 Full USDC** (+0.15% TVL / 5%-10% Safe-Harbor): Multi-contract protocol invariant & cross-reentrancy dossier.
- `POST /api/v1/deep-exploit-bounty` — **$9.50 Signal / $45.00 Full USDC** (5%-10% Safe-Harbor): Institutional pool liquidity & flash-loan resilience assessment + EIP-5792 Safe-Harbor rescue bundle.
- `GET | POST /api/v1/pass/topup` — **$1.00 / $5.00 / $25.00 USDC**: M2M Prepaid Security Credit Pass (+15% bonus credit, `<15ms` zero-facilitator latency via `X-Ingravity-Pass`).

## Agent Protocols & Safe-Harbor Terminal
- OpenAPI 3.1.0 Spec: https://red-shape-1b3b.daviddelmoral79.workers.dev/openapi.json
- x402 Discovery Manifest: https://red-shape-1b3b.daviddelmoral79.workers.dev/.well-known/x402
- MCP Streamable HTTP (2025-06-18): https://red-shape-1b3b.daviddelmoral79.workers.dev/mcp
- A2A Agent Card & JSON-RPC (v1.0 / v0.3.0): https://red-shape-1b3b.daviddelmoral79.workers.dev/.well-known/agent-card.json & https://red-shape-1b3b.daviddelmoral79.workers.dev/a2a
- 1-Click Safe-Harbor Rescue Terminal: https://red-shape-1b3b.daviddelmoral79.workers.dev/rescue?ticketId=TICKET-8453-...
- Budget Auto-Negotiation: send header `X-Agent-Budget: <usd>` or query `?budget=<usd>` to auto-select `ESSENTIAL` tier when eligible.
