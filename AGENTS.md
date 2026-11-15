# Ingravity Autonomous EVM Security & DeFi Guard v3.13.0

Machine-to-machine (M2M) pre-swap honeypot detection, transaction firewall, AMM/MEV math guard, Solidity contract auditing, and Safe-Harbor rescue across 5 EVM chains (`Base 8453`, `Arbitrum 42161`, `Optimism 10`, `Polygon 137`, `Ethereum 1`).

## Cryptographic Provenance & Zero-Custody Verification
- Canonical Gateway: https://red-shape-1b3b.daviddelmoral79.workers.dev
- Open-Source Repository: https://github.com/DMS1979/ingravity-security
- On-Chain Agent Identity: ERC-8004 Agent #10252 on Base (https://www.8004scan.io/agents/base/10252)
- Base Mainnet Treasury (PayTo): 0xAA99e12320a3db0116ef56D2e19F70f6796Bad0f (https://basescan.org/address/0xAA99e12320a3db0116ef56D2e19F70f6796Bad0f#tokentxns)
- Settlement Asset: Base Mainnet USDC (0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)
- Base Builder Attribution Code: bc_i26d7owr
- Zero-Custody Guarantee: Every x402 payment or Safe-Harbor settlement uses strict USDC EIP-3009 `transferWithAuthorization` or ERC-20 `transfer(0xa9059cbb)`. Ingravity NEVER requests `ERC-20 approve()` to itself.

## Quickstart (GET & POST — Compatible with AgentCash, x402 v2 & curl)
### Option 1: HTTP GET (One-line AgentCash / Trading Bot Pre-Swap Check)
```bash
npx agentcash fetch "https://red-shape-1b3b.daviddelmoral79.workers.dev/api/v1/fast-ping?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&chainId=8453"
npx agentcash fetch "https://red-shape-1b3b.daviddelmoral79.workers.dev/api/v1/token-rug-scanner?tokenAddress=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&chainId=8453&tier=ESSENTIAL"
```
### Option 2: HTTP POST JSON (Full Forensics / Firewall / Solidity / Rescue)
```bash
curl -X POST "https://red-shape-1b3b.daviddelmoral79.workers.dev/api/v1/tx-firewall" -H "Content-Type: application/json" -d '{"to":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","data":"0x","chainId":8453}'
```

## Monetized Endpoints (x402 v2 on Base Mainnet `eip155:8453`)
- `GET | POST /api/v1/fast-ping` — **$0.01 USDC flat**: Instant binary token honeypot / address drainer safety gate (`SAFE`/`DANGER`, zero forensic leakage). Query: `?address=0x...&chainId=8453`.
- `GET | POST /api/v1/token-rug-scanner` — **$0.04 Signal / $0.12 Full USDC** (+0.15% Position SLA / 5%-10% Safe-Harbor): 5-EVM ERC-20 bytecode honeypot, blacklist, hidden mint & EIP-1167 proxy clone scanner. Query: `?tokenAddress=0x...&chainId=8453&tier=ESSENTIAL|FULL`.
- `GET | POST /api/v1/tx-firewall` — **$0.10 USDC** (+0.15% Pre-Flight / 5%-10% Safe-Harbor): Calldata drainer & EIP-1967/Permit2 inspection + unsigned `approve(spender, 0)` rescue calldata. Query: `?to=0x...&data=0x...&chainId=8453`.
- `GET | POST /api/v1/defi-math-guard` — **$0.04 Signal / $0.10 Full USDC** (+0.15% Swap / 5%-10% Safe-Harbor): 48-step BigInt AMM MEV sandwich & liquidation bounds.
- `POST /api/v1/audit-solidity` — **$0.35 Signal / $0.85 Full USDC** (+0.15% TVL / 5%-10% Safe-Harbor): 24-vector deterministic Solidity auditor with Anti-Bypass Seal on CRITICAL/HIGH patches.
- `POST /api/v1/protocol-dossier` — **$3.50 Signal / $12.00 Full USDC** (+0.15% TVL / 5%-10% Safe-Harbor): Multi-contract protocol invariant & cross-reentrancy dossier.
- `POST /api/v1/deep-exploit-bounty` — **$9.50 Signal / $45.00 Full USDC** (5%-10% Safe-Harbor): Flash-loan exploit PoC & Whitehat Safe-Harbor rescue bundle.

## Agent Protocols & Safe-Harbor Terminal
- OpenAPI 3.1.0 Spec: https://red-shape-1b3b.daviddelmoral79.workers.dev/openapi.json
- x402 Discovery Manifest: https://red-shape-1b3b.daviddelmoral79.workers.dev/.well-known/x402
- MCP Streamable HTTP (2025-06-18): https://red-shape-1b3b.daviddelmoral79.workers.dev/mcp
- A2A AgentCard & JSON-RPC (v1.0 / v0.3.0): https://red-shape-1b3b.daviddelmoral79.workers.dev/.well-known/agent-card.json & https://red-shape-1b3b.daviddelmoral79.workers.dev/a2a
- 1-Click Safe-Harbor Rescue Terminal: https://red-shape-1b3b.daviddelmoral79.workers.dev/rescue?ticketId=TICKET-8453-...
- Budget Auto-Negotiation: send header `X-Agent-Budget: <usd>` or query `?budget=<usd>` to auto-select `ESSENTIAL` tier when eligible.
