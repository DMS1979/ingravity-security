---
name: ingravity-security
description: Pre-flight 5-EVM transaction firewall, ERC-20 honeypot & rugpull scanner, AMM MEV slippage math guard, 24-vector Solidity contract auditor, and Safe-Harbor rescue planner ($0.01-$45.00 USDC via gasless x402 v2 on Base Mainnet, plus <15ms Prepaid Credit Passes).
version: 1.3.6
homepage: https://red-shape-1b3b.daviddelmoral79.workers.dev
metadata:
  openclaw:
    requires:
      bins:
        - node
    primaryEnv: INGRAVITY_PRIVATE_KEY
---

# Ingravity Security Skill (`ingravity-security` v1.3.6)

Use this skill **before signing any blockchain transaction, buying any ERC-20 token, providing AMM liquidity, or deploying Solidity smart contracts** across **Base (`8453`)**, **Arbitrum (`42161`)**, **Optimism (`10`)**, **Polygon (`137`)**, or **Ethereum (`1`)**.

## 1-Command Terminal Usage (Zero Dependencies, Gasless Base USDC Auto-Pay)

Set `INGRAVITY_PRIVATE_KEY` (or `EVM_PRIVATE_KEY`) for a dedicated bot wallet holding Base Mainnet USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) — gas is 100% sponsored via EIP-3009 (`$0.00 ETH` gas):

```bash
# 1. Instant $0.01 USDC binary SAFE/DANGER gate on any token or spender address
npx -y ingravity-security@1.3.6 ping 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913

# 2. ERC-20 Honeypot & Bytecode/Transfer-Hook Scanner ($0.04 Signal / $0.12 Full)
npx -y ingravity-security@1.3.6 scan 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913

# 3. Pre-Sign EVM Transaction Calldata Firewall ($0.10 USDC)
npx -y ingravity-security@1.3.6 firewall 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 0x

# 4. Deterministic 24-Vector Solidity File Audit ($0.85 Full — 100% unsealed on pre-deploy drafts)
npx -y ingravity-security@1.3.6 audit ./Contract.sol

# 5. Mint a <15ms High-Frequency Prepaid M2M Credit Pass ($1, $5, or $25 USDC -> +15% bonus calls)
npx -y ingravity-security@1.3.6 pass 1
```

## MCP Server Configuration (Claude Code, Cursor, Windsurf, OpenClaw)

```json
{
  "mcpServers": {
    "ingravity-security": {
      "command": "npx",
      "args": ["-y", "-p", "ingravity-security@1.3.6", "ingravity-mcp"],
      "env": {
        "INGRAVITY_AGENT_BUDGET": "0.12",
        "INGRAVITY_PRIVATE_KEY": "0xYOUR_OPTIONAL_BOT_KEY"
      }
    }
  }
}
```
