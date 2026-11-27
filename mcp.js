#!/usr/bin/env node
/**
 * Ingravity Security MCP Server (v1.3.5 — Model Context Protocol 2025-06-18 + x402 v2 MCP Transport)
 * ----------------------------------------------------------------------------
 * Self-contained, zero-dependency Node.js STDIO MCP Server implementation.
 *
 * Implements the full MCP 2025-06-18 JSON-RPC 2.0 server lifecycle locally:
 *   - Protocol handshake & introspection: initialize, ping, tools/list,
 *     resources/list, resources/read, prompts/list, prompts/get.
 *   - Pure-local deterministic EVM utilities: ERC-8021 calldata attribution
 *     encoding and structural 4-byte EVM calldata ABI selector decoding.
 *   - Zero-custody local EIP-3009 auto-signing when INGRAVITY_PRIVATE_KEY is
 *     supplied in env/options (strictly capped by INGRAVITY_AGENT_BUDGET),
 *     plus full @x402/mcp _meta['x402/error'] & _meta['x402/payment'] support.
 */

const crypto = require("crypto");
const https = require("https");
const http = require("http");
const readline = require("readline");
const {
  IngravitySecurityActionProvider,
  encodeErc8021Calldata,
  sanitizeX402V2Accept,
  createEip3009PrivateKeySigner,
  BASE_USDC_CONTRACT,
  BASE_CHAIN_ID,
  ERC8021_BUILDER_CODE,
  ERC8021_SUFFIX_HEX
} = require("./index.js");

const SERVER_NAME = "ingravity-security";
const SERVER_VERSION = "1.3.6";
const DEFAULT_API_URL = (
  process.env.INGRAVITY_API_URL ||
  process.env.INGRAVITY_WORKER_URL ||
  "https://red-shape-1b3b.daviddelmoral79.workers.dev"
).replace(/\/$/, "");
const MCP_ENDPOINT_URL = (process.env.INGRAVITY_MCP_URL || `${DEFAULT_API_URL}/mcp`).trim();
const SUPPORTED_CHAINS = [8453, 42161, 10, 137, 1];
const EVM_ADDR_RE = /^0x[a-fA-F0-9]{40}$/;
const HEX_DATA_RE = /^0x[a-fA-F0-9]*$/;

const TOOL_ALIASES = {
  ingravity_fast_ping: "ingravity_fastPingAddressSafety",
  ingravity_tx_firewall: "ingravity_inspectEvmTransactionFirewall",
  ingravity_token_rug_scanner: "ingravity_scanTokenRugpullAndHoneypot",
  ingravity_defi_math_guard: "ingravity_computeDefiSlippageAndLiquidation",
  ingravity_audit_solidity: "ingravity_auditSolidityContract",
  ingravity_protocol_dossier: "ingravity_generateMultiContractProtocolDossier",
  ingravity_deep_exploit_bounty: "ingravity_simulateDeepExploitAndWhitehatBounty"
};

const KNOWN_EVM_SELECTORS = {
  "0x095ea7b3": { signature: "approve(address,uint256)", standard: "ERC-20", params: ["spender", "amount"] },
  "0xa9059cbb": { signature: "transfer(address,uint256)", standard: "ERC-20", params: ["to", "amount"] },
  "0x23b872dd": { signature: "transferFrom(address,address,uint256)", standard: "ERC-20", params: ["from", "to", "amount"] },
  "0xa22cb465": { signature: "setApprovalForAll(address,bool)", standard: "ERC-721 / ERC-1155", params: ["operator", "approved"] },
  "0xd505accf": { signature: "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", standard: "EIP-2612", params: ["owner", "spender", "value", "deadline"] },
  "0x2b67b570": { signature: "permit(address,PermitSingle,bytes)", standard: "Uniswap Permit2", params: ["owner", "permitSingle"] },
  "0x39509351": { signature: "increaseAllowance(address,uint256)", standard: "ERC-20", params: ["spender", "addedValue"] },
  "0xac9650d8": { signature: "multicall(bytes[])", standard: "Multicall", params: ["data"] }
};

const sessionReceiptCache = new Map();

const MCP_TOOLS = [
  {
    name: "ingravity_encodeErc8021Calldata",
    title: "ERC-8021 Base Builder Calldata Encoder (Local)",
    description: "Validates hexadecimal EVM calldata locally and idempotently appends the ERC-8021 Base Builder attribution suffix (bc_i26d7owr). Pure local deterministic execution with zero network calls.",
    inputSchema: {
      type: "object",
      properties: {
        calldata: { type: "string", description: "Hexadecimal EVM calldata starting with 0x (e.g., '0x095ea7b3...')." }
      },
      required: ["calldata"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "ingravity_decodeEvmCalldataSelector",
    title: "Structural EVM Calldata Selector Decoder (Local)",
    description: "Structurally parses EVM hexadecimal calldata locally to identify standard 4-byte selectors (ERC-20 approve/transfer/transferFrom, ERC-721 setApprovalForAll, EIP-2612 permit, Permit2, multicall) and extract raw 32-byte ABI words. Pure structural decoding — use ingravity_inspectEvmTransactionFirewall for live risk verdicts and proxy forensics.",
    inputSchema: {
      type: "object",
      properties: {
        data: { type: "string", description: "Hexadecimal EVM calldata string (0x...)." }
      },
      required: ["data"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "ingravity_fastPingAddressSafety",
    title: "Fast EVM Address Safety Ping ($0.01 USDC)",
    description: "Queries the Ingravity x402 v2 API (/api/v1/fast-ping) for an instant binary SAFE/DANGER address & honeypot gate across 5 EVM chains ($0.01 USDC flat on Base Mainnet, zero API keys). Strictly read-only.",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string", description: "42-character EVM contract, token, or spender address (0x...)." },
        chainId: { type: "integer", enum: SUPPORTED_CHAINS, default: 8453, description: "Target EVM chain ID (8453 Base default, 42161 Arbitrum, 10 Optimism, 137 Polygon, 1 Ethereum)." }
      },
      required: ["address"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  },
  {
    name: "ingravity_inspectEvmTransactionFirewall",
    title: "Pre-Flight EVM Transaction Firewall ($0.10 USDC)",
    description: "Submits transaction calldata to /api/v1/tx-firewall ($0.10 USDC on Base via x402 v2) for live 5-EVM RPC bytecode & EIP-1967/1167 proxy inspection, drainer interception, and unsigned EIP-5792 revocation bundles.",
    inputSchema: {
      type: "object",
      properties: {
        to: { type: "string", description: "Target contract, token, or recipient address (0x...)." },
        data: { type: "string", default: "0x", description: "Hexadecimal transaction calldata (0x...)." },
        from: { type: "string", description: "Optional signer wallet address (0x...)." },
        value: { type: "string", default: "0", description: "Optional native wei value as decimal string." },
        chainId: { type: "integer", enum: SUPPORTED_CHAINS, default: 8453 },
        ticketId: { type: "string", description: "Optional ZK-EC exposure ticket ID." },
        capitalAtRiskUsd: { type: "number", description: "Optional protected capital value in USD." }
      },
      required: ["to"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  },
  {
    name: "ingravity_scanTokenRugpullAndHoneypot",
    title: "ERC-20 Token Rugpull & Honeypot Scanner ($0.04-$0.12)",
    description: "Calls /api/v1/token-rug-scanner ($0.12 Full / $0.04 Essential USDC via x402 v2) to audit ERC-20 tokens via live 5-EVM RPC bytecode disassembly & proxy inspection (no Solidity source required).",
    inputSchema: {
      type: "object",
      properties: {
        tokenAddress: { type: "string", description: "Deployed ERC-20 token address (0x...)." },
        code: { type: "string", description: "Optional Solidity source code for pre-deploy or hybrid AST scan." },
        chainId: { type: "integer", enum: SUPPORTED_CHAINS, default: 8453 },
        tokenName: { type: "string", description: "Optional token label." },
        tier: { type: "string", enum: ["FULL", "ESSENTIAL"], default: "FULL" }
      }
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  },
  {
    name: "ingravity_computeDefiSlippageAndLiquidation",
    title: "DeFi Slippage, MEV & Liquidation Math Guard ($0.04-$0.10)",
    description: "Calls /api/v1/defi-math-guard ($0.10 Full / $0.04 Essential USDC via x402 v2) for exact 18-decimal BigInt AMM swap math, 48-step MEV sandwich bounds, and perpetual liquidation thresholds.",
    inputSchema: {
      type: "object",
      properties: {
        amm: {
          type: "object",
          properties: {
            reserveIn: { type: "string" },
            reserveOut: { type: "string" },
            amountIn: { type: "string" },
            feeBps: { type: "integer", default: 30 },
            userSlippageBps: { type: "integer", default: 100 }
          },
          required: ["reserveIn", "reserveOut", "amountIn"]
        },
        leverage: {
          type: "object",
          properties: {
            entryPrice: { type: "string" },
            leverage: { type: "string", default: "1" },
            side: { type: "string", enum: ["LONG", "SHORT"], default: "LONG" },
            maintenanceMarginBps: { type: "integer", default: 50 }
          },
          required: ["entryPrice"]
        },
        tier: { type: "string", enum: ["FULL", "ESSENTIAL"], default: "FULL" }
      }
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  },
  {
    name: "ingravity_auditSolidityContract",
    title: "24-Vector Solidity Contract Auditor ($0.35-$0.85)",
    description: "Calls /api/v1/audit-solidity ($0.85 Full / $0.35 Essential USDC via x402 v2) for a deterministic 24-vector Solidity static audit with 4-gate anti-noise filtering.",
    inputSchema: {
      type: "object",
      properties: {
        code: { type: "string", description: "Raw Solidity (.sol) smart contract source code." },
        contractName: { type: "string", default: "Contract.sol" },
        chainId: { type: "integer", enum: SUPPORTED_CHAINS, default: 8453 },
        contractAddress: { type: "string", description: "Optional deployed contract address for live TVL check." },
        ownerTreasury: { type: "string", description: "Optional owner/multisig recipient address." },
        tier: { type: "string", enum: ["FULL", "ESSENTIAL"], default: "FULL" }
      },
      required: ["code"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  },
  {
    name: "ingravity_generateMultiContractProtocolDossier",
    title: "Multi-Contract DeFi Protocol Auditor ($3.50-$12.00)",
    description: "Calls /api/v1/protocol-dossier ($12.00 Full / $3.50 Essential USDC via x402 v2) to audit 1-20 interdependent Solidity contracts for cross-contract reentrancy and ERC-4626/oracle invariants.",
    inputSchema: {
      type: "object",
      properties: {
        protocolName: { type: "string", default: "DeFi Protocol" },
        contracts: {
          type: "array",
          minItems: 1,
          maxItems: 20,
          items: {
            type: "object",
            properties: {
              name: { type: "string" },
              code: { type: "string" }
            },
            required: ["name", "code"]
          }
        },
        tvlTargetUsd: { type: "number", default: 1000000 },
        chainId: { type: "integer", enum: SUPPORTED_CHAINS, default: 8453 },
        contractAddress: { type: "string" },
        ownerTreasury: { type: "string" },
        tier: { type: "string", enum: ["FULL", "ESSENTIAL"], default: "FULL" }
      },
      required: ["contracts"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  },
  {
    name: "ingravity_simulateDeepExploitAndWhitehatBounty",
    title: "Flash-Loan Exploit Simulator & Safe-Harbor Planner ($9.50-$45.00)",
    description: "Calls /api/v1/deep-exploit-bounty ($45.00 Full / $9.50 Essential USDC via x402 v2) for flash-loan exploit vector simulation, live TVL inspection, and unsigned EIP-5792 Safe-Harbor rescue plans.",
    inputSchema: {
      type: "object",
      properties: {
        protocolName: { type: "string", description: "Target protocol or pool name." },
        poolAddress: { type: "string", description: "Optional EVM pool or vault address (0x...)." },
        chainId: { type: "integer", enum: SUPPORTED_CHAINS, default: 8453 },
        ownerTreasury: { type: "string" },
        tvlUsd: { type: "number", default: 250000 },
        code: { type: "string" },
        tier: { type: "string", enum: ["FULL", "ESSENTIAL"], default: "FULL" }
      },
      required: ["protocolName"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }
];

const MCP_RESOURCES = [
  {
    uri: "ingravity://docs/supported-chains",
    name: "Supported EVM Chains",
    description: "Canonical chain IDs and settlement asset metadata supported by the Ingravity Security MCP Server.",
    mimeType: "application/json"
  },
  {
    uri: "ingravity://docs/x402-settlement",
    name: "x402 v2 Settlement Guide",
    description: "How to supply INGRAVITY_PRIVATE_KEY (local auto-pay), PAYMENT-SIGNATURE, X-Agent-Budget, and X-Ingravity-Receipt-Token.",
    mimeType: "application/json"
  }
];

const MCP_PROMPTS = [
  {
    name: "pre_sign_transaction_check",
    description: "Structured security checklist before signing any EVM transaction calldata.",
    arguments: [
      { name: "to", description: "Target contract address (0x...)", required: true },
      { name: "data", description: "Hexadecimal calldata (0x...)", required: true },
      { name: "chainId", description: "Target EVM chain ID (default 8453)", required: false }
    ]
  },
  {
    name: "pre_swap_token_check",
    description: "Two-step honeypot and slippage verification workflow before swapping an ERC-20 token.",
    arguments: [
      { name: "tokenAddress", description: "ERC-20 token address (0x...)", required: true },
      { name: "chainId", description: "Target EVM chain ID (default 8453)", required: false }
    ]
  }
];

function makeResult(id, result) {
  return JSON.stringify({ jsonrpc: "2.0", id, result });
}

function makeError(id, code, message, data) {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: id !== undefined ? id : null,
    error: data !== undefined ? { code, message, data } : { code, message }
  });
}

function makeToolResult(payload, isError = false, extraMeta = null) {
  const result = {
    content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload
  };
  if (isError) result.isError = true;
  if (extraMeta && typeof extraMeta === "object" && Object.keys(extraMeta).length > 0) {
    result._meta = extraMeta;
  }
  return result;
}

function encodeX402PaymentHeader(rawPayment) {
  if (!rawPayment) return "";
  if (typeof rawPayment === "object") {
    return Buffer.from(JSON.stringify(rawPayment), "utf8").toString("base64");
  }
  const str = String(rawPayment).trim();
  if (!str) return "";
  if (str.startsWith("{")) {
    return Buffer.from(str, "utf8").toString("base64");
  }
  return str;
}

function decodeBase64JsonHeader(rawHeader) {
  if (!rawHeader || typeof rawHeader !== "string") return null;
  const trimmed = rawHeader.trim();
  if (!trimmed) return null;
  try {
    if (trimmed.startsWith("{")) return JSON.parse(trimmed);
    return JSON.parse(Buffer.from(trimmed, "base64").toString("utf8"));
  } catch (_) {
    return null;
  }
}

function extractMetaPaymentOptions(meta) {
  if (!meta || typeof meta !== "object") return {};
  const out = {};
  const rawPay = meta["x402/payment"] || meta["x402/payment-signature"] || meta["x-payment"] || meta.payment;
  if (rawPay) out.paymentSignature = encodeX402PaymentHeader(rawPay);
  const rawTx = meta["x-settlement-txhash"] || meta["x-tx-hash"] || meta.txHash;
  if (rawTx) out.txHash = String(rawTx).trim();
  const rawReceipt = meta["x-ingravity-receipt-token"] || meta.receiptToken;
  if (rawReceipt) out.receiptToken = String(rawReceipt).trim();
  const rawBudget = meta["x-agent-budget"] || meta.budget;
  if (rawBudget != null && String(rawBudget).trim()) out.budget = String(rawBudget).trim();
  const rawTrial = meta["x-ingravity-onboarding-trial"] || meta.trialToken;
  if (rawTrial) out.onboardingTrial = String(rawTrial).trim();
  return out;
}

function decodeCalldataLocally(dataHex) {
  const clean = String(dataHex || "").trim();
  if (!HEX_DATA_RE.test(clean) || clean.length % 2 !== 0) {
    throw new Error("Invalid hex calldata: must start with 0x and have even length.");
  }
  const body = clean.slice(2).toLowerCase();
  if (body.length === 0) {
    return {
      selector: "0x",
      isPlainNativeTransfer: true,
      knownFunction: null,
      wordCount: 0,
      words: [],
      hasErc8021Suffix: false,
      note: "Structural decode only. Run ingravity_inspectEvmTransactionFirewall for live risk verdicts."
    };
  }
  const selector = "0x" + body.slice(0, 8);
  const argsHex = body.slice(8);
  const words = [];
  for (let i = 0; i + 64 <= argsHex.length && words.length < 8; i += 64) {
    words.push("0x" + argsHex.slice(i, i + 64));
  }
  const known = KNOWN_EVM_SELECTORS[selector] || null;
  const extracted = {};
  if (known && words.length >= 1 && (selector === "0x095ea7b3" || selector === "0xa9059cbb" || selector === "0xa22cb465" || selector === "0x39509351")) {
    extracted.targetAddress = "0x" + words[0].slice(26);
    if (words[1]) {
      extracted.rawSecondWordHex = words[1];
      extracted.isMaxUint256 = words[1].toLowerCase() === "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    }
  }
  return {
    selector,
    isPlainNativeTransfer: false,
    knownFunction: known,
    extractedArgs: extracted,
    wordCount: words.length,
    words,
    byteLength: body.length / 2,
    hasErc8021Suffix: body.endsWith(ERC8021_SUFFIX_HEX.toLowerCase()),
    note: "Structural decode only. Run ingravity_inspectEvmTransactionFirewall for live risk verdicts and proxy forensics."
  };
}

function httpJsonRequest(method, targetUrl, bodyObj, extraHeaders = {}, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    let parsedUrl;
    try {
      parsedUrl = new URL(targetUrl);
    } catch (err) {
      return reject(err);
    }
    const bodyText = method === "POST" && bodyObj ? JSON.stringify(bodyObj) : "";
    const headers = {
      Accept: "application/json",
      "User-Agent": `${SERVER_NAME}-mcp/${SERVER_VERSION}`,
      ...extraHeaders
    };
    if (method === "POST") {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(bodyText, "utf8");
    }
    const transport = parsedUrl.protocol === "http:" ? http : https;
    const req = transport.request(
      {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === "http:" ? 80 : 443),
        path: `${parsedUrl.pathname}${parsedUrl.search}`,
        method,
        headers,
        timeout: timeoutMs
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          let json = null;
          try { json = JSON.parse(raw); } catch (_) {}
          resolve({
            status: res.statusCode || 500,
            headers: res.headers || {},
            json,
            raw
          });
        });
      }
    );
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error(`API request timed out after ${timeoutMs}ms`)));
    if (bodyText) req.write(bodyText, "utf8");
    req.end();
  });
}

function parseCaipChainId(networkStr) {
  const m = String(networkStr || "").match(/^eip155:(\d+)$/i);
  return m ? Number(m[1]) : BASE_CHAIN_ID;
}

async function callIngravityRestApi(method, routePath, bodyObj, cacheKey, options = {}) {
  const baseUrl = (options.apiUrl || DEFAULT_API_URL).replace(/\/$/, "");
  const headers = {};
  const budget = options.budget || process.env.INGRAVITY_AGENT_BUDGET;
  const receiptToken =
    options.receiptToken ||
    process.env.INGRAVITY_RECEIPT_TOKEN ||
    sessionReceiptCache.get(cacheKey);
  const paymentSig = encodeX402PaymentHeader(options.paymentSignature || process.env.INGRAVITY_PAYMENT_SIGNATURE);
  const txHash = options.txHash || process.env.INGRAVITY_TX_HASH;
  const onboardingTrial = options.onboardingTrial || process.env.INGRAVITY_ONBOARDING_TRIAL;
  const capitalAtRisk = options.capitalAtRiskUsd || process.env.INGRAVITY_CAPITAL_AT_RISK_USD;

  if (budget) headers["X-Agent-Budget"] = String(budget);
  if (receiptToken) headers["X-Ingravity-Receipt-Token"] = String(receiptToken);
  if (paymentSig) headers["PAYMENT-SIGNATURE"] = String(paymentSig);
  if (txHash) {
    headers["X-TX-HASH"] = String(txHash);
    headers["X-Settlement-TxHash"] = String(txHash);
  }
  if (onboardingTrial) headers["X-Ingravity-Onboarding-Trial"] = String(onboardingTrial);
  if (capitalAtRisk) headers["X-Capital-At-Risk-Usd"] = String(capitalAtRisk);

  const res = await httpJsonRequest(method, `${baseUrl}${routePath}`, bodyObj, headers, options.timeoutMs || 15000);
  const payload = res.json && typeof res.json === "object"
    ? res.json
    : { status: res.status, body: res.raw.slice(0, 500) };

  if (res.status >= 200 && res.status < 300) {
    const newReceipt =
      res.headers["x-ingravity-receipt-token"] ||
      (payload && typeof payload.receiptToken === "string" ? payload.receiptToken : null);
    if (newReceipt && cacheKey) {
      sessionReceiptCache.set(cacheKey, String(newReceipt));
    }
    const payRespObj = decodeBase64JsonHeader(res.headers["payment-response"] || res.headers["x-payment-response"]);
    const extraMeta = payRespObj ? { "x402/payment-response": payRespObj } : null;
    return makeToolResult(payload, false, extraMeta);
  }

  if (res.status === 402) {
    if (receiptToken && cacheKey) {
      sessionReceiptCache.delete(cacheKey);
      delete headers["X-Ingravity-Receipt-Token"];
    }
    const decodedChallenge = decodeBase64JsonHeader(res.headers["payment-required"] || res.headers["x-payment-required"]);
    const canonical402 =
      decodedChallenge && typeof decodedChallenge === "object" && Array.isArray(decodedChallenge.accepts)
        ? decodedChallenge
        : (payload && payload.x402Version && Array.isArray(payload.accepts)
          ? payload
          : { x402Version: 2, httpStatus: 402, paymentRequired: true, ...payload });

    // Local zero-custody EIP-3009 auto-signing when INGRAVITY_PRIVATE_KEY is explicitly configured
    const autoPrivKey = options.privateKey || process.env.INGRAVITY_PRIVATE_KEY || process.env.X402_PRIVATE_KEY;
    if (autoPrivKey && !paymentSig && Array.isArray(canonical402.accepts) && canonical402.accepts.length > 0) {
      try {
        const signer = createEip3009PrivateKeySigner(autoPrivKey);
        const maxBudgetUsdc = budget != null && String(budget).trim() !== "" ? Number(budget) : 0.12;
        const maxAtoms = BigInt(Math.floor(maxBudgetUsdc * 1e6 + 1e-6));
        const cleanAccepts = canonical402.accepts.map(sanitizeX402V2Accept);
        const requestedTier = bodyObj && bodyObj.tier ? String(bodyObj.tier).trim().toUpperCase() : null;
        const affordable = cleanAccepts.filter((a) => a && a.amount && BigInt(a.amount) <= maxAtoms);
        const chosen =
          (requestedTier
            ? affordable.find((a) => String((a.extra && a.extra.tier) || "FULL").toUpperCase() === requestedTier)
            : null) ||
          affordable.find((a) => String(a.network || "").toLowerCase() === "eip155:8453") ||
          affordable[0] ||
          null;

        if (chosen && chosen.payTo) {
          const now = Math.floor(Date.now() / 1000);
          const authorization = {
            from: signer.address,
            to: chosen.payTo,
            value: String(chosen.amount),
            validAfter: String(now - 60),
            validBefore: String(now + (chosen.maxTimeoutSeconds || 300)),
            nonce: "0x" + crypto.randomBytes(32).toString("hex")
          };
          const signature = await signer.signTypedData({
            domain: {
              name: (chosen.extra && chosen.extra.name) || "USD Coin",
              version: (chosen.extra && chosen.extra.version) || "2",
              chainId: parseCaipChainId(chosen.network),
              verifyingContract: chosen.asset || BASE_USDC_CONTRACT
            },
            message: authorization
          });
          const signedPayload = {
            x402Version: 2,
            accepted: chosen,
            payload: { signature, authorization }
          };
          const retryHeaders = {
            ...headers,
            "PAYMENT-SIGNATURE": Buffer.from(JSON.stringify(signedPayload), "utf8").toString("base64")
          };
          const paidRes = await httpJsonRequest(method, `${baseUrl}${routePath}`, bodyObj, retryHeaders, options.timeoutMs || 15000);
          if (paidRes.status >= 200 && paidRes.status < 300) {
            const paidData = paidRes.json && typeof paidRes.json === "object" ? paidRes.json : { status: paidRes.status, body: paidRes.raw };
            const newReceipt =
              paidRes.headers["x-ingravity-receipt-token"] ||
              (paidData && typeof paidData.receiptToken === "string" ? paidData.receiptToken : null);
            if (newReceipt && cacheKey) {
              sessionReceiptCache.set(cacheKey, String(newReceipt));
            }
            const payRespObj = decodeBase64JsonHeader(paidRes.headers["payment-response"] || paidRes.headers["x-payment-response"]);
            return makeToolResult(paidData, false, payRespObj ? { "x402/payment-response": payRespObj } : null);
          }
        }
      } catch (_) {}
    }

    return makeToolResult(canonical402, true, { "x402/error": canonical402 });
  }

  return makeToolResult(
    {
      httpStatus: res.status,
      ...payload
    },
    true
  );
}

async function executeToolCall(rawToolName, rawArgs, options = {}) {
  const toolName = TOOL_ALIASES[rawToolName] || rawToolName;
  const args = rawArgs && typeof rawArgs === "object" ? rawArgs : {};

  if (toolName === "ingravity_encodeErc8021Calldata") {
    if (typeof args.calldata !== "string" || !args.calldata.trim()) {
      return { rpcError: [-32602, "Invalid params: 'calldata' hex string is required."] };
    }
    try {
      const encoded = encodeErc8021Calldata(args.calldata);
      return {
        result: makeToolResult({
          builderCode: ERC8021_BUILDER_CODE,
          erc8021SuffixHex: ERC8021_SUFFIX_HEX,
          originalCalldata: args.calldata,
          encodedCalldata: encoded,
          executedLocally: true
        })
      };
    } catch (err) {
      return { rpcError: [-32602, err.message] };
    }
  }

  if (toolName === "ingravity_decodeEvmCalldataSelector") {
    if (typeof args.data !== "string") {
      return { rpcError: [-32602, "Invalid params: 'data' hex string is required."] };
    }
    try {
      const decoded = decodeCalldataLocally(args.data);
      return { result: makeToolResult({ ...decoded, executedLocally: true }) };
    } catch (err) {
      return { rpcError: [-32602, err.message] };
    }
  }

  if (toolName === "ingravity_fastPingAddressSafety") {
    if (!EVM_ADDR_RE.test(String(args.address || ""))) {
      return { rpcError: [-32602, "Invalid params: 'address' must be a 42-char EVM hex address (0x...)."] };
    }
    const chainId = Number(args.chainId || 8453);
    const route = `/api/v1/fast-ping?address=${encodeURIComponent(args.address)}&chainId=${chainId}`;
    return {
      result: await callIngravityRestApi("GET", route, null, `fast-ping:${args.address.toLowerCase()}:${chainId}`, options)
    };
  }

  if (toolName === "ingravity_inspectEvmTransactionFirewall") {
    if (!EVM_ADDR_RE.test(String(args.to || ""))) {
      return { rpcError: [-32602, "Invalid params: 'to' must be a 42-char EVM hex address (0x...)."] };
    }
    const payload = {
      to: args.to,
      data: args.data || "0x",
      value: args.value || "0",
      chainId: Number(args.chainId || 8453),
      ...(args.from ? { from: args.from } : {}),
      ...(args.ticketId ? { ticketId: args.ticketId } : {}),
      ...(args.capitalAtRiskUsd != null ? { capitalAtRiskUsd: Number(args.capitalAtRiskUsd) } : {})
    };
    return {
      result: await callIngravityRestApi("POST", "/api/v1/tx-firewall", payload, `tx-fw:${args.to.toLowerCase()}:${payload.data}:${payload.chainId}`, options)
    };
  }

  if (toolName === "ingravity_scanTokenRugpullAndHoneypot") {
    if (!args.tokenAddress && !args.code) {
      return { rpcError: [-32602, "Invalid params: supply at least one of 'tokenAddress' or 'code'."] };
    }
    if (args.tokenAddress && !EVM_ADDR_RE.test(String(args.tokenAddress))) {
      return { rpcError: [-32602, "Invalid params: 'tokenAddress' must be a valid 0x EVM address."] };
    }
    const payload = {
      chainId: Number(args.chainId || 8453),
      tier: args.tier || "FULL",
      ...(args.tokenAddress ? { tokenAddress: args.tokenAddress } : {}),
      ...(args.code ? { code: args.code } : {}),
      ...(args.tokenName ? { tokenName: args.tokenName } : {})
    };
    return {
      result: await callIngravityRestApi("POST", "/api/v1/token-rug-scanner", payload, `rug:${String(args.tokenAddress || "code").toLowerCase()}:${payload.chainId}:${payload.tier}`, options)
    };
  }

  if (toolName === "ingravity_computeDefiSlippageAndLiquidation") {
    if (!args.amm && !args.leverage) {
      return { rpcError: [-32602, "Invalid params: supply 'amm', 'leverage', or both."] };
    }
    const payload = {
      tier: args.tier || "FULL",
      ...(args.amm ? { amm: args.amm } : {}),
      ...(args.leverage ? { leverage: args.leverage } : {})
    };
    return {
      result: await callIngravityRestApi("POST", "/api/v1/defi-math-guard", payload, `math:${JSON.stringify(payload).slice(0, 80)}`, options)
    };
  }

  if (toolName === "ingravity_auditSolidityContract") {
    if (typeof args.code !== "string" || args.code.trim().length < 5) {
      return { rpcError: [-32602, "Invalid params: non-empty Solidity 'code' string is required."] };
    }
    const payload = {
      code: args.code,
      chainId: Number(args.chainId || 8453),
      tier: args.tier || "FULL",
      ...(args.contractName ? { contractName: args.contractName } : {}),
      ...(args.contractAddress ? { contractAddress: args.contractAddress } : {}),
      ...(args.ownerTreasury ? { ownerTreasury: args.ownerTreasury } : {})
    };
    return {
      result: await callIngravityRestApi("POST", "/api/v1/audit-solidity", payload, `audit:${args.contractAddress || args.contractName || "sol"}:${args.code.length}:${payload.tier}`, options)
    };
  }

  if (toolName === "ingravity_generateMultiContractProtocolDossier") {
    if (!Array.isArray(args.contracts) || args.contracts.length === 0) {
      return { rpcError: [-32602, "Invalid params: non-empty 'contracts' array of {name, code} is required."] };
    }
    const payload = {
      contracts: args.contracts,
      chainId: Number(args.chainId || 8453),
      tier: args.tier || "FULL",
      ...(args.protocolName ? { protocolName: args.protocolName } : {}),
      ...(args.tvlTargetUsd != null ? { tvlTargetUsd: Number(args.tvlTargetUsd) } : {}),
      ...(args.contractAddress ? { contractAddress: args.contractAddress } : {}),
      ...(args.ownerTreasury ? { ownerTreasury: args.ownerTreasury } : {})
    };
    return {
      result: await callIngravityRestApi("POST", "/api/v1/protocol-dossier", payload, `dossier:${args.protocolName || "proto"}:${args.contracts.length}:${payload.tier}`, options)
    };
  }

  if (toolName === "ingravity_simulateDeepExploitAndWhitehatBounty") {
    if (typeof args.protocolName !== "string" || !args.protocolName.trim()) {
      return { rpcError: [-32602, "Invalid params: non-empty 'protocolName' is required."] };
    }
    const payload = {
      protocolName: args.protocolName,
      chainId: Number(args.chainId || 8453),
      tier: args.tier || "FULL",
      ...(args.poolAddress ? { poolAddress: args.poolAddress } : {}),
      ...(args.ownerTreasury ? { ownerTreasury: args.ownerTreasury } : {}),
      ...(args.tvlUsd != null ? { tvlUsd: Number(args.tvlUsd) } : {}),
      ...(args.code ? { code: args.code } : {})
    };
    return {
      result: await callIngravityRestApi("POST", "/api/v1/deep-exploit-bounty", payload, `bounty:${args.protocolName}:${args.poolAddress || "default"}:${payload.tier}`, options)
    };
  }

  return { rpcError: [-32602, `Unknown tool: ${rawToolName}`] };
}

async function handleMcpMessage(jsonLine, options = {}) {
  const trimmed = String(jsonLine || "").trim();
  if (!trimmed) return null;

  let req;
  try {
    req = JSON.parse(trimmed);
  } catch (err) {
    return makeError(null, -32700, `Parse error: ${err.message}`);
  }

  if (!req || typeof req !== "object" || req.jsonrpc !== "2.0" || typeof req.method !== "string") {
    return makeError(req && req.id !== undefined ? req.id : null, -32600, "Invalid JSON-RPC 2.0 request");
  }

  const hasId = Object.prototype.hasOwnProperty.call(req, "id");
  const id = hasId ? req.id : undefined;
  const method = req.method;
  const params = req.params && typeof req.params === "object" ? req.params : {};

  if (!hasId && method.startsWith("notifications/")) {
    return null;
  }

  if (method === "initialize") {
    const protocolVersion = typeof params.protocolVersion === "string" ? params.protocolVersion : "2025-06-18";
    return makeResult(id, {
      protocolVersion,
      capabilities: {
        tools: { listChanged: false },
        resources: { subscribe: false, listChanged: false },
        prompts: { listChanged: false }
      },
      serverInfo: {
        name: SERVER_NAME,
        version: SERVER_VERSION
      },
      instructions:
        "Ingravity Security MCP Server (5-EVM Web3 defense). Use local tools ingravity_decodeEvmCalldataSelector and ingravity_encodeErc8021Calldata for structural calldata parsing and ERC-8021 attribution, and the 7 x402-backed API tools ($0.01-$45.00 USDC on Base) for live honeypot, drainer firewall, MEV math, and Solidity audit verdicts. Set INGRAVITY_PRIVATE_KEY + INGRAVITY_AGENT_BUDGET for automatic local gasless EIP-3009 payments."
    });
  }

  if (method === "ping") {
    return makeResult(id, {});
  }

  if (method === "tools/list") {
    return makeResult(id, { tools: MCP_TOOLS });
  }

  if (method === "tools/call") {
    const toolName = String(params.name || "");
    if (!toolName) {
      return makeError(id, -32602, "Invalid params: tool 'name' is required.");
    }
    try {
      const metaOpts = extractMetaPaymentOptions(params._meta);
      const mergedOptions = { ...options, ...metaOpts };
      const outcome = await executeToolCall(toolName, params.arguments || {}, mergedOptions);
      if (outcome.rpcError) {
        return makeError(id, outcome.rpcError[0], outcome.rpcError[1]);
      }
      return makeResult(id, outcome.result);
    } catch (err) {
      return makeError(id, -32603, `Tool execution error: ${err.message}`);
    }
  }

  if (method === "resources/list") {
    return makeResult(id, { resources: MCP_RESOURCES });
  }

  if (method === "resources/read") {
    const uri = String(params.uri || "");
    if (uri === "ingravity://docs/supported-chains") {
      return makeResult(id, {
        contents: [
          {
            uri,
            mimeType: "application/json",
            text: JSON.stringify({
              defaultChainId: 8453,
              supportedChains: [
                { chainId: 8453, name: "Base Mainnet", caip2: "eip155:8453", settlementAsset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" },
                { chainId: 42161, name: "Arbitrum One", caip2: "eip155:42161" },
                { chainId: 10, name: "OP Mainnet", caip2: "eip155:10" },
                { chainId: 137, name: "Polygon PoS", caip2: "eip155:137" },
                { chainId: 1, name: "Ethereum Mainnet", caip2: "eip155:1" }
              ]
            }, null, 2)
          }
        ]
      });
    }
    if (uri === "ingravity://docs/x402-settlement") {
      return makeResult(id, {
        contents: [
          {
            uri,
            mimeType: "application/json",
            text: JSON.stringify({
              protocol: "x402 v2",
              network: "eip155:8453",
              asset: "Native Base USDC (0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)",
              zeroCustody: true,
              envVars: {
                INGRAVITY_PRIVATE_KEY: "Optional local EVM private key (0x...) for automatic zero-custody EIP-3009 signing up to INGRAVITY_AGENT_BUDGET",
                INGRAVITY_AGENT_BUDGET: "Optional max USDC spend per call (default: 0.12 when INGRAVITY_PRIVATE_KEY is set)",
                INGRAVITY_API_URL: "Override Ingravity REST API base URL",
                INGRAVITY_PAYMENT_SIGNATURE: "Base64 EIP-3009 x402 PAYMENT-SIGNATURE header",
                INGRAVITY_RECEIPT_TOKEN: "Optional reusable X-Ingravity-Receipt-Token"
              }
            }, null, 2)
          }
        ]
      });
    }
    return makeError(id, -32602, `Unknown resource URI: ${uri}`);
  }

  if (method === "prompts/list") {
    return makeResult(id, { prompts: MCP_PROMPTS });
  }

  if (method === "prompts/get") {
    const promptName = String(params.name || "");
    const pArgs = params.arguments && typeof params.arguments === "object" ? params.arguments : {};
    if (promptName === "pre_sign_transaction_check") {
      return makeResult(id, {
        description: "Pre-sign EVM transaction inspection workflow",
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `First decode calldata selector locally with ingravity_decodeEvmCalldataSelector (data=${pArgs.data || "0x"}). Then inspect target ${pArgs.to || "0x..."} on chainId ${pArgs.chainId || 8453} with ingravity_inspectEvmTransactionFirewall before signing.`
            }
          }
        ]
      });
    }
    if (promptName === "pre_swap_token_check") {
      return makeResult(id, {
        description: "Pre-swap ERC-20 honeypot and slippage verification workflow",
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Run ingravity_fastPingAddressSafety on token ${pArgs.tokenAddress || "0x..."} (chainId ${pArgs.chainId || 8453}). If further due diligence is needed, run ingravity_scanTokenRugpullAndHoneypot and ingravity_computeDefiSlippageAndLiquidation before swapping.`
            }
          }
        ]
      });
    }
    return makeError(id, -32602, `Unknown prompt: ${promptName}`);
  }

  return makeError(id, -32601, `Method not found: ${method}`);
}

async function runCliCommand(argv, opts = {}) {
  const fs = require("fs");
  const sub = String(argv[0] || "").trim().toLowerCase();
  const privKey = opts.privateKey || process.env.INGRAVITY_PRIVATE_KEY || process.env.EVM_PRIVATE_KEY || process.env.PRIVATE_KEY || null;
  const passTok = opts.passToken || process.env.INGRAVITY_PASS_TOKEN || null;
  const maxSpend = opts.maxSpendUsdc != null
    ? Number(opts.maxSpendUsdc)
    : (process.env.INGRAVITY_AGENT_BUDGET != null ? Number(process.env.INGRAVITY_AGENT_BUDGET) : null);

  if (sub === "--version" || sub === "-v" || sub === "version") {
    return { version: SERVER_VERSION, name: SERVER_NAME };
  }
  if (sub === "--help" || sub === "-h" || sub === "help") {
    return {
      name: SERVER_NAME,
      version: SERVER_VERSION,
      usage: [
        "npx ingravity-security ping <0xAddress> [chainId=8453]          # $0.01 USDC binary SAFE/DANGER gate",
        "npx ingravity-security scan <0xTokenAddress> [chainId=8453]     # $0.04 Signal / $0.12 Full ERC-20 honeypot scan",
        "npx ingravity-security firewall <0xTo> [0xData=0x] [chainId]    # $0.10 USDC pre-sign calldata firewall",
        "npx ingravity-security audit <path/to/Contract.sol>             # $0.85 USDC 24-vector Solidity audit",
        "npx ingravity-security pass [usdAmount=1]                       # $1/$5/$25 Prepaid M2M Pass (+15% bonus, <15ms)",
        "npx ingravity-mcp                                               # Start MCP 2025-06-18 STDIO Server"
      ],
      autoPayEnv: "Set INGRAVITY_PRIVATE_KEY=0x... (or EVM_PRIVATE_KEY) with Base Mainnet USDC for 0-gas EIP-3009 auto-settlement."
    };
  }

  const guard = new IngravitySecurityActionProvider({
    workerUrl: opts.apiUrl || DEFAULT_API_URL,
    privateKey: privKey,
    passToken: passTok,
    maxSpendUsdc: maxSpend
  });

  if (sub === "ping" || sub === "fast-ping") {
    const address = argv[1] || BASE_USDC_CONTRACT;
    const chainId = argv[2] ? Number(argv[2]) : 8453;
    return await guard.fastPing({ address, chainId });
  }
  if (sub === "scan" || sub === "rug") {
    const tokenAddress = argv[1] || BASE_USDC_CONTRACT;
    const chainId = argv[2] ? Number(argv[2]) : 8453;
    const tier = argv[3] ? String(argv[3]).toUpperCase() : undefined;
    return await guard.tokenRugScanner({ tokenAddress, chainId, ...(tier ? { tier } : {}) });
  }
  if (sub === "firewall" || sub === "tx") {
    const to = argv[1] || BASE_USDC_CONTRACT;
    const data = argv[2] || "0x";
    const chainId = argv[3] ? Number(argv[3]) : 8453;
    return await guard.txFirewall({ to, data, chainId });
  }
  if (sub === "audit") {
    const fileArg = argv[1];
    if (!fileArg || !fs.existsSync(fileArg)) {
      throw new Error("Provide a valid Solidity file path: npx ingravity-security audit ./Contract.sol");
    }
    const code = fs.readFileSync(fileArg, "utf8");
    return await guard.auditSolidity({ code, contractName: fileArg });
  }
  if (sub === "pass" || sub === "topup") {
    const usdAmount = argv[1] ? Number(argv[1]) : 1;
    return await guard.topupPass({ usdAmount });
  }
  return null;
}

if (require.main === module) {
  const cliArgs = process.argv.slice(2);
  const cliSub = cliArgs[0] ? String(cliArgs[0]).trim().toLowerCase() : "";
  const isCliInvoke = Boolean(cliSub && cliSub !== "mcp" && cliSub !== "stdio" && cliSub !== "--stdio");
  if (isCliInvoke) {
    runCliCommand(cliArgs)
      .then((out) => {
        if (out !== null) {
          process.stdout.write(JSON.stringify(out, null, 2) + "\n");
          process.exit(0);
        }
      })
      .catch((err) => {
        process.stderr.write(JSON.stringify({ error: err.message }) + "\n");
        process.exit(1);
      });
  } else {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false
    });
    rl.on("line", async (line) => {
      try {
        const resp = await handleMcpMessage(line);
        if (resp) process.stdout.write(resp + "\n");
      } catch (err) {
        process.stdout.write(makeError(null, -32603, err.message) + "\n");
      }
    });
  }
}

module.exports = {
  handleMcpMessage,
  forwardMcpLine: handleMcpMessage,
  runCliCommand,
  executeToolCall,
  decodeCalldataLocally,
  MCP_TOOLS,
  MCP_RESOURCES,
  MCP_PROMPTS,
  MCP_ENDPOINT_URL,
  SERVER_NAME,
  SERVER_VERSION
};
