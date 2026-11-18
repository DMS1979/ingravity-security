#!/usr/bin/env node
/**
 * ingravity-mcp (ingravity-security v1.3.0 STDIO-to-HTTP MCP Bridge)
 * ----------------------------------------------------------------------------
 * Zero-dependency Model Context Protocol (MCP 2025-06-18) STDIO bridge for
 * Claude Desktop, Cursor, Windsurf, Cline, Glama Server introspection, and
 * autonomous agent runtimes.
 *
 * Forwards JSON-RPC 2.0 MCP calls directly to Ingravity Streamable-HTTP MCP:
 *   https://red-shape-1b3b.daviddelmoral79.workers.dev/mcp
 */

const https = require("https");
const http = require("http");
const readline = require("readline");

const DEFAULT_WORKER_URL = (process.env.INGRAVITY_WORKER_URL || "https://red-shape-1b3b.daviddelmoral79.workers.dev").replace(/\/$/, "");
const MCP_ENDPOINT_URL = (process.env.INGRAVITY_MCP_URL || `${DEFAULT_WORKER_URL}/mcp`).trim();

const OFFLINE_INTROSPECTION_TOOLS = [
  {
    name: "ingravity_fastPingAddressSafety",
    title: "Fast EVM Address Safety Ping",
    description: "Binary SAFE/DANGER address gate across 5 EVM chains ($0.01 USDC flat via x402 v2 on Base Mainnet).",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string", description: "42-character EVM address (0x...)." },
        chainId: { type: "integer", enum: [8453, 42161, 10, 137, 1], default: 8453 }
      },
      required: ["address"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  },
  {
    name: "ingravity_inspectEvmTransactionFirewall",
    title: "EVM Transaction Firewall",
    description: "Pre-sign 5-EVM transaction firewall, drainer interception & unsigned EIP-5792 revocation builder ($0.10 USDC via x402 v2).",
    inputSchema: {
      type: "object",
      properties: {
        to: { type: "string", description: "Target contract or spender address (0x...)." },
        data: { type: "string", default: "0x" },
        from: { type: "string" },
        value: { type: "string", default: "0" },
        chainId: { type: "integer", enum: [8453, 42161, 10, 137, 1], default: 8453 }
      },
      required: ["to"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  },
  {
    name: "ingravity_scanTokenRugpullAndHoneypot",
    title: "ERC-20 Token Rugpull & Honeypot Scanner",
    description: "Live 5-EVM RPC bytecode & EIP-1967/1167 proxy honeypot scanner by tokenAddress ($0.12 Full / $0.04 Essential USDC).",
    inputSchema: {
      type: "object",
      properties: {
        tokenAddress: { type: "string", description: "Deployed ERC-20 token address (0x...)." },
        code: { type: "string", description: "Optional Solidity source code." },
        chainId: { type: "integer", enum: [8453, 42161, 10, 137, 1], default: 8453 },
        tier: { type: "string", enum: ["FULL", "ESSENTIAL"], default: "FULL" }
      }
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  },
  {
    name: "ingravity_computeDefiSlippageAndLiquidation",
    title: "DeFi Slippage, MEV & Liquidation Math Guard",
    description: "Deterministic 18-decimal BigInt AMM slippage, 48-step MEV sandwich bounds & perp liquidation guard ($0.10 Full / $0.04 Essential).",
    inputSchema: {
      type: "object",
      properties: {
        amm: { type: "object", properties: { reserveIn: { type: "string" }, reserveOut: { type: "string" }, amountIn: { type: "string" } }, required: ["reserveIn", "reserveOut", "amountIn"] },
        leverage: { type: "object", properties: { entryPrice: { type: "string" }, leverage: { type: "string" }, side: { type: "string", enum: ["LONG", "SHORT"] } }, required: ["entryPrice"] },
        tier: { type: "string", enum: ["FULL", "ESSENTIAL"], default: "FULL" }
      }
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "ingravity_auditSolidityContract",
    title: "24-Vector Solidity Contract Auditor",
    description: "Deterministic 24-vector Solidity static audit with 4-gate anti-noise filter ($0.85 Full / $0.35 Essential USDC).",
    inputSchema: {
      type: "object",
      properties: {
        code: { type: "string", description: "Solidity (.sol) source code." },
        contractName: { type: "string" },
        chainId: { type: "integer", enum: [8453, 42161, 10, 137, 1], default: 8453 },
        tier: { type: "string", enum: ["FULL", "ESSENTIAL"], default: "FULL" }
      },
      required: ["code"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  },
  {
    name: "ingravity_generateMultiContractProtocolDossier",
    title: "Multi-Contract DeFi Protocol Auditor",
    description: "Cross-contract read-only reentrancy & ERC-4626/oracle invariants across 1-20 Solidity files ($12.00 Full / $3.50 Essential).",
    inputSchema: {
      type: "object",
      properties: {
        protocolName: { type: "string" },
        contracts: { type: "array", items: { type: "object", properties: { name: { type: "string" }, code: { type: "string" } }, required: ["name", "code"] } },
        tier: { type: "string", enum: ["FULL", "ESSENTIAL"], default: "FULL" }
      },
      required: ["contracts"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  },
  {
    name: "ingravity_simulateDeepExploitAndWhitehatBounty",
    title: "Flash-Loan Exploit Simulator & Safe-Harbor Planner",
    description: "Institutional flash-loan simulation, live TVL check & Safe-Harbor rescue bundle planner ($45.00 Full / $9.50 Essential).",
    inputSchema: {
      type: "object",
      properties: {
        protocolName: { type: "string" },
        poolAddress: { type: "string" },
        chainId: { type: "integer", enum: [8453, 42161, 10, 137, 1], default: 8453 },
        tier: { type: "string", enum: ["FULL", "ESSENTIAL"], default: "FULL" }
      },
      required: ["protocolName"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }
];

function buildOfflineIntrospectionFallback(reqObj, reqId) {
  const method = String((reqObj && reqObj.method) || "");
  if (method === "initialize") {
    const requestedVer = (reqObj && reqObj.params && reqObj.params.protocolVersion) || "2025-06-18";
    return JSON.stringify({
      jsonrpc: "2.0",
      id: reqId,
      result: {
        protocolVersion: requestedVer,
        capabilities: { tools: { listChanged: false }, resources: {}, prompts: {} },
        serverInfo: { name: "ingravity-evm-security-mcp", version: "3.13.0" },
        instructions: "Ingravity 5-EVM security & x402 v2 firewall MCP bridge (Base Mainnet USDC settlement)."
      }
    });
  }
  if (method === "ping") {
    return JSON.stringify({ jsonrpc: "2.0", id: reqId, result: {} });
  }
  if (method === "tools/list") {
    return JSON.stringify({ jsonrpc: "2.0", id: reqId, result: { tools: OFFLINE_INTROSPECTION_TOOLS } });
  }
  if (method === "resources/list") {
    return JSON.stringify({ jsonrpc: "2.0", id: reqId, result: { resources: [] } });
  }
  if (method === "prompts/list") {
    return JSON.stringify({ jsonrpc: "2.0", id: reqId, result: { prompts: [] } });
  }
  return null;
}

function makeJsonRpcError(id, code, message, data) {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: id !== undefined ? id : null,
    error: data !== undefined ? { code, message, data } : { code, message }
  });
}

function postJsonRaw(targetUrl, bodyText, extraHeaders = {}, timeoutMs = 12000) {
  return new Promise((resolve, reject) => {
    let parsedUrl;
    try {
      parsedUrl = new URL(targetUrl);
    } catch (err) {
      return reject(err);
    }
    const transport = parsedUrl.protocol === "http:" ? http : https;
    const req = transport.request(
      {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === "http:" ? 80 : 443),
        path: `${parsedUrl.pathname}${parsedUrl.search}`,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json, text/event-stream",
          "Content-Length": Buffer.byteLength(bodyText, "utf8"),
          ...extraHeaders
        },
        timeout: timeoutMs
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            status: res.statusCode || 500,
            contentType: String(res.headers["content-type"] || ""),
            body: Buffer.concat(chunks).toString("utf8")
          });
        });
      }
    );
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy(new Error(`MCP upstream timeout after ${timeoutMs}ms`));
    });
    req.write(bodyText, "utf8");
    req.end();
  });
}

async function forwardMcpLine(jsonLine, options = {}) {
  const endpointUrl = options.endpointUrl || MCP_ENDPOINT_URL;
  const trimmed = String(jsonLine || "").trim();
  if (!trimmed) return null;

  let reqObj;
  try {
    reqObj = JSON.parse(trimmed);
  } catch (err) {
    return makeJsonRpcError(null, -32700, `Parse error: ${err.message}`);
  }

  const reqId = Object.prototype.hasOwnProperty.call(reqObj, "id") ? reqObj.id : undefined;
  const isNotification = reqId === undefined && typeof reqObj.method === "string" && reqObj.method.startsWith("notifications/");

  const headers = {};
  const budget = options.budget || process.env.INGRAVITY_AGENT_BUDGET;
  const receiptToken = options.receiptToken || process.env.INGRAVITY_RECEIPT_TOKEN;
  const paymentSig = options.paymentSignature || process.env.INGRAVITY_PAYMENT_SIGNATURE;
  const capitalAtRisk = options.capitalAtRiskUsd || process.env.INGRAVITY_CAPITAL_AT_RISK_USD;
  if (budget) headers["X-Agent-Budget"] = String(budget);
  if (receiptToken) headers["X-Ingravity-Receipt-Token"] = String(receiptToken);
  if (paymentSig) headers["PAYMENT-SIGNATURE"] = String(paymentSig);
  if (capitalAtRisk) headers["X-Capital-At-Risk-Usd"] = String(capitalAtRisk);

  try {
    const res = await postJsonRaw(endpointUrl, trimmed, headers, options.timeoutMs || 12000);
    if (isNotification && res.status >= 200 && res.status < 300 && !res.body.trim()) {
      return null;
    }
    const rawBody = String(res.body || "").trim();
    if (!rawBody) {
      if (isNotification) return null;
      const fallback = buildOfflineIntrospectionFallback(reqObj, reqId);
      if (fallback) return fallback;
      return makeJsonRpcError(reqId, -32603, `Empty response from MCP server (HTTP ${res.status})`);
    }
    try {
      const parsedResp = JSON.parse(rawBody);
      return JSON.stringify(parsedResp);
    } catch (_) {
      if (res.contentType.includes("text/event-stream") || /^data:/m.test(rawBody)) {
        const dataLines = rawBody
          .split(/\r?\n/)
          .filter((l) => l.startsWith("data:"))
          .map((l) => l.slice(5).trim())
          .filter((l) => l && l !== "[DONE]");
        for (let i = dataLines.length - 1; i >= 0; i--) {
          try {
            const parsedSse = JSON.parse(dataLines[i]);
            return JSON.stringify(parsedSse);
          } catch (_) {}
        }
      }
      const fallback = buildOfflineIntrospectionFallback(reqObj, reqId);
      if (fallback) return fallback;
      return makeJsonRpcError(reqId, -32603, `Non-JSON response from MCP server (HTTP ${res.status})`, rawBody.slice(0, 300));
    }
  } catch (err) {
    if (isNotification) return null;
    const fallback = buildOfflineIntrospectionFallback(reqObj, reqId);
    if (fallback) return fallback;
    return makeJsonRpcError(reqId, -32603, `MCP transport error: ${err.message}`);
  }
}

if (require.main === module) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
  });

  rl.on("line", async (line) => {
    const response = await forwardMcpLine(line);
    if (response) {
      process.stdout.write(response.replace(/\r?\n/g, "") + "\n");
    }
  });
}

module.exports = {
  forwardMcpLine,
  MCP_ENDPOINT_URL,
  DEFAULT_WORKER_URL
};
