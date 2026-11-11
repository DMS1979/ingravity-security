#!/usr/bin/env node
/**
 * ingravity-mcp (ingravity-security v1.3.0 STDIO-to-HTTP MCP Bridge)
 * ----------------------------------------------------------------------------
 * Zero-dependency Model Context Protocol (MCP 2025-06-18) STDIO bridge for
 * Claude Desktop, Cursor, Windsurf, Cline, and autonomous agent runtimes.
 *
 * Forwards JSON-RPC 2.0 MCP calls directly to Ingravity Streamable-HTTP MCP:
 *   https://red-shape-1b3b.daviddelmoral79.workers.dev/mcp
 */

const https = require("https");
const http = require("http");
const readline = require("readline");

const DEFAULT_WORKER_URL = (process.env.INGRAVITY_WORKER_URL || "https://red-shape-1b3b.daviddelmoral79.workers.dev").replace(/\/$/, "");
const MCP_ENDPOINT_URL = (process.env.INGRAVITY_MCP_URL || `${DEFAULT_WORKER_URL}/mcp`).trim();

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
      return makeJsonRpcError(reqId, -32603, `Non-JSON response from MCP server (HTTP ${res.status})`, rawBody.slice(0, 300));
    }
  } catch (err) {
    if (isNotification) return null;
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
