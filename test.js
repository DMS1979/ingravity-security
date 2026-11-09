const assert = require("assert");
const {
  IngravitySecurityActionProvider,
  ingravityElizaPlugin,
  encodeErc8021Calldata,
  sanitizeX402V2Accept,
  ERC8021_BUILDER_CODE,
  ERC8021_SUFFIX_HEX,
  SDK_VERSION
} = require("./index.js");
const { forwardMcpLine, MCP_ENDPOINT_URL } = require("./mcp.js");

console.log(`[TEST] Testing Ingravity Security SDK v${SDK_VERSION} exports...`);

assert.strictEqual(SDK_VERSION, "1.2.0", "SDK_VERSION must be 1.2.0");
assert.ok(IngravitySecurityActionProvider, "IngravitySecurityActionProvider must be exported");
assert.ok(ingravityElizaPlugin, "ingravityElizaPlugin must be exported");
assert.strictEqual(ERC8021_BUILDER_CODE, "bc_i26d7owr");
assert.strictEqual(typeof forwardMcpLine, "function", "mcp.js forwardMcpLine must be exported");
assert.ok(MCP_ENDPOINT_URL.endsWith("/mcp"), "MCP_ENDPOINT_URL must point to /mcp");

const provider = new IngravitySecurityActionProvider();
assert.strictEqual(provider.version, "1.2.0");
assert.strictEqual(provider.enableReceiptCache, true);
assert.strictEqual(typeof provider.clearReceiptCache, "function");

const actions = provider.getActions();
assert.ok(Array.isArray(actions) && actions.length === 7, `Expected 7 paid x402 actions, got ${actions ? actions.length : 0}`);
assert.ok(!actions.some((a) => a.name.includes("quick_check") || /\bFREE\b/i.test(a.description)), "Zero-free-leak violation");
assert.ok(!actions.some((a) => /Multicall3/i.test(a.description)), "Stale Multicall3 reference found in action description");

assert.ok(ingravityElizaPlugin && Array.isArray(ingravityElizaPlugin.actions) && ingravityElizaPlugin.actions.length === 3);

// ERC-8021 idempotent calldata attribution test
const tagged = encodeErc8021Calldata("0x095ea7b3");
assert.ok(tagged.endsWith(ERC8021_SUFFIX_HEX), "ERC-8021 suffix missing");
assert.strictEqual(encodeErc8021Calldata(tagged), tagged, "ERC-8021 suffix must not double-append");

// Strict PayAI x402 v2 accept sanitization test
const sanitized = sanitizeX402V2Accept({
  scheme: "exact",
  network: "eip155:8453",
  amount: "100000",
  maxAmountRequired: "100000",
  payTo: "0xAA99e12320a3db0116ef56D2e19F70f6796Bad0f"
});
assert.strictEqual(Object.prototype.hasOwnProperty.call(sanitized, "maxAmountRequired"), false, "maxAmountRequired must be stripped");
assert.strictEqual(sanitized.amount, "100000");

// Test cache key stability
const k1 = provider._computeCacheKey("/api/v1/tx-firewall", { ticketId: "TICKET-8453-ABCD1234", to: "0x1", data: "0x09" });
const k2 = provider._computeCacheKey("/api/v1/tx-firewall?ticketId=TICKET-8453-ABCD1234", { ticketId: "ticket-8453-abcd1234" });
assert.strictEqual(k1, k2, "Receipt cache key should normalize ticketId & route pathname");

console.log(`[TEST PASSED] v${SDK_VERSION}: ${actions.length} paid actions, ${ingravityElizaPlugin.actions.length} Eliza actions, ERC-8021 helper, x402 v2 sanitizer & MCP STDIO bridge verified.`);
process.exit(0);
