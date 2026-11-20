const assert = require("assert");
const fs = require("fs");
const path = require("path");
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

assert.strictEqual(SDK_VERSION, "1.3.2", "SDK_VERSION must be 1.3.2");
assert.ok(IngravitySecurityActionProvider, "IngravitySecurityActionProvider must be exported");
assert.ok(ingravityElizaPlugin, "ingravityElizaPlugin must be exported");
assert.strictEqual(ERC8021_BUILDER_CODE, "bc_i26d7owr");
assert.strictEqual(typeof forwardMcpLine, "function", "mcp.js forwardMcpLine must be exported");
assert.ok(MCP_ENDPOINT_URL.endsWith("/mcp"), "MCP_ENDPOINT_URL must point to /mcp");

const provider = new IngravitySecurityActionProvider();
assert.strictEqual(provider.version, "1.3.2");
assert.strictEqual(provider.enableReceiptCache, true);
assert.strictEqual(typeof provider.clearReceiptCache, "function");

const actions = provider.getActions();
assert.ok(Array.isArray(actions) && actions.length === 7, `Expected 7 paid x402 actions, got ${actions ? actions.length : 0}`);
assert.ok(actions[0].description.includes("$0.01"), "Fast-Ping action must advertise $0.01 floor");
assert.ok(actions[1].schema.properties.chainId && actions[1].schema.properties.tier, "txFirewall schema must expose chainId and tier");
assert.ok(actions[6].schema.properties.chainId && actions[6].schema.properties.tier && actions[6].schema.properties.targetId, "deepExploitBounty schema must expose chainId, tier, targetId");
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

// Glama ownership claim persistence regression guard (must stay unauthenticated, redirect-free & before MCP/x402)
const glamaJsonPath = path.join(__dirname, "..", "glama.json");
const glamaDoc = JSON.parse(fs.readFileSync(glamaJsonPath, "utf8"));
assert.deepStrictEqual(Object.keys(glamaDoc).sort(), ["$schema", "claim"], "glama.json must expose strictly $schema and claim");
assert.strictEqual(glamaDoc.$schema, "https://glama.ai/mcp/schemas/connector.json");
assert.strictEqual(glamaDoc.claim, "glama_claim_pjiva77l14yvBRsvuPceWrW_WkeG3pCY");

const workerSrc = fs.readFileSync(path.join(__dirname, "..", "worker_x402_autonomo.js"), "utf8");
assert.ok(workerSrc.includes("const GLAMA_OWNERSHIP_CLAIM = Object.freeze("), "GLAMA_OWNERSHIP_CLAIM must remain frozen at top level");
assert.ok(workerSrc.includes(glamaDoc.claim), "Worker must retain verified Glama ownership claim token");
const fetchStart = workerSrc.indexOf("async function handleFetchRequest(");
const claimIdx = workerSrc.indexOf('"/mcp/.well-known/glama.json"', fetchStart);
const rootClaimIdx = workerSrc.indexOf('"/.well-known/glama.json"', fetchStart);
const internalSyncIdx = workerSrc.indexOf('"/api/v1/internal/sync-vault"', fetchStart);
const mcpIdx = workerSrc.indexOf('url.pathname === "/mcp"', fetchStart);
assert.ok(fetchStart > 0 && claimIdx > fetchStart && rootClaimIdx > fetchStart, "Both Glama verification paths must be routed in handleFetchRequest");
assert.ok(claimIdx < internalSyncIdx && claimIdx < mcpIdx, "Glama ownership claim must execute BEFORE auth-gated internal routes, /mcp, and x402 paywalls");

// Compact PAYMENT-REQUIRED HTTP header & v3.13.2 Swarm conversion guards
assert.ok(workerSrc.includes('const SWARM_VERSION = "3.13.2"'), "Worker must declare SWARM_VERSION = 3.13.2");
assert.ok(!workerSrc.includes("open-source engine code on GitHub"), "IP guard: must not claim proprietary engine is open-source");
assert.ok(workerSrc.includes("open-source SDK &amp; verifiable manifests on GitHub"), "IP guard: must state open-source SDK & verifiable manifests");
assert.ok(workerSrc.includes("ttlSeconds: 48 * 3600"), "Canary trial TTL must default to 48 hours");
assert.ok(workerSrc.includes("function getCapitalBandFloorUsd("), "Side-channel guard: must define getCapitalBandFloorUsd");
assert.ok(workerSrc.includes("function validateSignedPaymentTerms("), "x402 guard: must validate payTo, asset and amount server-side");
assert.ok(workerSrc.includes("function buildEip3009SigningDiagnostics("), "x402 guard: must emit EIP-3009 signing diagnostics");

// Official MCP Registry 1.3.2 coherence guards
const pkgDoc = JSON.parse(fs.readFileSync(path.join(__dirname, "package.json"), "utf8"));
const sdkServerDoc = JSON.parse(fs.readFileSync(path.join(__dirname, "server.json"), "utf8"));
const rootServerDoc = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "mcp_registry_server.json"), "utf8"));
assert.strictEqual(pkgDoc.version, "1.3.2", "package.json version must be 1.3.2");
assert.strictEqual(pkgDoc.mcpName, "io.github.DMS1979/ingravity-security", "package.json must declare mcpName");
assert.strictEqual(sdkServerDoc.version, "1.3.2", "sdk server.json version must be 1.3.2");
assert.strictEqual(sdkServerDoc.packages[0].version, "1.3.2", "sdk server.json npm package version must be 1.3.2");
assert.deepStrictEqual(sdkServerDoc, rootServerDoc, "sdk server.json and mcp_registry_server.json must be identical");
assert.ok(workerSrc.includes('usdPrice: "0.01"') && (workerSrc.includes('atomicAmount: "10000"') || workerSrc.includes('amount: "10000"')), "Fast-Ping must use $0.01 (10000 atomic USDC)");
assert.ok(workerSrc.includes("function normalizeCaip2Network("), "Worker must normalize CAIP-2 network aliases to eip155:8453");
assert.ok(workerSrc.includes("function encodeCompactPaymentRequiredHeader("), "Worker must define encodeCompactPaymentRequiredHeader helper");
assert.ok(workerSrc.includes("maxB64Len = 6400") && workerSrc.includes("level = 0") && workerSrc.includes("level === 1"), "Compact header encoder must attempt exact level=0 up to 6400 chars and preserve accepts at level=1");
assert.ok(!workerSrc.includes("utf8ToB64(JSON.stringify(paymentRequiredV2))"), "HTTP /api/v1/* must use encodeCompactPaymentRequiredHeader, not raw full paymentRequiredV2");
assert.ok(!workerSrc.includes("utf8ToB64(JSON.stringify(paymentRequiredA2A))"), "A2A /a2a must use encodeCompactPaymentRequiredHeader, not raw full paymentRequiredA2A");
assert.ok(!workerSrc.includes("utf8ToB64(JSON.stringify(challenge))"), "Deprecated quick-check must use encodeCompactPaymentRequiredHeader");

// Punto 2 & 3 conversion, schema, telemetry & echo-farm guards
const prospectorSrc = fs.readFileSync(path.join(__dirname, "..", "prospeccion_agentes_base.js"), "utf8");
assert.ok(
  !workerSrc.includes('price: {\n                mode: "hybrid"') && !workerSrc.includes('price: { mode: "hybrid"'),
  "OpenAPI /openapi.json x-payment-info.price must use fixed/dynamic (not hybrid)"
);
assert.ok(workerSrc.includes('"x-pricing-policy"') && workerSrc.includes('mode: "dynamic"'), "OpenAPI must declare valid dynamic/fixed pricing and x-pricing-policy");
assert.ok(workerSrc.includes('property="og:image"') || workerSrc.includes("og:image"), "Landing HTML must emit og:image metadata");
assert.ok(workerSrc.includes('field === "x402SettleSucceeded"'), "recordSettlementFunnel must force-flush on x402SettleSucceeded");
assert.ok(workerSrc.includes('assetTransferMethod: "eip3009"'), "Payment challenges must declare assetTransferMethod eip3009");
assert.ok(workerSrc.includes("permit2Authorization"), "Worker must support Permit2 authorization amount/payer extraction");
assert.ok(workerSrc.includes("ECHO_FARM_HOST_RE") && workerSrc.includes("agentdiet\\.dev"), "Worker must filter agentdiet.dev echo-farm hosts");
assert.ok(prospectorSrc.includes("LOW_YIELD_OUTCOME_COOLDOWN_MS") && prospectorSrc.includes("agentdiet\\.dev"), "Prospector must exclude agentdiet.dev and apply low-yield cooldown");
const compactLvl2Idx = workerSrc.indexOf("function buildCompactPaymentChallengeForHeader(");
const compactLvl2Slice = workerSrc.slice(compactLvl2Idx, compactLvl2Idx + 6200);
assert.ok(compactLvl2Slice.includes("level <= 2"), "Compact header Levels 1-2 must preserve accepts byte-identically to 402 JSON body");
assert.ok(compactLvl2Slice.includes("output: {\n              type: \"object\"") || compactLvl2Slice.includes("output: { type: \"object\""), "Compact header Level 2 must preserve schema.properties.output for extractSchemas2");

console.log(`[TEST PASSED] v${SDK_VERSION}: ${actions.length} paid actions ($0.01 Fast-Ping), ${ingravityElizaPlugin.actions.length} Eliza actions, ERC-8021 helper, x402 v2 sanitizer, MCP STDIO bridge, immutable Glama claim & v3.13.2 guards verified.`);
process.exit(0);
