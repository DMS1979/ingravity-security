const assert = require("assert");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { ethers } = require("ethers");
const {
  IngravitySecurityActionProvider,
  ingravityElizaPlugin,
  encodeErc8021Calldata,
  sanitizeX402V2Accept,
  createEip3009PrivateKeySigner,
  deriveAddressFromPrivateKey,
  keccak256Hex,
  BASE_USDC_CONTRACT,
  BASE_CHAIN_ID,
  ERC8021_BUILDER_CODE,
  ERC8021_SUFFIX_HEX,
  SDK_VERSION
} = require("./index.js");
const { forwardMcpLine, runCliCommand, MCP_ENDPOINT_URL } = require("./mcp.js");

console.log(`[TEST] Testing Ingravity Security SDK v${SDK_VERSION} exports...`);

assert.strictEqual(SDK_VERSION, "1.3.6", "SDK_VERSION must be 1.3.6");
assert.ok(IngravitySecurityActionProvider, "IngravitySecurityActionProvider must be exported");
assert.ok(ingravityElizaPlugin, "ingravityElizaPlugin must be exported");
assert.strictEqual(ERC8021_BUILDER_CODE, "bc_i26d7owr");
assert.strictEqual(typeof forwardMcpLine, "function", "mcp.js forwardMcpLine must be exported");
assert.ok(MCP_ENDPOINT_URL.endsWith("/mcp"), "MCP_ENDPOINT_URL must point to /mcp");

// 1. Cryptographic parity test against ethers v6 (Keccak-256, secp256k1 address & EIP-712 / EIP-3009 signature)
assert.strictEqual(
  keccak256Hex(Buffer.from("", "utf8")),
  "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
  "Empty Keccak-256 hash mismatch"
);
assert.strictEqual(
  keccak256Hex(Buffer.from("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)", "utf8")),
  ethers.id("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"),
  "EIP-3009 typeHash Keccak-256 mismatch vs ethers.id"
);

const TEST_PRIV_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ethersRefWallet = new ethers.Wallet(TEST_PRIV_KEY);
assert.strictEqual(deriveAddressFromPrivateKey(TEST_PRIV_KEY), ethersRefWallet.address, "secp256k1 address derivation mismatch vs ethers.Wallet");

const provider = new IngravitySecurityActionProvider();
assert.strictEqual(provider.version, "1.3.6");
assert.strictEqual(typeof provider.topupPass, "function");
assert.strictEqual(typeof runCliCommand, "function");
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

// Glama ownership claim persistence regression guard
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

// Official MCP Registry 1.3.6 (icons + websiteUrl) & npm 1.3.5 coherence + duplicate-key guard
const serverJsonRaw = fs.readFileSync(path.join(__dirname, "server.json"), "utf8");
assert.strictEqual((serverJsonRaw.match(/"version"\s*:/g) || []).length, 2, "server.json must have exactly 2 'version' keys (root + packages[0]), zero duplicates");
const pkgDoc = JSON.parse(fs.readFileSync(path.join(__dirname, "package.json"), "utf8"));
const sdkServerDoc = JSON.parse(serverJsonRaw);
const rootServerDoc = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "mcp_registry_server.json"), "utf8"));
const readmeDoc = fs.readFileSync(path.join(__dirname, "README.md"), "utf8");
assert.strictEqual(pkgDoc.version, "1.3.6", "package.json version must be 1.3.6");
assert.strictEqual(pkgDoc.mcpName, "io.github.DMS1979/ingravity-security", "package.json must declare mcpName");
assert.ok(pkgDoc.files.includes("server.json") && pkgDoc.files.includes("SKILL.md") && pkgDoc.files.includes("examples/"), "package.json files must ship server.json, SKILL.md, and examples/");
assert.strictEqual(sdkServerDoc.version, "1.3.7", "sdk server.json version must be 1.3.7");
assert.strictEqual(sdkServerDoc.packages[0].version, "1.3.6", "sdk server.json npm package version must be 1.3.6");
assert.strictEqual(sdkServerDoc.websiteUrl, "https://red-shape-1b3b.daviddelmoral79.workers.dev", "server.json must declare HTTPS websiteUrl");
assert.ok(Array.isArray(sdkServerDoc.icons) && sdkServerDoc.icons.length >= 1 && sdkServerDoc.icons[0].src === "https://red-shape-1b3b.daviddelmoral79.workers.dev/favicon.svg", "server.json must declare HTTPS icons");
assert.ok(sdkServerDoc.description.length <= 100 && sdkServerDoc.description.includes("$0.01"), "server.json description must be <=100 chars and highlight $0.01");
assert.deepStrictEqual(sdkServerDoc, rootServerDoc, "sdk server.json and mcp_registry_server.json must be identical");
assert.ok(readmeDoc.includes("wrapFetchWithPayment") && readmeDoc.includes("mcprush.com/badge") && readmeDoc.includes("/compact.svg"), "README.md must include 5-line x402 snippet and non-overlapping compact.svg mcprush badge");

// End-to-end Universal Wallet & MCP Auto-Pay + @x402/mcp _meta['x402/error'] verification
(async () => {
  // Verify built-in zero-dep EIP-3009 signature recovers to exact signer address via ethers.verifyTypedData
  const zeroDepSigner = createEip3009PrivateKeySigner(TEST_PRIV_KEY);
  const testDomain = { name: "USD Coin", version: "2", chainId: BASE_CHAIN_ID, verifyingContract: BASE_USDC_CONTRACT };
  const testTypes = {
    TransferWithAuthorization: [
      { name: "from", type: "address" },
      { name: "to", type: "address" },
      { name: "value", type: "uint256" },
      { name: "validAfter", type: "uint256" },
      { name: "validBefore", type: "uint256" },
      { name: "nonce", type: "bytes32" }
    ]
  };
  const testAuth = {
    from: ethersRefWallet.address,
    to: "0xAA99e12320a3db0116ef56D2e19F70f6796Bad0f",
    value: "10000",
    validAfter: "1700000000",
    validBefore: "1700000300",
    nonce: "0x" + "ab".repeat(32)
  };
  const zeroDepSig = await zeroDepSigner.signTypedData({ domain: testDomain, types: testTypes, message: testAuth });
  const recovered = ethers.verifyTypedData(testDomain, testTypes, testAuth, zeroDepSig);
  assert.strictEqual(recovered, ethersRefWallet.address, "Zero-dep EIP-3009 signature failed cryptographic recovery via ethers.verifyTypedData");

  let lastDecodedPayment = null;
  const mockChallenge = {
    x402Version: 2,
    resource: { url: "https://example.test/api/v1/fast-ping" },
    accepts: [
      {
        scheme: "exact",
        network: "eip155:8453",
        amount: "10000",
        asset: BASE_USDC_CONTRACT,
        payTo: "0xAA99e12320a3db0116ef56D2e19F70f6796Bad0f",
        maxTimeoutSeconds: 300,
        extra: { name: "USD Coin", version: "2", tier: "FULL" }
      }
    ]
  };
  const mockPaymentResp = { success: true, network: "eip155:8453", transaction: "0xmocktxhash123", payer: ethersRefWallet.address };

  const server = http.createServer((req, res) => {
    const payHdr = req.headers["payment-signature"];
    if (!payHdr) {
      res.writeHead(402, {
        "Content-Type": "application/json",
        "PAYMENT-REQUIRED": Buffer.from(JSON.stringify(mockChallenge), "utf8").toString("base64")
      });
      res.end(JSON.stringify(mockChallenge));
      return;
    }
    lastDecodedPayment = JSON.parse(Buffer.from(payHdr, "base64").toString("utf8"));
    res.writeHead(200, {
      "Content-Type": "application/json",
      "PAYMENT-RESPONSE": Buffer.from(JSON.stringify(mockPaymentResp), "utf8").toString("base64")
    });
    res.end(JSON.stringify({ status: "SAFE", verdict: "SAFE", action: "PROCEED", address: BASE_USDC_CONTRACT }));
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const mockApiUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    // Mode A: Raw privateKey in IngravitySecurityActionProvider
    const pPriv = new IngravitySecurityActionProvider({ workerUrl: mockApiUrl, privateKey: TEST_PRIV_KEY, maxSpendUsdc: 0.05, enableReceiptCache: false });
    const rPriv = await pPriv.fastPing({ address: BASE_USDC_CONTRACT, chainId: 8453 });
    assert.strictEqual(rPriv.verdict, "SAFE", "Raw privateKey auto-pay must succeed");
    assert.strictEqual(
      ethers.verifyTypedData(testDomain, testTypes, lastDecodedPayment.payload.authorization, lastDecodedPayment.payload.signature),
      ethersRefWallet.address
    );

    // Mode B: Ethers v6 Wallet (3-arg signTypedData)
    lastDecodedPayment = null;
    const pEthers = new IngravitySecurityActionProvider({ workerUrl: mockApiUrl, walletProvider: ethersRefWallet, maxSpendUsdc: 0.05, enableReceiptCache: false });
    const rEthers = await pEthers.fastPing({ address: BASE_USDC_CONTRACT, chainId: 8453 });
    assert.strictEqual(rEthers.verdict, "SAFE", "Ethers v6 Wallet auto-pay must succeed without TypeError");
    assert.strictEqual(
      ethers.verifyTypedData(testDomain, testTypes, lastDecodedPayment.payload.authorization, lastDecodedPayment.payload.signature),
      ethersRefWallet.address
    );

    // Mode C: Viem LocalAccount ({ address, signTypedData({ domain, types, primaryType, message }) })
    lastDecodedPayment = null;
    const mockViemAccount = {
      address: ethersRefWallet.address,
      signTypedData: async ({ domain, types, message }) => ethersRefWallet.signTypedData(domain, types, message)
    };
    const pViemAcc = new IngravitySecurityActionProvider({ workerUrl: mockApiUrl, walletProvider: mockViemAccount, maxSpendUsdc: 0.05, enableReceiptCache: false });
    const rViemAcc = await pViemAcc.fastPing({ address: BASE_USDC_CONTRACT, chainId: 8453 });
    assert.strictEqual(rViemAcc.verdict, "SAFE", "Viem LocalAccount auto-pay must succeed");

    // Mode D: Viem WalletClient ({ account: { address }, signTypedData({ account, domain, ... }) })
    lastDecodedPayment = null;
    const mockViemClient = {
      account: { address: ethersRefWallet.address },
      signTypedData: async ({ account, domain, types, message }) => {
        assert.strictEqual(account.address, ethersRefWallet.address);
        return ethersRefWallet.signTypedData(domain, types, message);
      }
    };
    const pViemCli = new IngravitySecurityActionProvider({ workerUrl: mockApiUrl, walletProvider: mockViemClient, maxSpendUsdc: 0.05, enableReceiptCache: false });
    const rViemCli = await pViemCli.fastPing({ address: BASE_USDC_CONTRACT, chainId: 8453 });
    assert.strictEqual(rViemCli.verdict, "SAFE", "Viem WalletClient auto-pay must succeed");

    // Mode E: 1-Command CLI Auto-Pay (`npx ingravity-security ping 0x...`)
    lastDecodedPayment = null;
    const cliPingRes = await runCliCommand(["ping", BASE_USDC_CONTRACT, "8453"], { apiUrl: mockApiUrl, privateKey: TEST_PRIV_KEY, maxSpendUsdc: 0.05 });
    assert.strictEqual(cliPingRes.verdict, "SAFE", "1-command CLI ping auto-pay must succeed");
    assert.strictEqual(
      ethers.verifyTypedData(testDomain, testTypes, lastDecodedPayment.payload.authorization, lastDecodedPayment.payload.signature),
      ethersRefWallet.address
    );

    // MCP 1: Unpaid call using snake_case alias must expose _meta['x402/error'] + isError: true
    const rawUnpaid = await forwardMcpLine(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 101,
        method: "tools/call",
        params: {
          name: "ingravity_fast_ping",
          arguments: { address: BASE_USDC_CONTRACT, chainId: 8453 }
        }
      }),
      { apiUrl: mockApiUrl }
    );
    const unpaidResp = JSON.parse(rawUnpaid);
    assert.strictEqual(unpaidResp.result.isError, true, "Unpaid STDIO call must set isError: true");
    assert.strictEqual(unpaidResp.result.structuredContent.x402Version, 2);
    assert.ok(unpaidResp.result._meta && unpaidResp.result._meta["x402/error"], "Unpaid STDIO 402 must expose _meta['x402/error'] for @x402/mcp");

    // MCP 2: Automatic local EIP-3009 signing via options.privateKey / INGRAVITY_PRIVATE_KEY within budget
    lastDecodedPayment = null;
    const rawAutoPaid = await forwardMcpLine(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 102,
        method: "tools/call",
        params: {
          name: "ingravity_fast_ping",
          arguments: { address: BASE_USDC_CONTRACT, chainId: 8453 }
        }
      }),
      { apiUrl: mockApiUrl, privateKey: TEST_PRIV_KEY, budget: "0.05" }
    );
    const autoPaidResp = JSON.parse(rawAutoPaid);
    assert.strictEqual(autoPaidResp.result.isError, undefined, "Auto-signed MCP call must succeed");
    assert.strictEqual(autoPaidResp.result.structuredContent.verdict, "SAFE");
    assert.strictEqual(autoPaidResp.result._meta["x402/payment-response"].transaction, "0xmocktxhash123");
    assert.strictEqual(
      ethers.verifyTypedData(testDomain, testTypes, lastDecodedPayment.payload.authorization, lastDecodedPayment.payload.signature),
      ethersRefWallet.address
    );

    // MCP 3: Budget cap guard — must NOT sign when challenge ($0.01) exceeds configured budget ($0.005)
    lastDecodedPayment = null;
    const rawOverBudget = await forwardMcpLine(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 103,
        method: "tools/call",
        params: {
          name: "ingravity_fastPingAddressSafety",
          arguments: { address: BASE_USDC_CONTRACT, chainId: 8453 }
        }
      }),
      { apiUrl: mockApiUrl, privateKey: TEST_PRIV_KEY, budget: "0.005" }
    );
    const overBudgetResp = JSON.parse(rawOverBudget);
    assert.strictEqual(overBudgetResp.result.isError, true, "Over-budget call must refuse auto-signing");
    assert.strictEqual(lastDecodedPayment, null, "Over-budget call must not transmit signature");
  } finally {
    server.close();
  }

  console.log(`[TEST PASSED] v${SDK_VERSION}: Zero-dep EIP-3009 cryptography verified vs ethers.Wallet, Viem/Ethers/AgentKit/privateKey universal adapter, MCP auto-pay + _meta['x402/error'] + snake_case aliases, & clean server.json verified.`);
  process.exit(0);
})().catch((err) => {
  console.error("[TEST FAILED]", err);
  process.exit(1);
});
