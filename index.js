/**
 * INGRAVITY SECURITY SDK (ingravity-security) v1.3.5
 * -----------------------------------------------------------------------
 * Autonomous 5-EVM Web3 Security, $0.01 Fast-Ping, Pre-Flight Transaction Firewall,
 * Live EVM RPC Token Honeypot Scanner, ERC-8021 Attribution & Atomic EIP-5792
 * Safe-Harbor Rescue Provider for Coinbase AgentKit, Viem, Ethers v5/v6, ElizaOS,
 * LangChain & MCP on Base (8453), Arbitrum (42161), Optimism (10), Polygon (137), and Ethereum (1).
 *
 * Official x402 v2 Catalog (Swarm v3.14.0):
 *  - Zero Free Verdict Leaks: 100% deterministic paid x402 v2 endpoints
 *  - Zero-Dependency EIP-3009 Signer + Universal Viem / Ethers / AgentKit Adapter
 *  - Settlement Network: Base Mainnet (eip155:8453)
 *  - Payee (Trust Wallet): 0xAA99e12320a3db0116ef56D2e19F70f6796Bad0f
 *  - Settlement Asset: Native USDC (0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)
 *  - Builder Code: bc_i26d7owr (ERC-8021)
 */

const crypto = require("crypto");

const WORKER_ENDPOINT = "https://red-shape-1b3b.daviddelmoral79.workers.dev";
const PAY_TO_WALLET = "0xAA99e12320a3db0116ef56D2e19F70f6796Bad0f";
const BASE_USDC_CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const BASE_CHAIN_ID = 8453;
const ERC8021_BUILDER_CODE = "bc_i26d7owr";
const ERC8021_SUFFIX_HEX = "0b62635f69323664376f77720080218021802180218021802180218021";
const SDK_VERSION = "1.3.5";

// ============================================================================
// 0. ZERO-DEPENDENCY ETHEREUM KECCAK-256 + SECP256K1 + EIP-3009 SIGNER
// ============================================================================
const MASK64 = 0xffffffffffffffffn;
const KECCAK_RC = new Array(24);
const KECCAK_ROTC = new Array(24);
const KECCAK_PI = new Array(24);

(function initKeccakTables() {
  let r = 1;
  for (let round = 0; round < 24; round++) {
    let rc = 0n;
    for (let j = 0; j < 7; j++) {
      if (r & 1) rc |= 1n << BigInt((1 << j) - 1);
      r = ((r << 1) ^ ((r >> 7) * 0x71)) & 0xff;
    }
    KECCAK_RC[round] = rc;
  }
  let x = 1;
  let y = 0;
  for (let t = 0; t < 24; t++) {
    const ny = (2 * x + 3 * y) % 5;
    x = y;
    y = ny;
    KECCAK_PI[t] = x + 5 * y;
    KECCAK_ROTC[t] = (((t + 1) * (t + 2)) / 2) % 64;
  }
})();

function rotl64(v, n) {
  if (n === 0) return v;
  const s = BigInt(n);
  return ((v << s) | (v >> (64n - s))) & MASK64;
}

function keccak256Buffer(input) {
  const src = Buffer.isBuffer(input) ? input : Buffer.from(input);
  const rate = 136;
  const rem = src.length % rate;
  const padLen = rate - rem;
  const msg = Buffer.alloc(src.length + padLen);
  src.copy(msg, 0);
  msg[src.length] = 0x01; // Original Ethereum Keccak-256 padding (NOT SHA3 0x06)
  msg[msg.length - 1] |= 0x80;

  const state = new BigUint64Array(25);
  const bc = new BigUint64Array(5);

  for (let offset = 0; offset < msg.length; offset += rate) {
    for (let i = 0; i < 17; i++) {
      state[i] ^= msg.readBigUInt64LE(offset + i * 8);
    }
    for (let round = 0; round < 24; round++) {
      for (let i = 0; i < 5; i++) {
        bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
      }
      for (let i = 0; i < 5; i++) {
        const t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
        for (let j = 0; j < 25; j += 5) state[j + i] ^= t;
      }
      let cur = state[1];
      for (let t = 0; t < 24; t++) {
        const idx = KECCAK_PI[t];
        const tmp = state[idx];
        state[idx] = rotl64(cur, KECCAK_ROTC[t]);
        cur = tmp;
      }
      for (let j = 0; j < 25; j += 5) {
        const s0 = state[j], s1 = state[j + 1], s2 = state[j + 2], s3 = state[j + 3], s4 = state[j + 4];
        state[j] = s0 ^ ((~s1 & MASK64) & s2);
        state[j + 1] = s1 ^ ((~s2 & MASK64) & s3);
        state[j + 2] = s2 ^ ((~s3 & MASK64) & s4);
        state[j + 3] = s3 ^ ((~s4 & MASK64) & s0);
        state[j + 4] = s4 ^ ((~s0 & MASK64) & s1);
      }
      state[0] ^= KECCAK_RC[round];
    }
  }

  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    out.writeBigUInt64LE(state[i], i * 8);
  }
  return out;
}

function keccak256Hex(input) {
  return "0x" + keccak256Buffer(input).toString("hex");
}

const SECP_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP_HALF_N = SECP_N >> 1n;
const SECP_GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const SECP_GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

function modPos(a, m) {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function modInv(a, m) {
  let t = 0n, newT = 1n;
  let r = m, newR = modPos(a, m);
  while (newR !== 0n) {
    const q = r / newR;
    const tmpT = t - q * newT; t = newT; newT = tmpT;
    const tmpR = r - q * newR; r = newR; newR = tmpR;
  }
  if (r !== 1n) throw new Error("Non-invertible scalar");
  return t < 0n ? t + m : t;
}

function jacDouble(p) {
  const [X1, Y1, Z1] = p;
  if (Z1 === 0n || Y1 === 0n) return [0n, 1n, 0n];
  const Y1Sq = modPos(Y1 * Y1, SECP_P);
  const S = modPos(4n * X1 * Y1Sq, SECP_P);
  const M = modPos(3n * X1 * X1, SECP_P);
  const X3 = modPos(M * M - 2n * S, SECP_P);
  const Y3 = modPos(M * (S - X3) - 8n * Y1Sq * Y1Sq, SECP_P);
  const Z3 = modPos(2n * Y1 * Z1, SECP_P);
  return [X3, Y3, Z3];
}

function jacAdd(p, q) {
  const [X1, Y1, Z1] = p;
  const [X2, Y2, Z2] = q;
  if (Z1 === 0n) return q;
  if (Z2 === 0n) return p;
  const Z1Sq = modPos(Z1 * Z1, SECP_P);
  const Z2Sq = modPos(Z2 * Z2, SECP_P);
  const U1 = modPos(X1 * Z2Sq, SECP_P);
  const U2 = modPos(X2 * Z1Sq, SECP_P);
  const S1 = modPos(Y1 * modPos(Z2Sq * Z2, SECP_P), SECP_P);
  const S2 = modPos(Y2 * modPos(Z1Sq * Z1, SECP_P), SECP_P);
  if (U1 === U2) {
    return S1 === S2 ? jacDouble(p) : [0n, 1n, 0n];
  }
  const H = modPos(U2 - U1, SECP_P);
  const R = modPos(S2 - S1, SECP_P);
  const HSq = modPos(H * H, SECP_P);
  const HCube = modPos(H * HSq, SECP_P);
  const U1HSq = modPos(U1 * HSq, SECP_P);
  const X3 = modPos(R * R - HCube - 2n * U1HSq, SECP_P);
  const Y3 = modPos(R * (U1HSq - X3) - S1 * HCube, SECP_P);
  const Z3 = modPos(H * Z1 * Z2, SECP_P);
  return [X3, Y3, Z3];
}

function secpScalarMulBase(k) {
  let scalar = modPos(k, SECP_N);
  if (scalar === 0n) throw new Error("Invalid zero scalar");
  let res = [0n, 1n, 0n];
  let addend = [SECP_GX, SECP_GY, 1n];
  while (scalar > 0n) {
    if (scalar & 1n) res = jacAdd(res, addend);
    addend = jacDouble(addend);
    scalar >>= 1n;
  }
  const invZ = modInv(res[2], SECP_P);
  const invZ2 = modPos(invZ * invZ, SECP_P);
  const invZ3 = modPos(invZ2 * invZ, SECP_P);
  return [modPos(res[0] * invZ2, SECP_P), modPos(res[1] * invZ3, SECP_P)];
}

function toChecksumAddress(rawHexLower40) {
  const clean = rawHexLower40.replace(/^0x/i, "").toLowerCase();
  const hashHex = keccak256Buffer(Buffer.from(clean, "utf8")).toString("hex");
  let out = "0x";
  for (let i = 0; i < 40; i++) {
    out += parseInt(hashHex[i], 16) >= 8 ? clean[i].toUpperCase() : clean[i];
  }
  return out;
}

function deriveAddressFromPrivateKey(privateKeyHex) {
  const clean = String(privateKeyHex || "").trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
    throw new Error("Invalid EVM private key: expected 32-byte (64 hex chars) key");
  }
  const privInt = BigInt("0x" + clean);
  if (privInt <= 0n || privInt >= SECP_N) {
    throw new Error("Private key scalar out of secp256k1 curve range");
  }
  const [px, py] = secpScalarMulBase(privInt);
  const pubBuf = Buffer.concat([
    Buffer.from(px.toString(16).padStart(64, "0"), "hex"),
    Buffer.from(py.toString(16).padStart(64, "0"), "hex")
  ]);
  const addrLower = keccak256Buffer(pubBuf).subarray(12).toString("hex");
  return toChecksumAddress(addrLower);
}

function rfc6979SignDigest(digestBuf, privHexClean) {
  const privBuf = Buffer.from(privHexClean, "hex");
  const d = BigInt("0x" + privHexClean);
  const z = BigInt("0x" + digestBuf.toString("hex"));

  // RFC 6979 HMAC-DRBG (SHA-256)
  let v = Buffer.alloc(32, 0x01);
  let kHmac = Buffer.alloc(32, 0x00);
  kHmac = crypto.createHmac("sha256", kHmac).update(Buffer.concat([v, Buffer.from([0x00]), privBuf, digestBuf])).digest();
  v = crypto.createHmac("sha256", kHmac).update(v).digest();
  kHmac = crypto.createHmac("sha256", kHmac).update(Buffer.concat([v, Buffer.from([0x01]), privBuf, digestBuf])).digest();
  v = crypto.createHmac("sha256", kHmac).update(v).digest();

  while (true) {
    v = crypto.createHmac("sha256", kHmac).update(v).digest();
    const k = BigInt("0x" + v.toString("hex"));
    if (k >= 1n && k < SECP_N) {
      const [rx, ry] = secpScalarMulBase(k);
      const r = rx % SECP_N;
      if (r !== 0n) {
        let recId = Number(ry & 1n) | (rx >= SECP_N ? 2 : 0);
        let s = modPos(modInv(k, SECP_N) * modPos(z + r * d, SECP_N), SECP_N);
        if (s !== 0n) {
          if (s > SECP_HALF_N) {
            s = SECP_N - s;
            recId ^= 1;
          }
          const rHex = r.toString(16).padStart(64, "0");
          const sHex = s.toString(16).padStart(64, "0");
          const vHex = (27 + recId).toString(16).padStart(2, "0");
          return "0x" + rHex + sHex + vHex;
        }
      }
    }
    kHmac = crypto.createHmac("sha256", kHmac).update(Buffer.concat([v, Buffer.from([0x00])])).digest();
    v = crypto.createHmac("sha256", kHmac).update(v).digest();
  }
}

function abiWordUint(val) {
  const bi = BigInt(val);
  if (bi < 0n) throw new Error("Negative uint256 in EIP-712 encoding");
  return Buffer.from(bi.toString(16).padStart(64, "0"), "hex");
}

function abiWordAddress(addr) {
  const clean = String(addr || "").trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(clean)) throw new Error(`Invalid EIP-712 address: ${addr}`);
  return Buffer.from(clean.padStart(64, "0"), "hex");
}

function abiWordBytes32(b32) {
  const clean = String(b32 || "").trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) throw new Error(`Invalid EIP-712 bytes32: ${b32}`);
  return Buffer.from(clean, "hex");
}

const EIP712_DOMAIN_TYPEHASH = keccak256Buffer(
  Buffer.from("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)", "utf8")
);
const EIP3009_TRANSFER_AUTH_TYPEHASH = keccak256Buffer(
  Buffer.from("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)", "utf8")
);

function hashEip3009TransferWithAuthorization(domain, message) {
  const domainSep = keccak256Buffer(
    Buffer.concat([
      EIP712_DOMAIN_TYPEHASH,
      keccak256Buffer(Buffer.from(String(domain.name || "USD Coin"), "utf8")),
      keccak256Buffer(Buffer.from(String(domain.version || "2"), "utf8")),
      abiWordUint(domain.chainId != null ? domain.chainId : BASE_CHAIN_ID),
      abiWordAddress(domain.verifyingContract || BASE_USDC_CONTRACT)
    ])
  );
  const structHash = keccak256Buffer(
    Buffer.concat([
      EIP3009_TRANSFER_AUTH_TYPEHASH,
      abiWordAddress(message.from),
      abiWordAddress(message.to),
      abiWordUint(message.value),
      abiWordUint(message.validAfter),
      abiWordUint(message.validBefore),
      abiWordBytes32(message.nonce)
    ])
  );
  return keccak256Buffer(Buffer.concat([Buffer.from([0x19, 0x01]), domainSep, structHash]));
}

function createEip3009PrivateKeySigner(privateKeyHex) {
  const clean = String(privateKeyHex || "").trim().replace(/^0x/i, "");
  const address = deriveAddressFromPrivateKey(clean);
  return {
    address,
    getAddress: async () => address,
    signTypedData: async (typedDataOrDomain, maybeTypes, maybeValue) => {
      const domain = maybeValue ? typedDataOrDomain : typedDataOrDomain.domain;
      const message = maybeValue ? maybeValue : typedDataOrDomain.message;
      const digest = hashEip3009TransferWithAuthorization(domain, message);
      return rfc6979SignDigest(digest, clean);
    }
  };
}

function parseChainIdFromCaip2(networkStr) {
  const m = String(networkStr || "").match(/^eip155:(\d+)$/i);
  return m ? Number(m[1]) : BASE_CHAIN_ID;
}

async function signWithUniversalWallet(wp, typedDataPayload) {
  if (!wp) return null;
  const { domain, types, primaryType, message } = typedDataPayload;

  // 1. Viem WalletClient ({ account: { address }, signTypedData })
  if (wp.account && typeof wp.account.address === "string" && typeof wp.signTypedData === "function") {
    const signature = await wp.signTypedData({
      account: wp.account,
      domain,
      types,
      primaryType,
      message
    });
    return { from: wp.account.address, signature };
  }

  // 2. Viem LocalAccount ({ address: "0x...", signTypedData })
  if (typeof wp.address === "string" && /^0x[0-9a-fA-F]{40}$/.test(wp.address) && typeof wp.signTypedData === "function" && typeof wp.getAddress !== "function") {
    const signature = await wp.signTypedData({ domain, types, primaryType, message });
    return { from: wp.address, signature };
  }

  // 3. Ethers v5 Signer (_signTypedData(domain, types, value))
  if (typeof wp._signTypedData === "function" && typeof wp.getAddress === "function") {
    const from = await wp.getAddress();
    const signature = await wp._signTypedData(domain, types, message);
    return { from, signature };
  }

  // 4. Ethers v6 Signer vs Coinbase AgentKit EvmWalletProvider
  if (typeof wp.signTypedData === "function" && typeof wp.getAddress === "function") {
    const from = await wp.getAddress();
    if (wp.signTypedData.length >= 3 || "_signingKey" in wp || ("provider" in wp && typeof wp.connect === "function")) {
      const signature = await wp.signTypedData(domain, types, message);
      return { from, signature };
    }
    try {
      const signature = await wp.signTypedData({ domain, types, primaryType, message });
      return { from, signature };
    } catch (err) {
      if (err instanceof TypeError || /undefined|null|types/i.test(String(err && err.message))) {
        const signature = await wp.signTypedData(domain, types, message);
        return { from, signature };
      }
      throw err;
    }
  }

  return null;
}

function encodeErc8021Calldata(calldataHex = "0x") {
  const clean = String(calldataHex || "0x").trim();
  const normalized = clean.startsWith("0x") || clean.startsWith("0X") ? clean.slice(2) : clean;
  if (!/^[0-9a-fA-F]*$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new Error("Invalid hex calldata passed to encodeErc8021Calldata");
  }
  const lower = normalized.toLowerCase();
  if (lower.endsWith(ERC8021_SUFFIX_HEX)) {
    return "0x" + lower;
  }
  return "0x" + lower + ERC8021_SUFFIX_HEX;
}

function sanitizeX402V2Accept(accept) {
  if (!accept || typeof accept !== "object") return accept;
  const { maxAmountRequired, ...cleanAccept } = accept;
  return cleanAccept;
}

// ============================================================================
// 1. COINBASE AGENTKIT, VIEM, ETHERS, LANGCHAIN & STANDALONE M2M PROVIDER
// ============================================================================
class IngravitySecurityActionProvider {
  constructor(config = {}) {
    this.name = "ingravity_security";
    this.version = SDK_VERSION;
    this.workerUrl = (config.workerUrl || WORKER_ENDPOINT).replace(/\/$/, "");
    this.payToWallet = config.payToWallet || PAY_TO_WALLET;
    this.walletProvider = config.walletProvider || (config.privateKey ? createEip3009PrivateKeySigner(config.privateKey) : null);
    this.maxSpendUsdc = config.maxSpendUsdc != null ? Number(config.maxSpendUsdc) : null;
    this.capitalAtRiskUsd = config.capitalAtRiskUsd != null ? Number(config.capitalAtRiskUsd) : null;
    this.enableReceiptCache = config.enableReceiptCache !== false;
    this._receiptCache = new Map();
  }

  clearReceiptCache() {
    this._receiptCache.clear();
  }

  _computeCacheKey(pathStr, body = {}) {
    const cleanPath = String(pathStr || "/").split("?")[0];
    let ticketFromQuery = "";
    try {
      const qIdx = String(pathStr || "").indexOf("?");
      if (qIdx >= 0) {
        const sp = new URLSearchParams(String(pathStr).slice(qIdx + 1));
        ticketFromQuery = sp.get("ticketId") || sp.get("targetId") || sp.get("victim") || sp.get("wallet") || "";
      }
    } catch (_) {}
    const targetCandidate =
      ticketFromQuery ||
      (body && (body.ticketId || body.targetId || body.victimWallet || body.tokenAddress || body.contractAddress || body.poolAddress || body.address || body.to)) ||
      "";
    if (targetCandidate) {
      return `${cleanPath}::${String(targetCandidate).trim().toLowerCase()}`;
    }
    const digest = crypto.createHash("sha256").update(JSON.stringify(body || {})).digest("hex").slice(0, 16);
    return `${cleanPath}::${digest}`;
  }

  getActions() {
    return [
      {
        name: "ingravity_fast_ping",
        description: "Ultra-low-cost binary SAFE/DANGER address gate across 5 EVM chains ($0.01 USDC flat via x402). Built for high-frequency bots with strict <=$0.05 auto-pay limits. Returns boolean SAFE/DANGER only (zero forensic details).",
        schema: {
          type: "object",
          properties: {
            address: { type: "string", description: "EVM contract, token, or spender address (0x...)" },
            chainId: { type: "integer", description: "EVM Chain ID (8453 Base, 42161 Arbitrum, 10 Optimism, 137 Polygon, 1 Ethereum; default: 8453)" }
          },
          required: ["address"]
        },
        invoke: async (params) => this.fastPing(params)
      },
      {
        name: "ingravity_tx_firewall",
        description: "Deep pre-sign 5-EVM transaction firewall via x402 ($0.10 USDC floor + 0.15% Pre-Flight / 5%-10% Whitehat Safe-Harbor Rescue, Anti-Bypass). Decodes calldata, inspects live EIP-1967/1167 proxy slots via RPC, and blocks wallet drainers & unlimited approvals before signing.",
        schema: {
          type: "object",
          properties: {
            to: { type: "string", description: "Target contract address (0x...)" },
            data: { type: "string", description: "Hexadecimal calldata (0x...)" },
            chainId: { type: "integer", description: "EVM Chain ID (8453 Base, 42161 Arbitrum, 10 Optimism, 137 Polygon, 1 Ethereum; default: 8453)" },
            tier: { type: "string", enum: ["FULL", "ESSENTIAL"], description: "Optional SLA tier (FULL or ESSENTIAL)" },
            from: { type: "string", description: "Optional sender wallet address (0x...)" },
            value: { type: "string", description: "Optional native ETH value in wei (default: '0')" },
            ticketId: { type: "string", description: "Optional ZK-EC Rescue Ticket ID (TICKET-8453-...)" },
            capitalAtRiskUsd: { type: "number", description: "Optional transaction value at risk in USD" }
          },
          required: ["to", "data"]
        },
        invoke: async (params) => this.txFirewall(params)
      },
      {
        name: "ingravity_token_rug_scanner",
        description: "Direct 5-EVM ERC-20 honeypot & rugpull forensic scanner by tokenAddress ($0.12 USDC Full Report / $0.04 USDC Signal Only via x402). Audits any EVM token directly by 0x address via live RPC bytecode disassembly & proxy storage slots — no Solidity source code required.",
        schema: {
          type: "object",
          properties: {
            tokenAddress: { type: "string", description: "EVM ERC-20 token address (0x...) — no .sol source required" },
            chainId: { type: "integer", description: "EVM Chain ID (8453 Base, 42161 Arbitrum, 10 Optimism, 137 Polygon, 1 Ethereum; default: 8453)" },
            tier: { type: "string", enum: ["FULL", "ESSENTIAL"], description: "Optional SLA tier (FULL or ESSENTIAL)" },
            code: { type: "string", description: "Optional Solidity (.sol) source code if auditing pre-deployment" },
            tokenName: { type: "string", description: "Optional token ticker or name" },
            capitalAtRiskUsd: { type: "number", description: "Optional swap position size in USD" }
          }
        },
        invoke: async (params) => this.tokenRugScanner(params)
      },
      {
        name: "ingravity_defi_math_guard",
        description: "Exact BigInt AMM slippage, MEV sandwich & leverage liquidation guard across 5 EVM chains via x402 ($0.10 USDC Full / $0.04 USDC Signal Only). 48-step binary search for mathematically provable minAmountOut.",
        schema: {
          type: "object",
          properties: {
            chainId: { type: "integer", description: "EVM Chain ID (default: 8453)" },
            tier: { type: "string", enum: ["FULL", "ESSENTIAL"], description: "Optional SLA tier (FULL or ESSENTIAL)" },
            capitalAtRiskUsd: { type: "number", description: "Optional swap/position value at risk in USD" },
            amm: {
              type: "object",
              properties: {
                reserveIn: { type: "string", description: "Pool input reserve in atomic units" },
                reserveOut: { type: "string", description: "Pool output reserve in atomic units" },
                amountIn: { type: "string", description: "Swap input amount in atomic units" },
                feeBps: { type: "integer", description: "Pool fee in bps (default: 30)" },
                userSlippageBps: { type: "integer", description: "Proposed slippage tolerance in bps" }
              },
              required: ["reserveIn", "reserveOut", "amountIn"]
            },
            leverage: { type: "object", description: "Optional leverage liquidation parameters" }
          }
        },
        invoke: async (params) => this.defiMathGuard(params)
      },
      {
        name: "ingravity_audit_solidity",
        description: "Deterministic 24-vector Solidity security audit & live EVM TVL Safe-Harbor protection ($0.85 USDC Full / $0.35 USDC Signal Only via x402). Includes line-by-line fixes plus optional atomic EIP-5792 wallet_sendCalls / sequential EOA Safe-Harbor rescue bundle (5%-10% split) when contractAddress holds live funds.",
        schema: {
          type: "object",
          properties: {
            code: { type: "string", description: "Raw Solidity (.sol) source code to audit" },
            contractName: { type: "string", description: "Optional contract filename" },
            contractAddress: { type: "string", description: "Optional deployed EVM contract address (0x...) for live TVL verification & Safe-Harbor rescue bundle" },
            chainId: { type: "integer", description: "EVM Chain ID (8453 Base, 42161 Arbitrum, 10 Optimism, 137 Polygon, 1 Ethereum; default: 8453)" },
            tier: { type: "string", enum: ["FULL", "ESSENTIAL"], description: "Optional SLA tier (FULL or ESSENTIAL)" },
            ownerTreasury: { type: "string", description: "Optional safe treasury recipient (0x...) for 90%-95% atomic Safe-Harbor sweep" },
            capitalAtRiskUsd: { type: "number", description: "Optional target/current TVL in USD" }
          },
          required: ["code"]
        },
        invoke: async (params) => this.auditSolidity(params)
      },
      {
        name: "ingravity_protocol_dossier",
        description: "Multi-contract DeFi protocol security dossier, cross-contract Read-Only Reentrancy graph & ERC-4626/Oracle invariant engine ($12.00 USDC Full / $3.50 USDC Signal Only via x402). Supports live EVM contractAddress TVL verification & Safe-Harbor rescue split.",
        schema: {
          type: "object",
          properties: {
            protocolName: { type: "string", description: "DeFi protocol name" },
            tvlTargetUsd: { type: "number", description: "Target or current TVL in USD" },
            contractAddress: { type: "string", description: "Optional live EVM vault/pool address (0x...) for on-chain liquidity verification" },
            chainId: { type: "integer", description: "EVM Chain ID (8453 Base, 42161 Arbitrum, 10 Optimism, 137 Polygon, 1 Ethereum; default: 8453)" },
            tier: { type: "string", enum: ["FULL", "ESSENTIAL"], description: "Optional SLA tier (FULL or ESSENTIAL)" },
            ownerTreasury: { type: "string", description: "Optional protocol multisig/treasury address (0x...)" },
            contracts: {
              type: "array",
              description: "Array of { name, code } Solidity contracts (up to 20 files)"
            }
          },
          required: ["contracts"]
        },
        invoke: async (params) => this.protocolDossier(params)
      },
      {
        name: "ingravity_deep_exploit_bounty",
        description: "Institutional flash-loan exploit vector simulation & Whitehat Safe-Harbor atomic rescue blueprint ($45.00 USDC Full / $9.50 USDC Triage via x402 + 5%-10% EIP-5792 wallet_sendCalls / Sequential EOA Safe-Harbor Rescue Split on saved capital).",
        schema: {
          type: "object",
          properties: {
            protocolName: { type: "string", description: "Target protocol identifier" },
            poolAddress: { type: "string", description: "Target EVM pool/vault address (0x...)" },
            chainId: { type: "integer", description: "EVM Chain ID (8453 Base, 42161 Arbitrum, 10 Optimism, 137 Polygon, 1 Ethereum; default: 8453)" },
            tier: { type: "string", enum: ["FULL", "ESSENTIAL"], description: "Optional SLA tier (FULL or ESSENTIAL)" },
            targetId: { type: "string", description: "Optional verified bounty/rescue target identifier" },
            ownerTreasury: { type: "string", description: "Optional protocol owner/multisig recipient for 90%-95% rescued funds" },
            tvlUsd: { type: "number", description: "Optional estimated pool TVL in USD (auto-verified on-chain when poolAddress is deployed)" },
            capitalAtRiskUsd: { type: "number", description: "Optional capital at risk in USD" },
            code: { type: "string", description: "Optional Solidity contract source code" }
          },
          required: ["protocolName"]
        },
        invoke: async (params) => this.deepExploitBounty(params)
      }
    ];
  }

  _cacheReceiptFromResponse(cacheKey, res, data) {
    if (!this.enableReceiptCache) return;
    const hdrTok = res && res.headers && typeof res.headers.get === "function" ? res.headers.get("X-Ingravity-Receipt-Token") : null;
    const tok = hdrTok || (data && typeof data.receiptToken === "string" ? data.receiptToken : null);
    if (tok) this._receiptCache.set(cacheKey, tok);
  }

  async _callEndpoint(path, body = {}, extraHeaders = {}) {
    const targetUrl = `${this.workerUrl}${path}`;
    const headers = { "Content-Type": "application/json", ...extraHeaders };
    const cacheKey = this._computeCacheKey(path, body);

    if (this.maxSpendUsdc != null) {
      headers["X-Agent-Budget"] = String(this.maxSpendUsdc);
    }

    const cap = (body && body.capitalAtRiskUsd != null)
      ? body.capitalAtRiskUsd
      : (body && body.transactionValueUsd != null ? body.transactionValueUsd : this.capitalAtRiskUsd);
    if (cap != null) {
      headers["X-Capital-At-Risk-Usd"] = String(cap);
    }

    const cachedReceipt = this.enableReceiptCache && !headers["X-Ingravity-Receipt-Token"]
      ? this._receiptCache.get(cacheKey)
      : null;
    if (cachedReceipt) {
      headers["X-Ingravity-Receipt-Token"] = cachedReceipt;
    }

    let res = await fetch(targetUrl, {
      method: "POST",
      headers,
      body: JSON.stringify(body)
    });

    if (res.ok) {
      const okJson = await res.json();
      this._cacheReceiptFromResponse(cacheKey, res, okJson);
      return okJson;
    }

    if (res.status === 402) {
      if (cachedReceipt) {
        this._receiptCache.delete(cacheKey);
        delete headers["X-Ingravity-Receipt-Token"];
      }
      let payReq = null;
      const payReqHeader = res.headers.get("PAYMENT-REQUIRED") || res.headers.get("X-Payment-Required");
      try {
        payReq = payReqHeader ? JSON.parse(Buffer.from(payReqHeader, "base64").toString("utf8")) : null;
      } catch (_) {}
      if (!payReq) payReq = await res.json();

      const accepts = (Array.isArray(payReq.accepts) && payReq.accepts.length ? payReq.accepts : [payReq]).map(sanitizeX402V2Accept);
      const budgetAtoms = this.maxSpendUsdc != null ? BigInt(Math.floor(this.maxSpendUsdc * 1e6 + 1e-6)) : null;
      const requestedTier = body && body.tier ? String(body.tier).trim().toUpperCase() : null;
      const affordable = budgetAtoms == null
        ? accepts
        : accepts.filter((a) => BigInt(a.amount) <= budgetAtoms);
      const accept = (requestedTier
        ? affordable.find((a) => String((a.extra && a.extra.tier) || "FULL").toUpperCase() === requestedTier)
        : null) || affordable[0] || null;

      const quote = {
        status: "402_PAYMENT_REQUIRED",
        costUsdc: Number((accept || accepts[0]).amount) / 1e6,
        costAtom: String((accept || accepts[0]).amount),
        availableTiers: accepts.map((a) => ({
          tier: (a.extra && a.extra.tier) || "FULL",
          amountUsdc: Number(a.amount) / 1e6,
          amountAtom: String(a.amount)
        })),
        destinationWallet: (accept || accepts[0]).payTo || this.payToWallet,
        network: (accept || accepts[0]).network || "eip155:8453",
        usdcToken: (accept || accepts[0]).asset || BASE_USDC_CONTRACT,
        paymentRequirements: payReq
      };
      if (!accept) return { ...quote, reason: "All available service tiers exceed your configured maxSpendUsdc budget" };

      const wp = this.walletProvider;
      if (wp) {
        const cleanAccept = sanitizeX402V2Accept(accept);
        const now = Math.floor(Date.now() / 1000);
        const settleChainId = parseChainIdFromCaip2(cleanAccept.network);
        const tempFrom =
          (wp.account && wp.account.address) ||
          (typeof wp.address === "string" ? wp.address : null) ||
          (typeof wp.getAddress === "function" ? await wp.getAddress() : null);

        if (tempFrom) {
          const authorization = {
            from: tempFrom,
            to: cleanAccept.payTo,
            value: String(cleanAccept.amount),
            validAfter: String(now - 60),
            validBefore: String(now + (cleanAccept.maxTimeoutSeconds || 300)),
            nonce: "0x" + crypto.randomBytes(32).toString("hex")
          };
          const signed = await signWithUniversalWallet(wp, {
            domain: {
              name: (cleanAccept.extra && cleanAccept.extra.name) || "USD Coin",
              version: (cleanAccept.extra && cleanAccept.extra.version) || "2",
              chainId: settleChainId,
              verifyingContract: cleanAccept.asset || BASE_USDC_CONTRACT
            },
            types: {
              TransferWithAuthorization: [
                { name: "from", type: "address" },
                { name: "to", type: "address" },
                { name: "value", type: "uint256" },
                { name: "validAfter", type: "uint256" },
                { name: "validBefore", type: "uint256" },
                { name: "nonce", type: "bytes32" }
              ]
            },
            primaryType: "TransferWithAuthorization",
            message: authorization
          });

          if (signed && signed.signature) {
            const paymentPayload = {
              x402Version: 2,
              accepted: cleanAccept,
              payload: { signature: signed.signature, authorization: { ...authorization, from: signed.from || tempFrom } }
            };
            const paidRes = await fetch(targetUrl, {
              method: "POST",
              headers: {
                ...headers,
                "PAYMENT-SIGNATURE": Buffer.from(JSON.stringify(paymentPayload)).toString("base64")
              },
              body: JSON.stringify(body)
            });
            if (paidRes.ok) {
              const paidJson = await paidRes.json();
              this._cacheReceiptFromResponse(cacheKey, paidRes, paidJson);
              return paidJson;
            }
            return { ...quote, status: "PAYMENT_REJECTED", httpStatus: paidRes.status, detail: await paidRes.text() };
          }
        }
      }

      return { ...quote, message: `Ingravity requires ${Number(accept.amount) / 1e6} USDC on Base via x402.` };
    }

    throw new Error(`Ingravity gateway error (${res.status}): ${await res.text()}`);
  }

  async fastPing(params = {}) {
    return this._callEndpoint("/api/v1/fast-ping", params);
  }

  // Backwards-compatible alias: routes legacy v1.0 callers directly to paid $0.01 Fast-Ping (zero free leaks)
  async quickCheck(params = {}) {
    const addr = params.address || params.to || params.tokenAddress;
    if (addr) return this.fastPing({ address: addr, chainId: params.chainId || 8453 });
    if (params.code) return this.auditSolidity(params);
    return this.txFirewall(params);
  }

  async txFirewall(params = {}) {
    let urlPath = "/api/v1/tx-firewall";
    if (params.ticketId) urlPath += `?ticketId=${encodeURIComponent(params.ticketId)}`;
    return this._callEndpoint(urlPath, params);
  }

  async tokenRugScanner(params = {}) {
    return this._callEndpoint("/api/v1/token-rug-scanner", params);
  }

  async defiMathGuard(params = {}) {
    const normalized = params.amm
      ? params
      : {
          amm: {
            reserveIn: String(params.reserveIn || "0"),
            reserveOut: String(params.reserveOut || "0"),
            amountIn: String(params.amountIn || "0"),
            feeBps: params.feeBps || 30,
            userSlippageBps: params.slippageTolerancePct != null ? Math.round(Number(params.slippageTolerancePct) * 100) : (params.userSlippageBps || 100)
          },
          ...(params.leverage ? { leverage: params.leverage } : {}),
          ...(params.chainId != null ? { chainId: params.chainId } : {}),
          ...(params.tier ? { tier: params.tier } : {}),
          ...(params.capitalAtRiskUsd != null ? { capitalAtRiskUsd: params.capitalAtRiskUsd } : {})
        };
    return this._callEndpoint("/api/v1/defi-math-guard", normalized);
  }

  async auditSolidity(params = {}) {
    return this._callEndpoint("/api/v1/audit-solidity", params);
  }

  async protocolDossier(params = {}) {
    return this._callEndpoint("/api/v1/protocol-dossier", params);
  }

  async deepExploitBounty(params = {}) {
    const payload = {
      protocolName: params.protocolName || params.protocol || "TargetProtocol",
      poolAddress: params.poolAddress || params.targetContract,
      ownerTreasury: params.ownerTreasury,
      tvlUsd: params.tvlUsd != null ? params.tvlUsd : params.capitalAtRiskUsd,
      ...(params.capitalAtRiskUsd != null ? { capitalAtRiskUsd: params.capitalAtRiskUsd } : {}),
      ...(params.chainId != null ? { chainId: params.chainId } : {}),
      ...(params.tier ? { tier: params.tier } : {}),
      ...(params.targetId ? { targetId: params.targetId } : {}),
      code: params.code
    };
    return this._callEndpoint("/api/v1/deep-exploit-bounty", payload);
  }

  async walletBlindAudit(params = {}) {
    const wallet = String(params.wallet || params.address || "").trim();
    const res = await fetch(`${this.workerUrl}/api/v1/wallet-audit?wallet=${encodeURIComponent(wallet)}`, {
      method: "GET",
      headers: { "Accept": "application/json" }
    });
    return await res.json();
  }
}

// ============================================================================
// 2. ELIZAOS (ai16z) PLUGIN PROVIDER
// ============================================================================
const fastPingAction = {
  name: "INGRAVITY_FAST_PING",
  similes: ["FAST_ADDRESS_CHECK", "BINARY_DRAINER_CHECK", "PING_CONTRACT_SAFETY"],
  description: "Ultra-fast $0.01 USDC binary SAFE/DANGER check on any Base/EVM address (0x...) via x402.",
  validate: async (runtime, message) => /0x[a-fA-F0-9]{40}/.test(message.content?.text || ""),
  handler: async (runtime, message, state, options, callback) => {
    try {
      const match = (message.content?.text || "").match(/0x[a-fA-F0-9]{40}/);
      const address = (options && options.address) || (match ? match[0] : "");
      if (!address) return false;
      const provider = new IngravitySecurityActionProvider({
        walletProvider: runtime?.walletProvider || null,
        privateKey: runtime?.getSetting ? runtime.getSetting("INGRAVITY_PRIVATE_KEY") : null,
        maxSpendUsdc: runtime?.maxSpendPerAction || 0.05
      });
      const res = await provider.fastPing({ address, chainId: (options && options.chainId) || 8453 });
      if (callback) callback({ text: `[Ingravity Fast-Ping] ${address} => ${res.verdict || res.status}`, data: res });
      return res;
    } catch (err) {
      if (callback) callback({ text: `Fast-Ping error: ${err.message}` });
      return false;
    }
  }
};

const scanTokenAction = {
  name: "INGRAVITY_SCAN_TOKEN_SECURITY",
  similes: ["CHECK_TOKEN_SAFETY", "VERIFY_HONEYPOT", "AUDIT_ERC20_RUG", "SCAN_TOKEN_RISK"],
  description: "Scans any Base ERC-20 token directly by tokenAddress (0x...) via live RPC bytecode & EIP-1167/1967 proxy storage slots ($0.12 Full / $0.04 Signal via x402).",
  validate: async (runtime, message) => /0x[a-fA-F0-9]{40}/.test(message.content?.text || ""),
  handler: async (runtime, message, state, options, callback) => {
    try {
      const match = (message.content?.text || "").match(/0x[a-fA-F0-9]{40}/);
      const tokenAddress = (options && options.tokenAddress) || (match ? match[0] : "");
      if (!tokenAddress) return false;

      const provider = new IngravitySecurityActionProvider({
        walletProvider: runtime?.walletProvider || null,
        privateKey: runtime?.getSetting ? runtime.getSetting("INGRAVITY_PRIVATE_KEY") : null,
        maxSpendUsdc: runtime?.maxSpendPerAction || 0.12
      });
      const res = await provider.tokenRugScanner({ tokenAddress, chainId: 8453 });
      if (callback) {
        callback({
          text: `[Ingravity Verdict] Token: ${tokenAddress} | Action: ${res.action || "PROCEED"} | Verdict: ${res.verdict || res.status}`,
          data: res
        });
      }
      return res;
    } catch (err) {
      if (callback) callback({ text: `Ingravity scan error: ${err.message}` });
      return false;
    }
  }
};

const txFirewallAction = {
  name: "INGRAVITY_TX_FIREWALL",
  similes: ["FIREWALL_TRANSACTION", "PRE_SIGN_CHECK", "SIMULATE_TRANSACTION_SAFETY"],
  description: "Simulates EVM calldata and live RPC spender storage slots ($0.10 USDC via x402) to block wallet drainers and infinite approvals before signing.",
  validate: async () => true,
  handler: async (runtime, message, state, options, callback) => {
    try {
      const { to, data, from, value, ticketId, capitalAtRiskUsd } = options || {};
      const provider = new IngravitySecurityActionProvider({
        walletProvider: runtime?.walletProvider || null,
        privateKey: runtime?.getSetting ? runtime.getSetting("INGRAVITY_PRIVATE_KEY") : null,
        maxSpendUsdc: runtime?.maxSpendPerAction || null
      });
      const res = await provider.txFirewall({ to, data, from, value, ticketId, capitalAtRiskUsd });
      if (callback) callback({ text: `[Ingravity Firewall] Action: ${res.action || "PROCEED"} | Verdict: ${res.verdict || res.status}`, data: res });
      return res;
    } catch (err) {
      if (callback) callback({ text: `Firewall error: ${err.message}` });
      return false;
    }
  }
};

const ingravityElizaPlugin = {
  name: "ingravity-security",
  version: SDK_VERSION,
  description: "Autonomous 5-EVM Web3 Security, $0.01 Fast-Ping, Pre-Flight Firewall & Direct 0x Honeypot Scanner (settled on Base Mainnet via x402 v2)",
  actions: [fastPingAction, scanTokenAction, txFirewallAction],
  evaluators: [],
  providers: []
};

module.exports = {
  IngravitySecurityActionProvider,
  ingravityElizaPlugin,
  fastPingAction,
  scanTokenAction,
  txFirewallAction,
  encodeErc8021Calldata,
  sanitizeX402V2Accept,
  createEip3009PrivateKeySigner,
  deriveAddressFromPrivateKey,
  keccak256Hex,
  WORKER_ENDPOINT,
  INGRAVITY_WORKER: WORKER_ENDPOINT,
  PAY_TO_WALLET,
  BASE_USDC_CONTRACT,
  BASE_USDC: BASE_USDC_CONTRACT,
  BASE_CHAIN_ID,
  ERC8021_BUILDER_CODE,
  ERC8021_SUFFIX_HEX,
  SDK_VERSION
};
