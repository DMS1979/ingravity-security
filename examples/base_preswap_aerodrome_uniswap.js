/**
 * Ingravity Security SDK — Base Mainnet Pre-Swap Guard (Aerodrome & Uniswap Bots)
 * -------------------------------------------------------------------------------
 * Drops a deterministic 2-step pre-swap gate ($0.01 Fast-Ping + $0.04 Honeypot Scan)
 * and optional $0.10 Pre-Sign Tx Firewall directly in front of Base DEX swaps.
 *
 * Run quote preview (no funds spent):
 *   node examples/base_preswap_aerodrome_uniswap.js
 */

const { IngravitySecurityActionProvider } = require("..");

const BASE_CHAIN_ID = 8453;
const AERODROME_ROUTER = "0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43";
const UNISWAP_V3_ROUTER = "0x2626664c2603336E57B271c5C0b26F421741e481";
const BASE_WETH = "0x4200000000000000000000000000000000000006";

async function safeSwapOnBase({ walletProvider = null, tokenOut = BASE_WETH, router = AERODROME_ROUTER, swapCalldata = "0x", botAddress } = {}) {
  // Step 1: Ultra-fast $0.01 binary gate + $0.04 ESSENTIAL ERC-20 honeypot check
  const guard = new IngravitySecurityActionProvider({
    walletProvider,
    maxSpendUsdc: 0.05,
    enableReceiptCache: true
  });

  const ping = await guard.fastPing({ address: tokenOut, chainId: BASE_CHAIN_ID });
  if (ping.status === "402_PAYMENT_REQUIRED") {
    return { readyToBroadcast: false, stage: "fast-ping", quote: ping };
  }
  if (ping.action === "ABORT" || ping.verdict === "DANGER") {
    throw new Error(`[INGRAVITY BLOCKED] Fast-Ping flagged ${tokenOut}: ${ping.verdict}`);
  }

  const scan = await guard.tokenRugScanner({ tokenAddress: tokenOut, chainId: BASE_CHAIN_ID, tier: "ESSENTIAL" });
  if (scan.action === "ABORT" || /HIGH_RUG_RISK|CRITICAL_HONEYPOT/.test(String(scan.verdict || ""))) {
    throw new Error(`[INGRAVITY BLOCKED] Honeypot/Rug Risk on ${tokenOut}: ${scan.verdict}`);
  }

  // Optional Step 2: Pre-sign calldata firewall ($0.10 USDC) if router calldata is non-trivial
  if (swapCalldata && swapCalldata !== "0x") {
    const fwGuard = new IngravitySecurityActionProvider({ walletProvider, maxSpendUsdc: 0.12 });
    const fw = await fwGuard.txFirewall({ to: router, data: swapCalldata, from: botAddress, chainId: BASE_CHAIN_ID });
    if (fw.action === "ABORT" || fw.verdict === "BLOCK_DRAINER") {
      throw new Error(`[INGRAVITY BLOCKED] Calldata Firewall blocked tx to ${router}: ${fw.verdict}`);
    }
  }

  return { readyToBroadcast: true, router, tokenOut, pingVerdict: ping.verdict, scanVerdict: scan.verdict };
}

if (require.main === module) {
  safeSwapOnBase({ router: UNISWAP_V3_ROUTER, tokenOut: BASE_WETH })
    .then((res) => console.log("Pre-Swap Guard Preview:", JSON.stringify(res, null, 2)))
    .catch((err) => {
      console.error(err.message);
      process.exit(1);
    });
}

module.exports = { safeSwapOnBase, AERODROME_ROUTER, UNISWAP_V3_ROUTER, BASE_WETH };
