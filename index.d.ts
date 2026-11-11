export interface IngravityConfig {
  workerUrl?: string;
  payToWallet?: string;
  walletProvider?: any;
  maxSpendUsdc?: number;
  capitalAtRiskUsd?: number;
  enableReceiptCache?: boolean;
}

export interface FastPingParams {
  address: string;
  chainId?: number;
}

export interface TxFirewallParams {
  to: string;
  data: string;
  chainId?: number;
  tier?: "FULL" | "ESSENTIAL";
  from?: string;
  value?: string;
  ticketId?: string;
  capitalAtRiskUsd?: number;
}

export interface TokenRugScannerParams {
  tokenAddress?: string;
  chainId?: number;
  tier?: "FULL" | "ESSENTIAL";
  code?: string;
  tokenName?: string;
  capitalAtRiskUsd?: number;
}

export interface DefiMathGuardParams {
  chainId?: number;
  tier?: "FULL" | "ESSENTIAL";
  capitalAtRiskUsd?: number;
  amm?: {
    reserveIn: string;
    reserveOut: string;
    amountIn: string;
    feeBps?: number;
    userSlippageBps?: number;
  };
  leverage?: {
    entryPrice: string;
    leverage: string;
    side?: "LONG" | "SHORT";
    maintenanceMarginBps?: number;
  };
  reserveIn?: number | string;
  reserveOut?: number | string;
  amountIn?: number | string;
  slippageTolerancePct?: number;
}

export interface AuditSolidityParams {
  code: string;
  contractName?: string;
  contractAddress?: string;
  chainId?: number;
  tier?: "FULL" | "ESSENTIAL";
  ownerTreasury?: string;
  capitalAtRiskUsd?: number;
}

export interface ProtocolDossierParams {
  protocolName?: string;
  tvlTargetUsd?: number;
  contractAddress?: string;
  chainId?: number;
  tier?: "FULL" | "ESSENTIAL";
  ownerTreasury?: string;
  contracts: Array<{ name: string; code: string }>;
}

export interface DeepExploitBountyParams {
  protocolName: string;
  poolAddress?: string;
  targetContract?: string;
  chainId?: number;
  tier?: "FULL" | "ESSENTIAL";
  targetId?: string;
  ownerTreasury?: string;
  tvlUsd?: number;
  capitalAtRiskUsd?: number;
  code?: string;
}

export interface WalletBlindAuditParams {
  wallet: string;
}

export function encodeErc8021Calldata(calldataHex?: string): string;
export function sanitizeX402V2Accept<T extends Record<string, any>>(accept: T): Omit<T, "maxAmountRequired">;

export class IngravitySecurityActionProvider {
  constructor(config?: IngravityConfig);
  name: string;
  version: string;
  workerUrl: string;
  payToWallet: string;
  walletProvider: any;
  maxSpendUsdc: number | null;
  capitalAtRiskUsd: number | null;
  enableReceiptCache: boolean;
  clearReceiptCache(): void;
  getActions(): any[];
  fastPing(params: FastPingParams): Promise<any>;
  txFirewall(params: TxFirewallParams): Promise<any>;
  tokenRugScanner(params: TokenRugScannerParams): Promise<any>;
  defiMathGuard(params: DefiMathGuardParams): Promise<any>;
  auditSolidity(params: AuditSolidityParams): Promise<any>;
  protocolDossier(params: ProtocolDossierParams): Promise<any>;
  deepExploitBounty(params: DeepExploitBountyParams): Promise<any>;
  walletBlindAudit(params: WalletBlindAuditParams): Promise<any>;
  quickCheck(params: Record<string, any>): Promise<any>;
}

export const ingravityElizaPlugin: any;
export const fastPingAction: any;
export const scanTokenAction: any;
export const txFirewallAction: any;
export const WORKER_ENDPOINT: string;
export const PAY_TO_WALLET: string;
export const BASE_USDC_CONTRACT: string;
export const BASE_CHAIN_ID: number;
export const ERC8021_BUILDER_CODE: string;
export const ERC8021_SUFFIX_HEX: string;
export const SDK_VERSION: string;
