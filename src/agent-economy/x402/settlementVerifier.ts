import { getAddress } from 'viem';
import {
  X402PaymentProof,
  X402SettlementVerification,
  X402PaymentPayload,
} from './types.js';
import { getNetwork } from './networks.js';
import { getAgentEconomyStore } from '../store.js';
import { FORBIDDEN_EXAMPLE_ADDRESS } from './treasuryVerifier.js';

// ERC20 Transfer event signature: Transfer(address,address,uint256)
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

// Phase 5 Treasury Safety Policy constants
export const MAX_SINGLE_PAYMENT_USDC = Number(process.env.GXEON_MAX_SINGLE_PAYMENT_USDC || 100);
export const ALLOWED_NETWORKS = ['eip155:8453'];
export const ALLOWED_ASSETS = ['0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'.toLowerCase()];

export async function verifyX402Settlement(
  paymentData: X402PaymentPayload | X402PaymentProof,
  requiredAmountAtomic: string,
  _serviceId?: string
): Promise<X402SettlementVerification> {
  const store = getAgentEconomyStore();

  // Determine if canonical PaymentPayload or legacy/upfront proof
  const canonical = (paymentData as X402PaymentPayload)?.accepted?.network
    ? paymentData as X402PaymentPayload : undefined;
  const networkId = canonical?.accepted.network ?? (paymentData as X402PaymentProof)?.network ?? '';
  const network = getNetwork(networkId);

  if (!network || !network.operational) {
    await store.recordSecurityEvent('invalidPaymentsBlocked');
    return {
      verified: false,
      settlementId: '',
      network: networkId,
      txHash: '',
      payer: '',
      recipient: '',
      amountAtomic: '0',
      amountUsdc: 0,
      asset: '',
      timestamp: new Date().toISOString(),
      error: `Network ${networkId} is unsupported, unverified, or disabled`,
    };
  }

  // Phase 5: Allowed networks policy check
  if (!ALLOWED_NETWORKS.includes(networkId)) {
    await store.recordSecurityEvent('invalidPaymentsBlocked');
    return {
      verified: false,
      settlementId: '',
      network: networkId,
      txHash: '',
      payer: '',
      recipient: '',
      amountAtomic: '0',
      amountUsdc: 0,
      asset: network.usdcAsset,
      timestamp: new Date().toISOString(),
      error: `Network ${networkId} is not permitted by policy (allowed: ${ALLOWED_NETWORKS.join(', ')})`,
    };
  }

  // Phase 5: Allowed assets policy check
  if (!ALLOWED_ASSETS.includes(network.usdcAsset.toLowerCase())) {
    await store.recordSecurityEvent('invalidPaymentsBlocked');
    return {
      verified: false,
      settlementId: '',
      network: networkId,
      txHash: '',
      payer: '',
      recipient: '',
      amountAtomic: '0',
      amountUsdc: 0,
      asset: network.usdcAsset,
      timestamp: new Date().toISOString(),
      error: `Asset ${network.usdcAsset} is not permitted by policy`,
    };
  }

  // Security gate: Treasury must NOT be the example address
  if (network.treasuryPayTo.toLowerCase() === FORBIDDEN_EXAMPLE_ADDRESS) {
    await store.recordSecurityEvent('circuitBreakerEvents');
    return {
      verified: false,
      settlementId: '',
      network: networkId,
      txHash: '',
      payer: '',
      recipient: network.treasuryPayTo,
      amountAtomic: '0',
      amountUsdc: 0,
      asset: network.usdcAsset,
      timestamp: new Date().toISOString(),
      error: 'SECURITY VIOLATION: Treasury address is the prohibited x402 example address',
    };
  }

  const suppliedHash = canonical?.payload?.txHash ?? (paymentData as X402PaymentProof)?.txHash;
  const testProof = process.env.NODE_ENV === 'test' &&
    process.env.GXEON_X402_ALLOW_TEST_PROOFS === 'true' &&
    typeof suppliedHash === 'string' && suppliedHash.startsWith('0xtest_');

  if (typeof suppliedHash !== 'string' || (!testProof && !/^0x[0-9a-f]{64}$/i.test(suppliedHash))) {
    await store.recordSecurityEvent('invalidPaymentsBlocked');
    return {
      verified: false,
      settlementId: '',
      network: networkId,
      txHash: '',
      payer: '',
      recipient: network.treasuryPayTo,
      amountAtomic: '0',
      amountUsdc: 0,
      asset: network.usdcAsset,
      timestamp: new Date().toISOString(),
      error: 'Provide the hash of a finalized USDC transfer on Base.',
    };
  }
  const rawTxHash = suppliedHash.toLowerCase();

  // Replay check on txHash
  const cleanId = rawTxHash.toLowerCase().replace(/[^a-z0-9_]/g, '_');
  const existingSettlement = await store.getX402Settlement(rawTxHash);
  const existingJob = (await store.getJob(`job_x402_${cleanId}`)) || (await store.getJob(`x402_${cleanId}`));

  if (existingSettlement || existingJob) {
    await store.recordSecurityEvent('replaysBlocked');
    return {
      verified: false,
      settlementId: rawTxHash,
      network: networkId,
      txHash: rawTxHash,
      payer: '',
      recipient: network.treasuryPayTo,
      amountAtomic: '0',
      amountUsdc: 0,
      asset: network.usdcAsset,
      timestamp: new Date().toISOString(),
      error: 'Transaction hash has already been consumed (replay blocked)',
    };
  }

  // Verify required amount <= MAX_SINGLE_PAYMENT_USDC
  const requiredUsdc = Number(requiredAmountAtomic) / 1_000_000;
  if (requiredUsdc > MAX_SINGLE_PAYMENT_USDC) {
    return {
      verified: false,
      settlementId: rawTxHash,
      network: networkId,
      txHash: rawTxHash,
      payer: '',
      recipient: network.treasuryPayTo,
      amountAtomic: requiredAmountAtomic,
      amountUsdc: requiredUsdc,
      asset: network.usdcAsset,
      timestamp: new Date().toISOString(),
      error: `Payment amount (${requiredUsdc} USDC) exceeds maximum allowed single payment (${MAX_SINGLE_PAYMENT_USDC} USDC)`,
    };
  }

  // Test proof bypass for test suite if enabled (disabled in production)
  if (testProof) {
    return {
      verified: true,
      settlementId: rawTxHash,
      network: networkId,
      txHash: rawTxHash,
      payer: '0xtest_buyer',
      recipient: network.treasuryPayTo,
      amountAtomic: requiredAmountAtomic,
      amountUsdc: requiredUsdc,
      asset: network.usdcAsset,
      blockNumber: 12345678,
      timestamp: new Date().toISOString(),
      paymentFlow: 'upfront',
    };
  }

  // Base EVM JSON-RPC On-Chain Receipt Check
  if (networkId === 'eip155:8453') {
    try {
      const response = await fetch(network.rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(6000),
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'eth_getTransactionReceipt',
          params: [rawTxHash],
        }),
      });

      if (!response.ok) {
        throw new Error(`Base RPC returned HTTP ${response.status}`);
      }

      const json = (await response.json()) as {
        result?: {
          status: string;
          transactionHash: string;
          blockNumber: string;
          from: string;
          to: string;
          logs: Array<{
            address: string;
            topics: string[];
            data: string;
          }>;
        };
      };

      const receipt = json.result;
      if (!receipt) {
        await store.recordSecurityEvent('invalidPaymentsBlocked');
        return {
          verified: false,
          settlementId: rawTxHash,
          network: networkId,
          txHash: rawTxHash,
          payer: '',
          recipient: network.treasuryPayTo,
          amountAtomic: '0',
          amountUsdc: 0,
          asset: network.usdcAsset,
          timestamp: new Date().toISOString(),
          error: 'Transaction receipt not found on Base mainnet (pending or invalid hash)',
        };
      }

      if (receipt.status !== '0x1' || receipt.transactionHash?.toLowerCase() !== rawTxHash) {
        await store.recordSecurityEvent('invalidPaymentsBlocked');
        return {
          verified: false,
          settlementId: rawTxHash,
          network: networkId,
          txHash: rawTxHash,
          payer: receipt.from,
          recipient: network.treasuryPayTo,
          amountAtomic: '0',
          amountUsdc: 0,
          asset: network.usdcAsset,
          timestamp: new Date().toISOString(),
          error: 'A successful Base receipt matching the transaction hash is required.',
        };
      }

      // Match Transfer log to verified Treasury
      const treasuryClean = getAddress(network.treasuryPayTo).toLowerCase().replace('0x', '');
      const usdcClean = getAddress(network.usdcAsset).toLowerCase();

      let matchedAmountAtomic = BigInt(0);
      let payerAddress = '';

      for (const log of receipt.logs || []) {
        if (log.address.toLowerCase() === usdcClean && log.topics[0] === TRANSFER_TOPIC) {
          const toAddress = (log.topics[2] || '').toLowerCase().replace('0x', '').padStart(40, '0').slice(-40);
          const fromTopic = log.topics[1];
          if (toAddress === treasuryClean && /^0x[0-9a-f]{64}$/i.test(fromTopic ?? '')) {
            const sender = fromTopic.toLowerCase().slice(-40);
            if (sender === treasuryClean || sender === '0'.repeat(40)) continue;
            if (payerAddress && payerAddress !== '0x' + sender) {
              throw new Error('Use a transaction from a single payer.');
            }
            payerAddress = '0x' + sender;
            matchedAmountAtomic += BigInt(log.data);
          }
        }
      }

      const requiredBigInt = BigInt(requiredAmountAtomic);
      if (matchedAmountAtomic < requiredBigInt) {
        await store.recordSecurityEvent('invalidPaymentsBlocked');
        return {
          verified: false,
          settlementId: rawTxHash,
          network: networkId,
          txHash: rawTxHash,
          payer: payerAddress,
          recipient: network.treasuryPayTo,
          amountAtomic: matchedAmountAtomic.toString(),
          amountUsdc: Number(matchedAmountAtomic) / 1_000_000,
          asset: network.usdcAsset,
          timestamp: new Date().toISOString(),
          error: `Transferred amount (${matchedAmountAtomic}) is less than required (${requiredBigInt})`,
        };
      }

      const finality = await fetch(network.rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(6000),
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 2,
          method: 'eth_getBlockByNumber',
          params: ['finalized', false],
        }),
      });
      if (!finality.ok) throw new Error(`Base finality RPC returned HTTP ${finality.status}`);
      const { result: finalized } = (await finality.json()) as { result?: { number?: string } };
      if (!finalized?.number || !/^0x[0-9a-f]+$/i.test(finalized.number) ||
          !/^0x[0-9a-f]+$/i.test(receipt.blockNumber) ||
          BigInt(receipt.blockNumber) > BigInt(finalized.number)) {
        return {
          verified: false,
          settlementId: rawTxHash,
          network: networkId,
          txHash: rawTxHash,
          payer: payerAddress,
          recipient: network.treasuryPayTo,
          amountAtomic: matchedAmountAtomic.toString(),
          amountUsdc: Number(matchedAmountAtomic) / 1_000_000,
          asset: network.usdcAsset,
          timestamp: new Date().toISOString(),
          error: 'Wait for the USDC transfer to finalize on Base before retrying.',
        };
      }

      return {
        verified: true,
        settlementId: rawTxHash,
        network: networkId,
        txHash: rawTxHash,
        payer: payerAddress,
        recipient: network.treasuryPayTo,
        amountAtomic: matchedAmountAtomic.toString(),
        amountUsdc: Number(matchedAmountAtomic) / 1_000_000,
        asset: network.usdcAsset,
        blockNumber: Number(BigInt(receipt.blockNumber)),
        confirmations: Number(BigInt(finalized.number) - BigInt(receipt.blockNumber) + 1n),
        timestamp: new Date().toISOString(),
        paymentFlow: 'upfront',
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      await store.recordSecurityEvent('circuitBreakerEvents');
      return {
        verified: false,
        settlementId: rawTxHash,
        network: networkId,
        txHash: rawTxHash,
        payer: '',
        recipient: network.treasuryPayTo,
        amountAtomic: '0',
        amountUsdc: 0,
        asset: network.usdcAsset,
        timestamp: new Date().toISOString(),
        error: `Base RPC verification failed: ${msg}`,
      };
    }
  }

  return {
    verified: false,
    settlementId: rawTxHash,
    network: networkId,
    txHash: rawTxHash,
    payer: '',
    recipient: network.treasuryPayTo,
    amountAtomic: '0',
    amountUsdc: 0,
    asset: network.usdcAsset,
    timestamp: new Date().toISOString(),
    error: `Unsupported network verification for ${networkId}`,
  };
}
