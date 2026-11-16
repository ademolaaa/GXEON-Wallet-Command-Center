import { afterEach, describe, expect, it, vi } from 'vitest';
import servicesHandler from '../../api/v1/services.js';
import offersHandler from '../../api/v1/offers.js';
import { verifyX402Settlement } from '../../src/agent-economy/x402/settlementVerifier.js';

const originalPayTo = process.env.GXEON_X402_BASE_PAYTO;
const originalVerified = process.env.GXEON_TREASURY_VERIFIED;

function response() {
  const headers: Record<string, string> = {};
  return {
    statusCode: 200,
    headers,
    body: undefined as any,
    setHeader(name: string, value: string) { headers[name] = value; },
    end(value?: string) { this.body = value ? JSON.parse(value) : undefined; },
  };
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  if (originalPayTo === undefined) delete process.env.GXEON_X402_BASE_PAYTO;
  else process.env.GXEON_X402_BASE_PAYTO = originalPayTo;
  if (originalVerified === undefined) delete process.env.GXEON_TREASURY_VERIFIED;
  else process.env.GXEON_TREASURY_VERIFIED = originalVerified;
});

describe('x402 money-truth gate', () => {
  it('does not advertise the official example address as an active x402 rail', async () => {
    process.env.GXEON_X402_BASE_PAYTO =
      '0x209693bc6afc0c5328ba36faf03c514ef312287c';
    process.env.GXEON_TREASURY_VERIFIED = 'true';

    const res = response();
    await servicesHandler(
      { method: 'GET', url: '/v1/payment-methods' },
      res
    );

    expect(res.statusCode).toBe(200);
    const x402 = res.body.paymentMethods.find(
      (item: any) => item.rail === 'x402'
    );
    expect(x402).toMatchObject({
      enabled: false,
      status: 'CONFIGURATION_REQUIRED',
      supportedNetworks: [],
      gateways: {},
    });
    expect(x402.blocker).toContain('official specification example address');
  });

  it('keeps prepaid Stripe live while excluding x402 from active billing rails', async () => {
    process.env.GXEON_X402_BASE_PAYTO =
      '0x209693bc6afc0c5328ba36faf03c514ef312287c';
    process.env.GXEON_TREASURY_VERIFIED = 'true';

    const res = response();
    await servicesHandler(
      { method: 'GET', url: '/v1/pricing' },
      res
    );

    expect(res.statusCode).toBe(200);
    expect(res.body.billingRails).toContain('prepaid_credits');
    expect(res.body.billingRails).toContain('stripe_live');
    expect(res.body.billingRails).not.toContain('x402');
  });

  it('marks x402 canonical offers paused until treasury activation', async () => {
    const res = response();
    await offersHandler({ method: 'GET', url: '/v1/offers' }, res);

    expect(res.statusCode).toBe(200);
    const x402Offers = res.body.canonicalOffers.filter(
      (offer: any) => offer.paymentRail === 'x402'
    );
    expect(x402Offers).toHaveLength(2);
    expect(x402Offers.every((offer: any) => offer.status === 'PAUSED')).toBe(true);
    expect(x402Offers.every((offer: any) => offer.blocker)).toBe(true);
  });
});

describe('x402 receipt verification', () => {
  const treasury = '0x' + '11'.repeat(20);
  const buyer = '0x' + '22'.repeat(20);
  const usdc = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
  const txHash = '0x' + '33'.repeat(32);

  it('keeps authorization-only payments out of settled revenue', async () => {
    vi.stubEnv('GXEON_X402_BASE_PAYTO', treasury);
    vi.stubEnv('GXEON_TREASURY_VERIFIED', 'true');
    vi.stubEnv('GXEON_X402_ALLOW_TEST_PROOFS', 'true');
    const result = await verifyX402Settlement({
      x402Version: 2,
      resource: { url: 'https://example.com/x402/json-validate' },
      accepted: {
        scheme: 'exact', network: 'eip155:8453', asset: usdc, amount: '10000',
        payTo: treasury, maxTimeoutSeconds: 60,
      },
      payload: {
        signature: '0xtest_sig_authorization_only',
        authorization: {
          from: buyer, to: treasury, value: '10000', validAfter: 0,
          validBefore: Math.floor(Date.now() / 1000) + 60, nonce: '0x' + '44'.repeat(32),
        },
      },
    }, '10000');

    expect(result.verified).toBe(false);
    expect(result.error).toContain('finalized USDC transfer');
    expect(result.amountAtomic).toBe('0');
  });

  it.each([
    { head: '0x63', sender: buyer, verified: false },
    { head: '0x64', sender: treasury, verified: false },
    { head: '0x64', sender: buyer, verified: true },
  ])('checks payment finality and payer ($head, verified=$verified)', async ({ head, sender, verified }) => {
    vi.stubEnv('GXEON_X402_BASE_PAYTO', treasury);
    vi.stubEnv('GXEON_TREASURY_VERIFIED', 'true');

    const send = vi.fn(async (_url: string, init: RequestInit) => {
      const request = JSON.parse(String(init.body));
      if (request.method === 'eth_getTransactionReceipt') {
        return Response.json({
          result: {
            status: '0x1', transactionHash: txHash, blockNumber: '0x64', from: sender,
            logs: [{
              address: usdc,
              topics: [
                '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
                '0x' + sender.slice(2).padStart(64, '0'),
                '0x' + treasury.slice(2).padStart(64, '0'),
              ],
              data: '0x2710',
            }],
          },
        });
      }
      expect(request.method).toBe('eth_getBlockByNumber');
      expect(request.params).toEqual(['finalized', false]);
      return Response.json({ result: { number: head } });
    });
    vi.stubGlobal('fetch', send);

    const result = await verifyX402Settlement({ network: 'eip155:8453', txHash }, '10000');
    expect(result.verified).toBe(verified);
    if (verified) expect(result).toMatchObject({ txHash, payer: buyer, amountAtomic: '10000', blockNumber: 100 });
  });
});
