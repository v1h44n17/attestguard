/**
 * Fetch a fresh attestation from NEAR AI Cloud and verify it locally.
 *
 * The verifier picks a random 32-byte nonce, sends it with the request, and
 * requires the quote's signed TD report to bind that nonce. A recorded quote
 * cannot pass that check, so this proves the enclave answered just now.
 *
 *   npm run attest:live                  ecdsa, deepseek/deepseek-v3.2
 *   npm run attest:live -- ed25519
 */
import { randomBytes } from 'node:crypto';
import { verifyAttestation, type GatewayAttestation, type QuoteReport } from './quote.ts';

export const ATTESTATION_URL = 'https://cloud-api.near.ai/v1/attestation/report';
export const DEFAULT_MODEL = 'deepseek/deepseek-v3.2';

export interface LiveAttestation {
  report: QuoteReport;
  attestation: GatewayAttestation;
  model: string;
  nonce: string;
  fetchMs: number;
}

export async function verifyLive(model = DEFAULT_MODEL, algo: 'ecdsa' | 'ed25519' = 'ecdsa'): Promise<LiveAttestation> {
  const nonce = randomBytes(32).toString('hex');
  const url = `${ATTESTATION_URL}?${new URLSearchParams({ model, nonce, signing_algo: algo })}`;
  const started = performance.now();
  const response = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`NEAR AI Cloud returned HTTP ${response.status}: ${(await response.text()).slice(0, 200)}`);
  const body = (await response.json()) as { gateway_attestation?: GatewayAttestation };
  const fetchMs = performance.now() - started;
  if (!body.gateway_attestation) throw new Error('response has no gateway_attestation');
  const attestation = body.gateway_attestation;
  return { report: verifyAttestation(attestation, { expectedNonce: nonce }), attestation, model, nonce, fetchMs };
}

async function main(): Promise<void> {
  const algo = process.argv[2] === 'ed25519' ? 'ed25519' : 'ecdsa';
  const live = await verifyLive(DEFAULT_MODEL, algo);
  console.log(`NEAR AI Cloud live attestation, ${live.model}, ${algo}`);
  console.log(`nonce sent      ${live.nonce}`);
  console.log(`fetched in      ${live.fetchMs.toFixed(0)} ms`);
  console.log(`verified in     ${(live.report.micros / 1000).toFixed(2)} ms\n`);
  for (const check of live.report.checks) console.log(`${check.ok ? '✓' : '✗'} ${check.id.padEnd(20)} ${check.detail}`);
  console.log(`\nquote sha256    ${live.report.quoteHash}`);
  console.log(live.report.ok ? '\nLIVE ATTESTATION VERIFIED' : '\nLIVE ATTESTATION REJECTED');
  process.exit(live.report.ok ? 0 : 1);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
