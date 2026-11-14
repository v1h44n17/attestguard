/**
 * Latency benchmark for the off-chain gate. No network, no chain: it measures
 * only the work the verifier does before a transaction is sent.
 *
 *   npm run bench            2000 iterations per case
 *   npm run bench -- 10000   custom iteration count
 *
 * Exits non-zero if the full gate's p99 is over the 5 ms budget.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO_ROOT } from './config.ts';
import { addressOf, intentDigest, recoverSigner, signIntent, type PaymentIntent } from './intent.ts';
import { reviewIntent, type PolicySnapshot } from './policy.ts';
import { hashQuote, verifyAttestation, type GatewayAttestation } from './quote.ts';

const BUDGET_MICROS = 5000;
const WARMUP = 200;

const iterations = Number(process.argv[2] ?? 2000);
if (!Number.isInteger(iterations) || iterations < 100) throw new Error('iterations must be an integer of at least 100');

const attestation = (
  JSON.parse(readFileSync(join(REPO_ROOT, 'docs', 'sample_attestation.json'), 'utf8')) as {
    gateway_attestation: GatewayAttestation;
  }
).gateway_attestation;

const key = Buffer.alloc(32, 1);
const intent: PaymentIntent = {
  contract: 'envelope.attestguard.testnet',
  agent: 'agent.attestguard.testnet',
  vendor: 'vendor.attestguard.testnet',
  amount: 3_000_000_000_000_000_000_000n,
  nonce: '11'.repeat(32),
  expiresAtNs: 1_800_000_000_000_000_000n,
  quoteHash: hashQuote(attestation.intel_quote),
};
const policy: PolicySnapshot = {
  dailyCap: 5_000_000_000_000_000_000_000n,
  spent24h: 0n,
  availableBalance: 10n ** 24n,
  paused: false,
  vendors: new Set([intent.vendor]),
};
const review = { nowNs: 1_700_000_000_000_000_000n, nonceUsed: false };
const digest = intentDigest(intent);
const signature = signIntent(intent, key);

interface Stats {
  name: string;
  min: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
}

function bench(name: string, run: () => unknown): Stats {
  for (let i = 0; i < WARMUP; i++) run();
  const samples = new Float64Array(iterations);
  for (let i = 0; i < iterations; i++) {
    const started = process.hrtime.bigint();
    run();
    samples[i] = Number(process.hrtime.bigint() - started) / 1000;
  }
  samples.sort();
  const at = (quantile: number): number => samples[Math.min(iterations - 1, Math.floor(quantile * iterations))]!;
  return { name, min: samples[0]!, p50: at(0.5), p95: at(0.95), p99: at(0.99), max: samples[iterations - 1]! };
}

function assertSound(): void {
  if (!verifyAttestation(attestation).ok) throw new Error('sample attestation failed to verify');
  if (recoverSigner(digest, signature) !== addressOf(key)) throw new Error('signature does not recover to the signer');
  if (reviewIntent(policy, intent, review).length !== 0) throw new Error('benchmark intent violates policy');
}

assertSound();
const results = [
  bench('TDX quote verification (10 checks)', () => verifyAttestation(attestation)),
  bench('policy review', () => reviewIntent(policy, intent, review)),
  bench('intent digest (sha256)', () => intentDigest(intent)),
  bench('intent sign (secp256k1)', () => signIntent(intent, key)),
  bench('signature recover (secp256k1)', () => recoverSigner(digest, signature)),
  bench('FULL GATE: verify quote + review + sign', () => {
    verifyAttestation(attestation);
    reviewIntent(policy, intent, review);
    signIntent(intent, key);
  }),
];

const cell = (micros: number): string => micros.toFixed(1).padStart(9);
console.log(`AttestGuard off-chain gate, ${iterations} iterations per case, times in microseconds\n`);
console.log(`${'case'.padEnd(46)}${['min', 'p50', 'p95', 'p99', 'max'].map((h) => h.padStart(9)).join('')}`);
for (const r of results) {
  console.log(`${r.name.padEnd(46)}${cell(r.min)}${cell(r.p50)}${cell(r.p95)}${cell(r.p99)}${cell(r.max)}`);
}

const gate = results[results.length - 1]!;
const within = gate.p99 <= BUDGET_MICROS;
console.log(
  `\nfull gate p50 ${(gate.p50 / 1000).toFixed(3)} ms, p99 ${(gate.p99 / 1000).toFixed(3)} ms; budget ${BUDGET_MICROS / 1000} ms: ${within ? 'PASS' : 'FAIL'}`,
);
process.exit(within ? 0 : 1);
