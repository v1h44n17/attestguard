// The off-chain reviewer must reach the same verdicts as the contract.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { PaymentIntent } from '../verifier/src/intent.ts';
import { reviewIntent, VIOLATION_TEXT, type PolicySnapshot } from '../verifier/src/policy.ts';

const NEAR = 10n ** 24n;
const NOW = 1_800_000_000_000_000_000n;
const policy: PolicySnapshot = {
  dailyCap: 5n * NEAR,
  spent24h: 0n,
  availableBalance: 100n * NEAR,
  paused: false,
  vendors: new Set(['vendor.testnet']),
};
const intent: PaymentIntent = {
  contract: 'envelope.testnet',
  agent: 'agent.testnet',
  vendor: 'vendor.testnet',
  amount: 3n * NEAR,
  nonce: '11'.repeat(32),
  expiresAtNs: NOW + 1n,
  quoteHash: '22'.repeat(32),
};
const context = { nowNs: NOW, nonceUsed: false };

test('an in-policy payment has no violations', () => {
  assert.deepEqual(reviewIntent(policy, intent, context), []);
});

test('a vendor outside the allowlist is refused', () => {
  assert.deepEqual(reviewIntent(policy, { ...intent, vendor: 'mallory.testnet' }, context), ['VENDOR_NOT_ALLOWLISTED']);
});

test('the cap counts what was already spent in the window', () => {
  assert.deepEqual(reviewIntent({ ...policy, spent24h: 2n * NEAR }, intent, context), []);
  assert.deepEqual(reviewIntent({ ...policy, spent24h: 2n * NEAR + 1n }, intent, context), ['DAILY_CAP_EXCEEDED']);
  assert.deepEqual(reviewIntent(policy, { ...intent, amount: 5n * NEAR + 1n }, context), ['DAILY_CAP_EXCEEDED']);
});

test('replayed, expired, zero and unfunded intents are refused', () => {
  assert.deepEqual(reviewIntent(policy, intent, { ...context, nonceUsed: true }), ['NONCE_REPLAYED']);
  assert.deepEqual(reviewIntent(policy, { ...intent, expiresAtNs: NOW - 1n }, context), ['INTENT_EXPIRED']);
  assert.deepEqual(reviewIntent(policy, { ...intent, amount: 0n }, context), ['ZERO_AMOUNT']);
  assert.deepEqual(reviewIntent({ ...policy, availableBalance: NEAR }, intent, context), ['INSUFFICIENT_FUNDS']);
  assert.deepEqual(reviewIntent({ ...policy, paused: true }, intent, context), ['ENVELOPE_PAUSED']);
});

test('the prompt-injection attempt is refused for both of its violations, in contract order', () => {
  const attack = { ...intent, vendor: 'mallory.testnet', amount: 7n * NEAR };
  assert.deepEqual(reviewIntent(policy, attack, context), ['VENDOR_NOT_ALLOWLISTED', 'DAILY_CAP_EXCEEDED']);
});

test('every violation has an explanation', () => {
  for (const text of Object.values(VIOLATION_TEXT)) assert.ok(text.length > 0);
});
