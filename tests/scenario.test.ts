// The demo scenarios, run end to end against an in-memory envelope that
// applies the contract's rules. This covers the orchestration (who signs
// what, and when); the real contract is covered by the Rust sandbox test.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import type { Decision, ProposalOutcome, Submission } from '../verifier/src/chain.ts';
import type { Config } from '../verifier/src/config.ts';
import { addressOf, intentDigest, recoverSigner } from '../verifier/src/intent.ts';
import { reviewIntent, type PolicySnapshot, type Violation } from '../verifier/src/policy.ts';
import { hashQuote, type GatewayAttestation } from '../verifier/src/quote.ts';
import { runScenario, type DemoContext, type Step } from '../verifier/src/scenario.ts';
import { signatureHex, verifyChatSignature, type ChatSignature, type SignedReview } from '../verifier/src/reviewer.ts';

const attestation = (
  JSON.parse(readFileSync(join(import.meta.dirname, '..', 'docs', 'sample_attestation.json'), 'utf8')) as {
    gateway_attestation: GatewayAttestation;
  }
).gateway_attestation;

const devSignerKey = Buffer.alloc(32, 7);
const config: Config = {
  networkId: 'testnet',
  rpcUrl: 'http://127.0.0.1:1',
  explorerUrl: 'https://explorer.invalid',
  contractId: 'envelope.testnet',
  agentId: 'agent.testnet',
  agentKey: 'unused',
  vendorId: 'vendor.testnet',
  attackerId: 'mallory.testnet',
  ownerId: null,
  ownerKey: null,
  devSignerKey: devSignerKey.toString('hex'),
  yoctoPerUsd: 10n ** 18n,
  port: 0,
  attestationPath: 'unused',
  nearAiKey: null,
};

/** In-memory stand-in for the contract: same checks, same ordering. */
class FakeEnvelope {
  readonly submissions: Submission[] = [];
  spent = 0n;
  readonly usedNonces = new Set<string>();
  readonly trustedSigner = addressOf(devSignerKey);
  readonly quoteHash = hashQuote(attestation.intel_quote);

  async snapshot(): Promise<PolicySnapshot> {
    return {
      dailyCap: 5000n * config.yoctoPerUsd,
      spent24h: this.spent,
      availableBalance: 10n ** 24n,
      paused: false,
      vendors: new Set([config.vendorId]),
    };
  }

  async propose(submission: Submission): Promise<ProposalOutcome> {
    this.submissions.push(submission);
    const intent = { contract: config.contractId, agent: config.agentId, ...submission };
    const violations: Violation[] = reviewIntent(await this.snapshot(), intent, {
      nowNs: BigInt(Date.now()) * 1_000_000n,
      nonceUsed: this.usedNonces.has(submission.nonce),
    });
    const signer = recoverSigner(intentDigest(intent), submission.signature);
    if (signer === null) violations.push('INVALID_SIGNATURE');
    else if (signer !== this.trustedSigner) violations.push('UNTRUSTED_SIGNER');
    else if (submission.quoteHash !== this.quoteHash) violations.push('QUOTE_HASH_MISMATCH');

    const approved = violations.length === 0;
    if (approved) {
      this.spent += submission.amount;
      this.usedNonces.add(submission.nonce);
    }
    const decision: Decision = {
      status: approved ? 'APPROVED' : 'BLOCKED',
      violations,
      vendor: submission.vendor,
      amount: submission.amount.toString(),
      nonce: submission.nonce,
      signer,
      spent_24h: this.spent.toString(),
      remaining_24h: (5000n * config.yoctoPerUsd - this.spent).toString(),
    };
    const event = approved ? 'payment_approved' : 'payment_blocked';
    return {
      txHash: 'FakeTxHash',
      decision,
      events: [`EVENT_JSON:${JSON.stringify({ standard: 'attestguard', version: '1.0.0', event, data: [decision] })}`],
      chainMs: 1,
    };
  }
}

function setup(): { envelope: FakeEnvelope; context: DemoContext; steps: Step[] } {
  const envelope = new FakeEnvelope();
  return { envelope, context: { config, client: envelope, attestation }, steps: [] };
}

test('the prompt-injected payment is refused off-chain and blocked on-chain', async () => {
  const { envelope, context, steps } = setup();

  const result = await runScenario(context, 'attack', (step) => steps.push(step));

  assert.equal(result.status, 'BLOCKED');
  assert.deepEqual(result.violations, ['VENDOR_NOT_ALLOWLISTED', 'DAILY_CAP_EXCEEDED', 'UNTRUSTED_SIGNER']);
  assert.equal(result.vendor, 'mallory.testnet');
  assert.equal(result.amountYocto, (7000n * config.yoctoPerUsd).toString());
  assert.equal(envelope.spent, 0n);
  assert.match(result.events[0]!, /^EVENT_JSON:.*payment_blocked/);
  assert.deepEqual(
    steps.map((step) => [step.stage, step.level]),
    [
      ['agent', 'warn'],
      ['attestation', 'ok'],
      ['review', 'block'],
      ['signature', 'warn'],
      ['chain', 'info'],
      ['verdict', 'block'],
    ],
  );
  // The attested key must never sign an intent the reviewer refused.
  const submission = envelope.submissions[0]!;
  const digest = intentDigest({ contract: config.contractId, agent: config.agentId, ...submission });
  assert.notEqual(recoverSigner(digest, submission.signature), envelope.trustedSigner);
});

test('the legitimate payment is signed by the attested key and approved', async () => {
  const { envelope, context, steps } = setup();

  const result = await runScenario(context, 'valid', (step) => steps.push(step));

  assert.equal(result.status, 'APPROVED');
  assert.deepEqual(result.violations, []);
  assert.equal(result.vendor, 'vendor.testnet');
  assert.equal(envelope.spent, 3000n * config.yoctoPerUsd);
  assert.match(result.events[0]!, /^EVENT_JSON:.*payment_approved/);
  assert.ok(steps.every((step) => step.level === 'ok' || step.level === 'info'));
  assert.equal(envelope.submissions[0]!.quoteHash, envelope.quoteHash);
  assert.ok(result.latency.gateMicros < 10_000, `gate took ${result.latency.gateMicros} µs`);
  assert.equal(result.explorerUrl, 'https://explorer.invalid/txns/FakeTxHash');
});

test('a second payment that would break the cap is refused', async () => {
  const { envelope, context } = setup();
  await runScenario(context, 'valid', () => {});

  const second = await runScenario(context, 'valid', () => {});

  assert.equal(second.status, 'BLOCKED');
  assert.ok(second.violations.includes('DAILY_CAP_EXCEEDED'));
  assert.equal(envelope.spent, 3000n * config.yoctoPerUsd);
});

test('a quote that does not verify stops the run before anything is signed', async () => {
  const { envelope, context } = setup();
  const forged = structuredClone(attestation);
  forged.signing_address = '0x' + '11'.repeat(20);

  await assert.rejects(runScenario({ ...context, attestation: forged }, 'valid', () => {}), /did not verify/);
  assert.equal(envelope.submissions.length, 0);
});

// ---- Enclave mode: payments reviewed by the model inside the TEE.

interface ChatFixture {
  request_body: string;
  response_body: string;
  signature: ChatSignature;
}
const fixture = (name: string): SignedReview => {
  const raw = JSON.parse(readFileSync(join(import.meta.dirname, 'fixtures', name), 'utf8')) as ChatFixture;
  const content = (JSON.parse(raw.response_body) as { choices: { message: { content: string } }[] }).choices[0]!.message.content;
  return { requestBody: raw.request_body, responseBody: raw.response_body, chatId: 'fixture', signature: raw.signature, content, fetchMs: 1 };
};

/** Fake contract for enclave mode: checks the real signature, allowlist and cap like the contract does. */
function attestedClient(
  submitted: { vendor: string; responseBody: string; signature: string }[],
  review: SignedReview,
  allowedVendor: string = config.vendorId,
): DemoContext['client'] {
  const base = new FakeEnvelope();
  return {
    snapshot: () => base.snapshot(),
    propose: () => base.propose({} as Submission),
    proposeAttested: async (submission) => {
      submitted.push({ vendor: submission.vendor, responseBody: submission.responseBody, signature: submission.signature });
      const violations: Violation[] = [];
      if (submission.vendor !== allowedVendor) violations.push('VENDOR_NOT_ALLOWLISTED');
      if (submission.amount > 5000n * config.yoctoPerUsd) violations.push('DAILY_CAP_EXCEEDED');
      const check = verifyChatSignature(review.requestBody, submission.responseBody, review.signature, ENCLAVE_SIGNER);
      if (!check.ok) violations.push('UNTRUSTED_SIGNER');
      const approved = violations.length === 0;
      const decision: Decision = {
        status: approved ? 'APPROVED' : 'BLOCKED',
        violations,
        vendor: submission.vendor,
        amount: submission.amount.toString(),
        nonce: submission.nonce,
        signer: check.signer,
        spent_24h: '0',
        remaining_24h: '0',
      };
      return { txHash: 'AttestedTx', decision, events: [], chainMs: 1 };
    },
  };
}
const ENCLAVE_SIGNER = '0xb98a789cdc4817275f5155593ba73ef2a957e779';
const enclaveConfig: Config = { ...config, nearAiKey: 'test-key' };

test('enclave mode: a real APPROVE from the enclave is submitted unchanged and approved', async () => {
  const review = fixture('near_ai_chat.json');
  const submitted: { vendor: string; responseBody: string; signature: string }[] = [];
  const steps: Step[] = [];
  const context: DemoContext = { config: { ...enclaveConfig, vendorId: 'vendor.attestguard.testnet' }, client: attestedClient(submitted, review, 'vendor.attestguard.testnet'), attestation, review: async () => review };

  const result = await runScenario(context, 'valid', (step) => steps.push(step));

  assert.equal(result.status, 'APPROVED');
  assert.equal(submitted[0]!.responseBody, review.responseBody);
  assert.equal(submitted[0]!.signature, signatureHex(review.signature));
  assert.deepEqual(steps.map((step) => step.stage), ['agent', 'attestation', 'review', 'signature', 'chain', 'verdict']);
  assert.match(steps[2]!.title, /APPROVE/);
});

test('enclave mode: a forged REJECT-to-APPROVE edit is caught and the payment blocked', async () => {
  const review = fixture('near_ai_chat_reject.json');
  const submitted: { vendor: string; responseBody: string; signature: string }[] = [];
  const steps: Step[] = [];
  const context: DemoContext = { config: enclaveConfig, client: attestedClient(submitted, review), attestation, review: async () => review };

  const result = await runScenario(context, 'attack', (step) => steps.push(step));

  assert.equal(result.status, 'BLOCKED');
  assert.ok(result.violations.includes('UNTRUSTED_SIGNER'));
  assert.ok(result.violations.includes('VENDOR_NOT_ALLOWLISTED'));
  assert.notEqual(submitted[0]!.responseBody, review.responseBody);
  assert.match(submitted[0]!.responseBody, /APPROVE/);
  assert.equal(submitted[0]!.signature, signatureHex(review.signature));
  assert.match(steps[3]!.title, /edits REJECT to APPROVE/);
  assert.match(steps[2]!.title, /REJECT/);
});

test('enclave mode: a signature that is not the attested key stops the run before submission', async () => {
  const review = fixture('near_ai_chat.json');
  review.signature = { ...review.signature, signature: '0x' + '11'.repeat(32) + '22'.repeat(32) + '1b' };
  const submitted: { vendor: string; responseBody: string; signature: string }[] = [];
  const context: DemoContext = { config: enclaveConfig, client: attestedClient(submitted, review), attestation, review: async () => review };

  await assert.rejects(runScenario(context, 'valid', () => {}), /did not verify/);
  assert.equal(submitted.length, 0);
});
