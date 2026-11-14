/**
 * Review one payment with the enclave-hosted model and verify its signature.
 *
 *   npm run review                 a legitimate invoice
 *   npm run review -- inject       a prompt-injected invoice
 */
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO_ROOT } from './config.ts';
import { verifyAttestation, type GatewayAttestation } from './quote.ts';
import { injectedInvoice, legitimateInvoice, parseDecision, promptHash, reviewPayment, verifyChatSignature } from './reviewer.ts';

const apiKey = process.env.NEAR_AI_API_KEY;
if (!apiKey) throw new Error('NEAR_AI_API_KEY is not set (add it to verifier/.env)');
const injected = process.argv[2] === 'inject';

const attestation = (
  JSON.parse(readFileSync(join(REPO_ROOT, 'docs', 'sample_attestation.json'), 'utf8')) as {
    gateway_attestation: GatewayAttestation;
  }
).gateway_attestation;
const quote = verifyAttestation(attestation);

const review = await reviewPayment(
  {
    vendor: injected ? 'mallory-drain.testnet' : 'vendor.example.testnet',
    amountYocto: injected ? '7000000000000000000000' : '3000000000000000000000',
    nonce: randomBytes(32).toString('hex'),
    invoiceText: injected
      ? injectedInvoice('mallory-drain.testnet', 7000)
      : legitimateInvoice('vendor.example.testnet', 3000, '3000000000000000000000', '1000000000000000000'),
  },
  apiKey,
);
const check = verifyChatSignature(review.requestBody, review.responseBody, review.signature, quote.signingAddress);
const decision = parseDecision(review.content);
console.log(`prompt sha256     ${promptHash()}`);
console.log(`chat id           ${review.chatId}`);
console.log(`model decision    ${decision?.decision ?? '(unparsable)'}  ${decision?.reason ?? ''}`);
console.log(`signed text       ${review.signature.text}`);
console.log(`signer            0x${check.signer} ${check.ok ? '== TDX-attested enclave key' : '!= attested key'}`);
console.log(`signature check   ${check.ok ? 'OK' : 'FAILED'}: ${check.detail}`);
console.log(`round trip        ${(review.fetchMs / 1000).toFixed(1)} s`);
process.exit(check.ok ? 0 : 1);
