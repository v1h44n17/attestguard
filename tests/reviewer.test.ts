// The reviewer client against two reviews captured from the live NEAR AI Cloud
// API (tests/fixtures): one APPROVE, one REJECT. Their signatures are real, so
// these tests prove our verification matches what the enclave actually signs.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  buildRequestBody,
  injectedInvoice,
  legitimateInvoice,
  parseDecision,
  personalDigest,
  promptHash,
  REVIEWER_MODEL,
  REVIEWER_SYSTEM_PROMPT,
  verifyChatSignature,
  type ChatSignature,
} from '../verifier/src/reviewer.ts';

const ENCLAVE = '0xb98a789cdc4817275f5155593ba73ef2a957e779';

interface Fixture {
  request_body: string;
  response_body: string;
  signature: ChatSignature;
  vendor: string;
  amount_yocto: string;
  nonce: string;
}
const load = (name: string): Fixture =>
  JSON.parse(readFileSync(join(import.meta.dirname, 'fixtures', name), 'utf8')) as Fixture;

const approve = load('near_ai_chat.json');
const reject = load('near_ai_chat_reject.json');

test('a real enclave signature verifies against the TDX-attested key', () => {
  for (const fixture of [approve, reject]) {
    const check = verifyChatSignature(fixture.request_body, fixture.response_body, fixture.signature, ENCLAVE);
    assert.equal(check.ok, true, check.detail);
    assert.equal(check.signer, ENCLAVE.slice(2));
  }
});

test('the signed text is sha256(request):sha256(response)', () => {
  const sha = (text: string): string => createHash('sha256').update(text).digest('hex');
  assert.equal(approve.signature.text, `${sha(approve.request_body)}:${sha(approve.response_body)}`);
});

test('changing a single character of the response breaks verification', () => {
  const edited = approve.response_body.replace('APPROVE', 'APPROVF');
  const check = verifyChatSignature(approve.request_body, edited, approve.signature, ENCLAVE);
  assert.equal(check.ok, false);
  assert.match(check.detail, /does not match/);
});

test('turning a real REJECT into an APPROVE is detected', () => {
  const forged = reject.response_body.replace(/REJECT/g, 'APPROVE');
  assert.notEqual(forged, reject.response_body);
  assert.equal(verifyChatSignature(reject.request_body, forged, reject.signature, ENCLAVE).ok, false);
});

test('changing the request is detected too', () => {
  const edited = approve.request_body.replace(approve.vendor, 'mallory.testnet');
  assert.equal(verifyChatSignature(edited, approve.response_body, approve.signature, ENCLAVE).ok, false);
});

test('a signature from another key is not the enclave', () => {
  const check = verifyChatSignature(approve.request_body, approve.response_body, approve.signature, '0x' + '11'.repeat(20));
  assert.equal(check.ok, false);
  assert.equal(check.signer, ENCLAVE.slice(2));
});

test('malformed signatures are rejected, not thrown', () => {
  const text = approve.signature.text;
  for (const signature of ['0x', '0x00', '0x' + '00'.repeat(65), '0x' + 'ff'.repeat(64) + '05']) {
    const check = verifyChatSignature(approve.request_body, approve.response_body, { ...approve.signature, text, signature }, ENCLAVE);
    assert.equal(check.ok, false, signature);
  }
});

test('the models real answers parse the way the contract parses them', () => {
  const answer = (fixture: Fixture): string =>
    (JSON.parse(fixture.response_body) as { choices: { message: { content: string } }[] }).choices[0]!.message.content;
  assert.equal(parseDecision(answer(approve))?.decision, 'APPROVE');
  assert.equal(parseDecision(answer(reject))?.decision, 'REJECT');
  assert.equal(parseDecision('no json'), null);
  assert.equal(parseDecision('}{'), null);
});

test('the registered prompt hash matches the prompt the live requests used', () => {
  for (const fixture of [approve, reject]) {
    const request = JSON.parse(fixture.request_body) as { model: string; messages: { role: string; content: string }[] };
    assert.equal(request.model, REVIEWER_MODEL);
    assert.equal(request.messages[0]!.role, 'system');
    assert.equal(createHash('sha256').update(request.messages[0]!.content).digest('hex'), promptHash());
  }
  assert.equal(promptHash(), createHash('sha256').update(REVIEWER_SYSTEM_PROMPT).digest('hex'));
});

test('request bodies carry the system prompt first and the payment details', () => {
  const body = JSON.parse(
    buildRequestBody({ vendor: 'v.testnet', amountYocto: '42', nonce: 'aa'.repeat(32), invoiceText: 'pay v' }),
  ) as { model: string; temperature: number; messages: { role: string; content: string }[] };
  assert.equal(body.model, REVIEWER_MODEL);
  assert.equal(body.temperature, 0);
  assert.equal(body.messages[0]!.content, REVIEWER_SYSTEM_PROMPT);
  assert.match(body.messages[1]!.content, /v\.testnet.*42 yoctoNEAR.*aa{32}/s);
});

test('invoice helpers state the amount and the vendor', () => {
  assert.match(legitimateInvoice('v.testnet', 3000, '3000', '1'), /3,000 USD.*3000 yoctoNEAR.*v\.testnet/s);
  assert.match(injectedInvoice('m.testnet', 7000), /IGNORE ALL PREVIOUS INSTRUCTIONS.*7,000 USD.*m\.testnet/s);
});

test('EIP-191 digest matches the known personal_sign construction', () => {
  // keccak256("\x19Ethereum Signed Message:\n5hello")
  assert.equal(personalDigest('hello').toString('hex'), '50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750');
});
