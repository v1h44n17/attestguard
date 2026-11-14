// Intent serialisation and signing. The known-answer vector is the same one
// asserted by the contract's `intent_digest_matches_shared_vector` unit test:
// if either side changes how an intent is serialised, one of the two fails.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  addressOf,
  intentDigest,
  intentMessage,
  recoverSigner,
  signDigest,
  signIntent,
  type PaymentIntent,
} from '../verifier/src/intent.ts';

const key = Buffer.alloc(32, 1);
const vector: PaymentIntent = {
  contract: 'envelope.attestguard.testnet',
  agent: 'agent.attestguard.testnet',
  vendor: 'vendor.attestguard.testnet',
  amount: 30_000_000_000_000_000_000_000n,
  nonce: '11'.repeat(32),
  expiresAtNs: 1_800_000_000_000_000_000n,
  quoteHash: '22'.repeat(32),
};
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

test('digest, address and signature match the contract test vector', () => {
  assert.equal(
    intentDigest(vector).toString('hex'),
    '5d27b2da2fd6aafbdacd8bc5b234d00f64298276b2fa1a82ae329cea860eb3c2',
  );
  assert.equal(addressOf(key), '1a642f0e3c3af545e7acbd38b07251b3990914f1');
  assert.equal(
    signIntent(vector, key),
    '5b49c134b2202284d723ff9d739e4bfe7daf689ec54bc1a3a1e65e81861d63b9' +
      '2f5bed38000b1f1b037f01d51ca5b53c77ee4166fde0214e92f55cbe731cfc1201',
  );
});

test('the message is newline-delimited and starts with the domain', () => {
  assert.equal(
    intentMessage(vector),
    [
      'attestguard-intent-v1',
      vector.contract,
      vector.agent,
      vector.vendor,
      '30000000000000000000000',
      vector.nonce,
      '1800000000000000000',
      vector.quoteHash,
    ].join('\n'),
  );
});

test('a signature recovers to its signer', () => {
  assert.equal(recoverSigner(intentDigest(vector), signIntent(vector, key)), addressOf(key));
});

test('legacy v values 27 and 28 are accepted', () => {
  const signature = signIntent(vector, key);
  const legacy = signature.slice(0, 128) + (parseInt(signature.slice(128), 16) + 27).toString(16);
  assert.equal(recoverSigner(intentDigest(vector), legacy), addressOf(key));
});

test('changing any field changes who the signature recovers to', () => {
  const signature = signIntent(vector, key);
  const variants: PaymentIntent[] = [
    { ...vector, amount: vector.amount + 1n },
    { ...vector, vendor: 'mallory.testnet' },
    { ...vector, contract: 'other-envelope.testnet' },
    { ...vector, agent: 'other-agent.testnet' },
    { ...vector, nonce: '12'.repeat(32) },
    { ...vector, expiresAtNs: vector.expiresAtNs + 1n },
    { ...vector, quoteHash: '23'.repeat(32) },
  ];
  for (const variant of variants) {
    assert.notEqual(recoverSigner(intentDigest(variant), signature), addressOf(key));
  }
});

test('malformed and malleable signatures do not recover', () => {
  const digest = intentDigest(vector);
  const signature = signIntent(vector, key);
  assert.equal(recoverSigner(digest, signature.slice(2)), null);
  assert.equal(recoverSigner(digest, 'zz'), null);
  assert.equal(recoverSigner(digest, signature.slice(0, 128) + '05'), null);
  assert.equal(recoverSigner(digest, '00'.repeat(64) + '00'), null);

  const s = BigInt('0x' + signature.slice(64, 128));
  const flippedV = signature.endsWith('00') ? '01' : '00';
  const highS = signature.slice(0, 64) + (SECP256K1_ORDER - s).toString(16).padStart(64, '0') + flippedV;
  assert.equal(recoverSigner(digest, highS), null);
});

test('signing is deterministic and low-S', () => {
  const digest = intentDigest(vector);
  assert.equal(signDigest(digest, key), signDigest(digest, key));
  assert.ok(BigInt('0x' + signDigest(digest, key).slice(64, 128)) <= SECP256K1_ORDER / 2n);
});

test('malformed intents are rejected before signing', () => {
  assert.throws(() => intentMessage({ ...vector, nonce: 'abcd' }), /nonce/);
  assert.throws(() => intentMessage({ ...vector, nonce: 'AA'.repeat(32) }), /nonce/);
  assert.throws(() => intentMessage({ ...vector, quoteHash: '' }), /quoteHash/);
  assert.throws(() => intentMessage({ ...vector, amount: -1n }), /amount/);
});
