// TDX quote verification against the real NEAR AI Cloud attestation in docs/,
// plus one tampering test per check to prove each check can actually fail.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  hashQuote,
  INTEL_SGX_ROOT_CA_PUBLIC_KEY,
  parseQuote,
  replayEventLog,
  verifyAttestation,
  type GatewayAttestation,
  type QuoteReport,
} from '../verifier/src/quote.ts';

const SAMPLE = join(import.meta.dirname, '..', 'docs', 'sample_attestation.json');
const original = (JSON.parse(readFileSync(SAMPLE, 'utf8')) as { gateway_attestation: GatewayAttestation })
  .gateway_attestation;

// Byte offsets inside a v4 TDX quote.
const MRTD = 48 + 136;
const REPORT_DATA = 48 + 520;
const ATTESTATION_KEY = 700;
const QE_REPORT = 770;

function tampered(mutate: (attestation: GatewayAttestation) => void): QuoteReport {
  const copy = structuredClone(original);
  mutate(copy);
  return verifyAttestation(copy);
}

function flipByte(hex: string, offset: number): string {
  const byte = (parseInt(hex.slice(offset * 2, offset * 2 + 2), 16) ^ 0xff).toString(16).padStart(2, '0');
  return hex.slice(0, offset * 2) + byte + hex.slice(offset * 2 + 2);
}

function failed(report: QuoteReport): string[] {
  return report.checks.filter((check) => !check.ok).map((check) => check.id);
}

test('the sample NEAR AI Cloud attestation passes every check', () => {
  const report = verifyAttestation(original);
  assert.deepEqual(failed(report), []);
  assert.equal(report.ok, true);
  assert.equal(report.checks.length, 10);
  assert.equal(report.signingAddress, original.signing_address.slice(2).toLowerCase());
  assert.equal(report.quoteHash, createHash('sha256').update(Buffer.from(original.intel_quote, 'hex')).digest('hex'));
  assert.equal(report.quoteHash, hashQuote(original.intel_quote));
  assert.equal(report.measurements.mrtd, original.info.tcb_info.mrtd);
});

test('the chain is anchored to the Intel SGX Root CA key', () => {
  const quote = parseQuote(Buffer.from(original.intel_quote, 'hex'));
  assert.match(quote.pckChainPem, /BEGIN CERTIFICATE/);
  assert.equal(INTEL_SGX_ROOT_CA_PUBLIC_KEY.length, 130);
  const report = verifyAttestation(original, { trustedRootPublicKey: '04' + 'ab'.repeat(64) });
  assert.deepEqual(failed(report), ['pck_chain']);
});

test('a modified measurement breaks the quote signature', () => {
  const report = tampered((a) => (a.intel_quote = flipByte(a.intel_quote, MRTD)));
  assert.deepEqual(failed(report), ['quote_signature', 'measurements']);
});

test('swapping the signing address inside the quote breaks the quote signature', () => {
  const report = tampered((a) => (a.intel_quote = flipByte(a.intel_quote, REPORT_DATA)));
  assert.equal(report.ok, false);
  assert.ok(failed(report).includes('quote_signature'));
  assert.ok(failed(report).includes('report_data_binding'));
});

test('claiming a different signing address is caught by the report data binding', () => {
  const report = tampered((a) => (a.signing_address = '0x' + '11'.repeat(20)));
  assert.deepEqual(failed(report), ['report_data_binding']);
});

test('a different request nonce is caught by the report data binding', () => {
  const report = tampered((a) => (a.request_nonce = '00'.repeat(32)));
  assert.deepEqual(failed(report), ['report_data_binding']);
});

test('a substituted attestation key is rejected', () => {
  const report = tampered((a) => (a.intel_quote = flipByte(a.intel_quote, ATTESTATION_KEY)));
  assert.deepEqual(failed(report), ['quote_signature', 'qe_report_binding']);
});

test('a modified Quoting Enclave report fails the PCK signature', () => {
  const report = tampered((a) => (a.intel_quote = flipByte(a.intel_quote, QE_REPORT + 8)));
  assert.deepEqual(failed(report), ['qe_report_signature']);
});

test('expired certificates are rejected', () => {
  const report = verifyAttestation(original, { now: new Date('2100-01-01T00:00:00Z') });
  assert.deepEqual(failed(report), ['pck_validity']);
});

test('published measurements must match the signed report', () => {
  const report = tampered((a) => (a.info.tcb_info.rtmr3 = '00'.repeat(48)));
  assert.deepEqual(failed(report), ['measurements']);
});

test('an event log with a missing event does not replay', () => {
  const report = tampered((a) => a.info.tcb_info.event_log.pop());
  assert.deepEqual(failed(report), ['event_log_replay']);
});

test('a modified compose file is caught', () => {
  const report = tampered((a) => (a.info.tcb_info.app_compose += ' '));
  assert.deepEqual(failed(report), ['compose_hash']);
});

test('a compose hash swapped consistently everywhere but the measured digest is caught', () => {
  const report = tampered((a) => {
    const tcb = a.info.tcb_info;
    tcb.app_compose += ' ';
    tcb.compose_hash = createHash('sha256').update(tcb.app_compose).digest('hex');
    tcb.event_log.find((event) => event.event === 'compose-hash')!.event_payload = tcb.compose_hash;
  });
  assert.deepEqual(failed(report), ['compose_hash']);
});

test('malformed quotes are reported, not thrown', () => {
  for (const quote of ['', 'zz', original.intel_quote.slice(0, 400), flipByte(original.intel_quote, 0)]) {
    const report = tampered((a) => (a.intel_quote = quote));
    assert.equal(report.ok, false);
    assert.ok(failed(report).includes('quote_structure'));
  }
  const truncated = tampered((a) => (a.intel_quote = a.intel_quote.slice(0, 3000)));
  assert.ok(failed(truncated).includes('quote_structure'));
});

test('event log replay rejects out-of-range registers', () => {
  const [first] = original.info.tcb_info.event_log;
  assert.throws(() => replayEventLog([{ ...first!, imr: 4 }]));
  assert.equal(replayEventLog([]).every((register) => register.every((byte) => byte === 0)), true);
});

test('verification stays inside the 5 ms budget', () => {
  for (let i = 0; i < 50; i++) verifyAttestation(original);
  const samples = Array.from({ length: 200 }, () => verifyAttestation(original).micros).sort((a, b) => a - b);
  assert.ok(samples[100]! < 5000, `median ${samples[100]} µs`);
});

// ---- Live captures from NEAR AI Cloud (2026-11-14), one per signing algorithm.
// Verified at their capture time so the test does not depend on today's date.
const LIVE_TIME = new Date('2026-11-14T17:35:00Z');
const live = (name: string): GatewayAttestation =>
  (JSON.parse(readFileSync(join(import.meta.dirname, 'fixtures', name), 'utf8')) as {
    gateway_attestation: GatewayAttestation;
  }).gateway_attestation;

test('a live ECDSA attestation from NEAR AI Cloud passes every check', () => {
  const attestation = live('live_ecdsa.json');
  const report = verifyAttestation(attestation, { now: LIVE_TIME, expectedNonce: attestation.request_nonce });
  assert.deepEqual(failed(report), []);
  assert.equal(report.checks.length, 11);
  assert.equal(report.signingAddress, attestation.signing_address.slice(2).toLowerCase());
});

test('a live ed25519 attestation binds the 32-byte key and passes every check', () => {
  const attestation = live('live_ed25519.json');
  const report = verifyAttestation(attestation, { now: LIVE_TIME, expectedNonce: attestation.request_nonce });
  assert.deepEqual(failed(report), []);
  assert.equal(report.signingAddress, attestation.signing_address.toLowerCase());
  assert.equal(report.signingAddress.length, 64);
});

test('a replayed attestation fails the freshness check', () => {
  const attestation = live('live_ecdsa.json');
  const report = verifyAttestation(attestation, { now: LIVE_TIME, expectedNonce: '00'.repeat(32) });
  assert.deepEqual(failed(report), ['nonce_fresh']);
});

test('an unknown signing algorithm is rejected', () => {
  const attestation = structuredClone(live('live_ecdsa.json'));
  attestation.signing_algo = 'rsa';
  assert.deepEqual(failed(verifyAttestation(attestation, { now: LIVE_TIME })), ['report_data_binding']);
});
