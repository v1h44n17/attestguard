/**
 * Intel TDX quote (v4, ECDSA-P256) verification for NEAR AI Cloud attestations.
 *
 * What is verified, all locally and with no network access:
 *   1. the quote's structure and TEE type;
 *   2. the attestation key's ECDSA signature over the header and TD report;
 *   3. that the Quoting Enclave report commits to that attestation key;
 *   4. the PCK certificate's signature over the Quoting Enclave report;
 *   5. the PCK certificate chain up to the pinned Intel SGX Root CA key;
 *   6. that the TD report data binds the TEE signing address and the nonce;
 *   7. that the published measurements match the signed TD report;
 *   8. that replaying the event log reproduces RTMR0-3;
 *   9. that the application compose file hashes to the measured compose hash.
 *
 * What is NOT verified: TCB level and certificate revocation (both need
 * Intel's Provisioning Certification Service), and the NVIDIA GPU evidence.
 */
import { createHash, createPublicKey, verify, X509Certificate, type KeyObject } from 'node:crypto';

/** Uncompressed P-256 public key of the Intel SGX Root CA. */
export const INTEL_SGX_ROOT_CA_PUBLIC_KEY =
  '040ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f5' +
  '67918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394';

const HEADER_LEN = 48;
const TD_REPORT_LEN = 584;
const SIGNED_LEN = HEADER_LEN + TD_REPORT_LEN;
const QE_REPORT_LEN = 384;
const QE_REPORT_DATA_OFFSET = 320;
const TEE_TYPE_TDX = 0x81;
const ATT_KEY_TYPE_ECDSA_P256 = 2;
const CERT_TYPE_QE_REPORT = 6;
const CERT_TYPE_PCK_CHAIN = 5;
const RTMR_COUNT = 4;
const SHA384_LEN = 48;

export interface EventLogEntry {
  imr: number;
  event_type: number;
  digest: string;
  event: string;
  event_payload: string;
}

export interface GatewayAttestation {
  signing_address: string;
  signing_algo: string;
  intel_quote: string;
  report_data: string;
  request_nonce: string;
  info: {
    tcb_info: {
      mrtd: string;
      rtmr0: string;
      rtmr1: string;
      rtmr2: string;
      rtmr3: string;
      compose_hash: string;
      app_compose: string;
      event_log: EventLogEntry[];
    };
  };
}

export interface ParsedQuote {
  version: number;
  attestationKeyType: number;
  teeType: number;
  signedBytes: Buffer;
  mrtd: Buffer;
  rtmrs: Buffer[];
  reportData: Buffer;
  signature: Buffer;
  attestationKey: Buffer;
  qeReport: Buffer;
  qeReportSignature: Buffer;
  qeAuthData: Buffer;
  pckChainPem: string;
}

export interface Check {
  id: string;
  ok: boolean;
  detail: string;
}

export interface QuoteReport {
  ok: boolean;
  checks: Check[];
  /** SHA-256 of the raw quote: the value the contract binds a signer to. */
  quoteHash: string;
  /** Address taken from the signed TD report data, without `0x`. */
  signingAddress: string;
  measurements: { mrtd: string; rtmr: string[]; composeHash: string };
  /** Wall-clock time of the whole verification, in microseconds. */
  micros: number;
}

export class QuoteFormatError extends Error {}

function need(condition: boolean, message: string): asserts condition {
  if (!condition) throw new QuoteFormatError(message);
}

export function parseQuote(quote: Buffer): ParsedQuote {
  need(quote.length > SIGNED_LEN + 4, 'quote is too short');
  const version = quote.readUInt16LE(0);
  const attestationKeyType = quote.readUInt16LE(2);
  const teeType = quote.readUInt32LE(4);
  need(version === 4, `unsupported quote version ${version}`);
  need(attestationKeyType === ATT_KEY_TYPE_ECDSA_P256, 'attestation key is not ECDSA P-256');
  need(teeType === TEE_TYPE_TDX, 'quote is not from a TDX trust domain');

  const body = HEADER_LEN;
  const mrtd = quote.subarray(body + 136, body + 184);
  const rtmrs = Array.from({ length: RTMR_COUNT }, (_, i) =>
    quote.subarray(body + 328 + i * SHA384_LEN, body + 376 + i * SHA384_LEN),
  );
  const reportData = quote.subarray(body + 520, body + 584);

  let at = SIGNED_LEN;
  const take = (length: number): Buffer => {
    need(at + length <= quote.length, 'quote signature data is truncated');
    at += length;
    return quote.subarray(at - length, at);
  };
  const signatureDataLength = take(4).readUInt32LE(0);
  need(at + signatureDataLength <= quote.length, 'quote signature data is truncated');
  const signature = take(64);
  const attestationKey = take(64);
  need(take(2).readUInt16LE(0) === CERT_TYPE_QE_REPORT, 'missing QE report certification data');
  take(4);
  const qeReport = take(QE_REPORT_LEN);
  const qeReportSignature = take(64);
  const qeAuthData = take(take(2).readUInt16LE(0));
  need(take(2).readUInt16LE(0) === CERT_TYPE_PCK_CHAIN, 'missing PCK certificate chain');
  const pckChainPem = take(take(4).readUInt32LE(0)).toString('latin1');

  return {
    version,
    attestationKeyType,
    teeType,
    signedBytes: quote.subarray(0, SIGNED_LEN),
    mrtd,
    rtmrs,
    reportData,
    signature,
    attestationKey,
    qeReport,
    qeReportSignature,
    qeAuthData,
    pckChainPem,
  };
}

function p256Key(raw: Buffer): KeyObject {
  return createPublicKey({
    format: 'jwk',
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: raw.subarray(0, 32).toString('base64url'),
      y: raw.subarray(32, 64).toString('base64url'),
    },
  });
}

function rawP256(key: KeyObject): string {
  const jwk = key.export({ format: 'jwk' });
  return '04' + Buffer.from(jwk.x!, 'base64url').toString('hex') + Buffer.from(jwk.y!, 'base64url').toString('hex');
}

function verifyP256(data: Buffer, key: KeyObject, signature: Buffer): boolean {
  return verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, signature);
}

function splitPem(chain: string): X509Certificate[] {
  const blocks = chain.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
  return blocks.map((pem) => new X509Certificate(pem));
}

/** Replay a TCG-style event log: each event extends its register with SHA-384. */
export function replayEventLog(events: EventLogEntry[]): Buffer[] {
  const registers = Array.from({ length: RTMR_COUNT }, () => Buffer.alloc(SHA384_LEN));
  for (const event of events) {
    need(Number.isInteger(event.imr) && event.imr >= 0 && event.imr < RTMR_COUNT, 'event log has an invalid register index');
    const digest = Buffer.from(event.digest, 'hex');
    need(digest.length === SHA384_LEN, 'event log digest is not SHA-384');
    registers[event.imr] = createHash('sha384').update(registers[event.imr]!).update(digest).digest();
  }
  return registers;
}

/** Digest dstack extends into RTMR3 for a runtime event: SHA-384(type ":" name ":" payload). */
export function runtimeEventDigest(event: EventLogEntry): string {
  const type = Buffer.alloc(4);
  type.writeUInt32LE(event.event_type);
  return createHash('sha384')
    .update(type)
    .update(':')
    .update(event.event)
    .update(':')
    .update(Buffer.from(event.event_payload, 'hex'))
    .digest('hex');
}

const stripHex = (value: string): string => value.replace(/^0x/i, '').toLowerCase();

export function hashQuote(intelQuoteHex: string): string {
  return createHash('sha256').update(Buffer.from(intelQuoteHex, 'hex')).digest('hex');
}

export interface VerifyOptions {
  /** Time at which certificate validity is judged. Defaults to now. */
  now?: Date;
  /** Root key to trust. Defaults to the Intel SGX Root CA. */
  trustedRootPublicKey?: string;
}

/**
 * Verify a NEAR AI Cloud gateway attestation. Never throws on a bad quote:
 * every failure is reported as a failed check.
 */
export function verifyAttestation(attestation: GatewayAttestation, options: VerifyOptions = {}): QuoteReport {
  const started = process.hrtime.bigint();
  const checks: Check[] = [];
  const check = (id: string, run: () => string | false): void => {
    try {
      const detail = run();
      checks.push(detail === false ? { id, ok: false, detail: 'failed' } : { id, ok: true, detail });
    } catch (error) {
      checks.push({ id, ok: false, detail: error instanceof Error ? error.message : String(error) });
    }
  };
  const fail = (message: string): never => {
    throw new Error(message);
  };

  const now = options.now ?? new Date();
  const trustedRoot = stripHex(options.trustedRootPublicKey ?? INTEL_SGX_ROOT_CA_PUBLIC_KEY);
  const tcb = attestation.info.tcb_info;
  const quoteBytes = Buffer.from(attestation.intel_quote, 'hex');
  const quoteHash = createHash('sha256').update(quoteBytes).digest('hex');

  let quote: ParsedQuote | undefined;
  check('quote_structure', () => {
    quote = parseQuote(quoteBytes);
    return `TDX quote v${quote.version}, ${quoteBytes.length} bytes`;
  });

  if (quote) {
    const q = quote;
    check('quote_signature', () =>
      verifyP256(q.signedBytes, p256Key(q.attestationKey), q.signature)
        ? 'attestation key signed the header and TD report (ECDSA P-256)'
        : fail('attestation key signature over the TD report is invalid'),
    );

    check('qe_report_binding', () => {
      const expected = createHash('sha256').update(q.attestationKey).update(q.qeAuthData).digest();
      const reportData = q.qeReport.subarray(QE_REPORT_DATA_OFFSET, QE_REPORT_DATA_OFFSET + 64);
      return expected.equals(reportData.subarray(0, 32)) && reportData.subarray(32).every((byte) => byte === 0)
        ? 'Quoting Enclave report commits to the attestation key'
        : fail('Quoting Enclave report does not commit to the attestation key');
    });

    let chain: X509Certificate[] = [];
    check('pck_chain', () => {
      chain = splitPem(q.pckChainPem);
      if (chain.length < 2) fail('PCK certificate chain is incomplete');
      for (let i = 0; i < chain.length; i++) {
        const issuer = chain[Math.min(i + 1, chain.length - 1)]!;
        if (!chain[i]!.checkIssued(issuer) || !chain[i]!.verify(issuer.publicKey)) {
          fail(`certificate ${i} is not signed by its issuer`);
        }
      }
      const root = chain[chain.length - 1]!;
      if (rawP256(root.publicKey) !== trustedRoot) fail('chain does not end at the trusted Intel SGX Root CA key');
      return `${chain.length} certificates, rooted at the pinned Intel SGX Root CA`;
    });

    check('pck_validity', () => {
      if (chain.length === 0) fail('no certificate chain to check');
      for (const cert of chain) {
        if (now < cert.validFromDate || now > cert.validToDate) {
          fail(`certificate "${cert.subject.replace(/\n/g, ', ')}" is outside its validity period`);
        }
      }
      return `all certificates valid at ${now.toISOString()}`;
    });

    check('qe_report_signature', () => {
      if (chain.length === 0) fail('no PCK certificate to verify against');
      return verifyP256(q.qeReport, chain[0]!.publicKey, q.qeReportSignature)
        ? 'PCK certificate signed the Quoting Enclave report'
        : fail('PCK signature over the Quoting Enclave report is invalid');
    });

    check('report_data_binding', () => {
      const address = Buffer.from(stripHex(attestation.signing_address), 'hex');
      const nonce = Buffer.from(stripHex(attestation.request_nonce), 'hex');
      if (address.length !== 20 || nonce.length !== 32) fail('signing address or nonce has the wrong length');
      const expected = Buffer.concat([address, Buffer.alloc(12), nonce]);
      return expected.equals(q.reportData)
        ? `TD report data binds signer 0x${address.toString('hex')} and the request nonce`
        : fail('TD report data does not bind the claimed signing address and nonce');
    });

    check('measurements', () => {
      const claimed = [tcb.mrtd, tcb.rtmr0, tcb.rtmr1, tcb.rtmr2, tcb.rtmr3].map(stripHex);
      const signed = [q.mrtd, ...q.rtmrs].map((value) => value.toString('hex'));
      return claimed.every((value, i) => value === signed[i])
        ? 'MRTD and RTMR0-3 match the signed TD report'
        : fail('published measurements differ from the signed TD report');
    });

    check('event_log_replay', () => {
      const replayed = replayEventLog(tcb.event_log);
      return replayed.every((value, i) => value.equals(q.rtmrs[i]!))
        ? `${tcb.event_log.length} events replay to RTMR0-3`
        : fail('event log does not replay to the signed RTMR values');
    });
  }

  check('compose_hash', () => {
    const computed = createHash('sha256').update(tcb.app_compose).digest('hex');
    if (computed !== stripHex(tcb.compose_hash)) fail('app compose file does not hash to compose_hash');
    const measured = tcb.event_log.find((event) => event.imr === 3 && event.event === 'compose-hash');
    if (!measured || stripHex(measured.event_payload) !== computed) fail('compose hash is not in the measured event log');
    if (runtimeEventDigest(measured!) !== stripHex(measured!.digest)) fail('compose-hash event digest does not cover its payload');
    return `app compose ${computed.slice(0, 16)}… is measured into RTMR3`;
  });

  return {
    ok: checks.every((entry) => entry.ok),
    checks,
    quoteHash,
    signingAddress: quote ? quote.reportData.subarray(0, 20).toString('hex') : '',
    measurements: {
      mrtd: quote ? quote.mrtd.toString('hex') : '',
      rtmr: quote ? quote.rtmrs.map((value) => value.toString('hex')) : [],
      composeHash: stripHex(tcb.compose_hash),
    },
    micros: Number(process.hrtime.bigint() - started) / 1000,
  };
}
