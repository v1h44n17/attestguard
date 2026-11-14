/**
 * Payment intents: the exact bytes an attested signer commits to.
 *
 * This mirrors `Intent::message` / `Intent::digest` in the envelope contract.
 * A shared known-answer vector in both test suites keeps the two in step.
 */
import { createHash } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

export const INTENT_DOMAIN = 'attestguard-intent-v1';

export interface PaymentIntent {
  /** Envelope contract account id. */
  contract: string;
  /** Agent account id allowed to propose. */
  agent: string;
  vendor: string;
  /** Amount in yoctoNEAR. */
  amount: bigint;
  /** 32-byte nonce, hex. */
  nonce: string;
  /** Expiry as a nanosecond Unix timestamp. */
  expiresAtNs: bigint;
  /** SHA-256 of the TEE quote the signer is bound to, hex. */
  quoteHash: string;
}

const HEX_32 = /^[0-9a-f]{64}$/;

export function intentMessage(intent: PaymentIntent): string {
  if (!HEX_32.test(intent.nonce)) throw new Error('nonce must be 32 bytes of lowercase hex');
  if (!HEX_32.test(intent.quoteHash)) throw new Error('quoteHash must be 32 bytes of lowercase hex');
  if (intent.amount < 0n) throw new Error('amount must not be negative');
  return [
    INTENT_DOMAIN,
    intent.contract,
    intent.agent,
    intent.vendor,
    intent.amount.toString(),
    intent.nonce,
    intent.expiresAtNs.toString(),
    intent.quoteHash,
  ].join('\n');
}

export function intentDigest(intent: PaymentIntent): Buffer {
  return createHash('sha256').update(intentMessage(intent)).digest();
}

/** Ethereum-style address of a secp256k1 private key, hex without `0x`. */
export function addressOf(privateKey: Uint8Array): string {
  return addressOfPublicKey(secp256k1.getPublicKey(privateKey, false));
}

function addressOfPublicKey(uncompressed: Uint8Array): string {
  return Buffer.from(keccak_256(uncompressed.subarray(1)).subarray(12)).toString('hex');
}

/** Sign a digest; returns 65 bytes `r || s || v` as hex (low-S, v in {0,1}). */
export function signDigest(digest: Uint8Array, privateKey: Uint8Array): string {
  const signature = secp256k1.sign(digest, privateKey, { lowS: true });
  return Buffer.concat([signature.toCompactRawBytes(), Buffer.from([signature.recovery])]).toString('hex');
}

export function signIntent(intent: PaymentIntent, privateKey: Uint8Array): string {
  return signDigest(intentDigest(intent), privateKey);
}

/** Address that produced `signatureHex` over `digest`, or null if it is malformed. */
export function recoverSigner(digest: Uint8Array, signatureHex: string): string | null {
  try {
    const bytes = Buffer.from(signatureHex, 'hex');
    if (bytes.length !== 65) return null;
    const v = bytes[64]! >= 27 ? bytes[64]! - 27 : bytes[64]!;
    if (v !== 0 && v !== 1) return null;
    const signature = secp256k1.Signature.fromCompact(bytes.subarray(0, 64)).addRecoveryBit(v);
    if (signature.hasHighS()) return null;
    return addressOfPublicKey(signature.recoverPublicKey(digest).toRawBytes(false));
  } catch {
    return null;
  }
}
