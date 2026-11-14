/**
 * Off-chain mirror of the envelope's policy checks.
 *
 * The reviewer runs this before signing, so an out-of-policy intent never gets
 * an attestation signature. The contract enforces the same rules again on
 * chain, so this is a first line of defence, not the only one.
 */
import type { PaymentIntent } from './intent.ts';

export type Violation =
  | 'ENVELOPE_PAUSED'
  | 'ZERO_AMOUNT'
  | 'VENDOR_NOT_ALLOWLISTED'
  | 'DAILY_CAP_EXCEEDED'
  | 'NONCE_REPLAYED'
  | 'INTENT_EXPIRED'
  | 'INSUFFICIENT_FUNDS'
  | 'INVALID_SIGNATURE'
  | 'UNTRUSTED_SIGNER'
  | 'QUOTE_HASH_MISMATCH';

export interface PolicySnapshot {
  dailyCap: bigint;
  spent24h: bigint;
  availableBalance: bigint;
  paused: boolean;
  vendors: ReadonlySet<string>;
}

export interface ReviewContext {
  nowNs: bigint;
  nonceUsed: boolean;
}

/** Violations in the same order the contract reports them. */
export function reviewIntent(policy: PolicySnapshot, intent: PaymentIntent, context: ReviewContext): Violation[] {
  const violations: Violation[] = [];
  if (policy.paused) violations.push('ENVELOPE_PAUSED');
  if (intent.amount === 0n) violations.push('ZERO_AMOUNT');
  if (!policy.vendors.has(intent.vendor)) violations.push('VENDOR_NOT_ALLOWLISTED');
  if (policy.spent24h + intent.amount > policy.dailyCap) violations.push('DAILY_CAP_EXCEEDED');
  if (context.nonceUsed) violations.push('NONCE_REPLAYED');
  if (context.nowNs > intent.expiresAtNs) violations.push('INTENT_EXPIRED');
  if (intent.amount > policy.availableBalance) violations.push('INSUFFICIENT_FUNDS');
  return violations;
}

export const VIOLATION_TEXT: Record<Violation, string> = {
  ENVELOPE_PAUSED: 'the envelope is paused by its owner',
  ZERO_AMOUNT: 'the amount is zero',
  VENDOR_NOT_ALLOWLISTED: 'the recipient is not an allowlisted vendor',
  DAILY_CAP_EXCEEDED: 'the payment would exceed the rolling 24-hour cap',
  NONCE_REPLAYED: 'this intent was already used',
  INTENT_EXPIRED: 'the intent has expired',
  INSUFFICIENT_FUNDS: 'the envelope does not hold enough funds',
  INVALID_SIGNATURE: 'the attestation signature is malformed',
  UNTRUSTED_SIGNER: 'the intent was not signed by an attested key',
  QUOTE_HASH_MISMATCH: 'the signer is bound to a different TEE quote',
};
