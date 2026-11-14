# Architecture

See the diagram and the verification list in the top-level [README](../README.md). This file records the contract's
data model and the intent format shared by the verifier and the contract.

## Contract state (`contracts/attest-guard-envelope/src/lib.rs`)
- `owner`, `agent`: account ids. Only the owner configures; only the agent proposes.
- `daily_cap`: yoctoNEAR allowed in any rolling 24 hours (`window`: 24 hourly buckets, ring-indexed by `hour % 24`).
- `vendors`: `IterableSet<AccountId>` allowlist.
- `used_nonces`: `LookupSet<[u8; 32]>`, replay protection; a nonce is consumed only by an approved payment.
- `signers`: `LookupMap<[u8; 20], { quote_hash, registered_at_ns }>`, the Ethereum-style addresses whose signatures are
  accepted, each bound to the SHA-256 of a TDX quote the owner verified.
- `paused`, counters, `total_paid`.

## Intent (signed by the attested key)
`sha256` of the UTF-8 string, newline separated:

```
attestguard-intent-v1
<envelope contract id>
<agent account id>
<vendor account id>
<amount in yoctoNEAR, decimal>
<nonce, 64 lowercase hex>
<expiry, ns since epoch, decimal>
<quote hash, 64 lowercase hex>
```

Signature: 65 bytes `r || s || v`, low-S, `v` in {0, 1, 27, 28}.

## Decision flow
1. Agent calls `propose_payment(vendor, amount, nonce, expires_at_ns, {quote_hash, signature})`.
2. The contract evaluates every rule (paused, zero amount, allowlist, cap, nonce, expiry, balance, signature, signer
   registered, quote hash match) and collects all violations.
3. No violations: record the nonce and spend, `Promise::transfer` to the vendor, emit `payment_approved`, then a
   callback emits `transfer_settled` or, on failure, returns the spend to the window (`transfer_failed`).
4. Any violation: no state change except a counter, emit `payment_blocked` with the full list.
