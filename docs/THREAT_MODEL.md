# Threat model

**Assumption:** the AI agent is untrusted. It may be prompt-injected, jailbroken or fully attacker-controlled, and it
holds the only key allowed to call `propose_payment`. The owner's key and Intel's TDX hardware are trusted.

Every row names the test that exercises it, so each defence can be checked rather than taken on faith.

| # | Attack | Defence | Where | Test |
|---|---|---|---|---|
| 1 | Injected invoice redirects a payment to the attacker's wallet | Vendor allowlist; unlisted recipients are blocked | contract + reviewer | `vendor_outside_allowlist_is_blocked`, sandbox step 1 |
| 2 | Agent is talked into one huge payment | Rolling 24 h cap (24 hourly buckets) | contract + reviewer | `single_payment_over_cap_is_blocked`, `cap_window_rolls_hour_by_hour` |
| 3 | Many small payments to dodge a per-payment limit | Cumulative spend counted in the window | contract | `cumulative_spend_over_cap_is_blocked` |
| 4 | `u128` overflow to wrap the cap check | Checked arithmetic | contract | `amount_overflow_cannot_bypass_cap` |
| 5 | Agent signs with a key of its own | Signer must be registered and bound to a verified quote | contract | `unregistered_signer_is_blocked`, scenario test |
| 6 | Change amount or vendor after the attested signature | Signature covers amount, vendor, nonce, expiry, quote hash | contract | `signature_over_different_amount_is_blocked`, `..._vendor_...` |
| 7 | Replay a valid signed intent | One-time nonces, consumed on approval | contract | `replayed_nonce_is_blocked`, sandbox step 3 |
| 8 | Replay an intent against another envelope | Contract and agent ids are inside the digest | contract | `signature_for_another_envelope_is_blocked` |
| 9 | Hold a signed intent and use it later | Intent expiry | contract | `expired_intent_is_blocked` |
| 10 | Signature malleability (high-S twin) | High-S signatures rejected | contract | `high_s_signature_is_blocked` |
| 11 | Forged or edited TDX quote | Intel root → PCK → QE → TD report chain verified; measurements, RTMR replay, compose hash checked | verifier | `tests/quote.test.ts` (one tampering test per check) |
| 12 | Replay an old genuine quote | Fresh random nonce must be bound in the signed TD report | verifier | `a replayed attestation fails the freshness check`, `npm run attest:live` |
| 13 | Agent calls admin methods (add vendor, raise cap, withdraw) | Owner-only access control | contract | `agent_cannot_*` tests |
| 14 | Stranger initialises a freshly deployed contract | Deploy and `new` in one atomic transaction | deploy script | `verifier/src/deploy.ts` |
| 15 | Vendor account cannot receive funds | Callback returns the spend to the window | contract | `failed_transfer_returns_spend_to_the_window`, sandbox step 9 |
| 16 | Emergency | Owner pause blocks every proposal | contract | `paused_envelope_blocks_everything` |
| 17 | Blocked attempts leave no trace | Blocked proposals succeed and emit `EVENT_JSON` with every violation | contract | `prompt_injection_attempt_reports_every_violation_in_an_event` |

## Not defended (be sceptical of anything that claims otherwise)

- **Enclave-held signing key.** The key that signs intents is a stand-in held by the verifier, not generated inside the
  enclave, because NEAR AI Cloud has no hook for signing arbitrary intents. The contract trusts whatever signer the
  *owner* registers against a quote hash. So the attestation proves a genuine enclave exists and the owner linked it;
  it does not prove that enclave approved each payment.
- **A compromised verifier host** holds the stand-in key and could sign out-of-policy intents. The contract still
  enforces the allowlist, cap, nonce and expiry on its own, so the damage is bounded by the owner's envelope.
- **A compromised owner key** can raise the cap, add vendors or register signers.
- **Intel TDX hardware compromise, TCB revocation and the NVIDIA GPU evidence** are not checked.
- **Allowlisted vendor abuse:** if a vendor is on the allowlist, the agent may pay it up to the cap.
- The contract is unaudited and runs on testnet only.
