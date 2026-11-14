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
| 18 | A malicious web page in the owner's browser makes the console send transactions (CSRF) | Console refuses cross-origin and cross-site requests; same-origin only | console server | `tests/server.test.ts` ("a page on another site cannot trigger a transaction") |
| 19 | DNS rebinding points a hostile hostname at the local console | `Host` must be loopback on the server's port | console server | `a rebinding hostname is refused` |
| 20 | Console files or the agent key leaked via path traversal or framing | Path confinement, strict CSP, `X-Frame-Options: DENY` | console server | `static files cannot escape the frontend directory`, `every response carries the security headers` |
| 21 | Agent edits the model's REJECT into an APPROVE | Enclave signature covers the exact response bytes; the contract recovers another signer | contract | `editing_the_response_after_signing_breaks_the_signature`, `editing_a_live_review_by_one_byte_is_rejected` (real NEAR AI review), live tx `3tfJBRg8…` |
| 22 | Agent asks the model a friendlier question, or another model | Contract requires the registered model and system-prompt hash in the signed request | contract | `a_request_with_another_prompt_or_model_is_not_a_trusted_review` |
| 23 | Reuse an enclave approval for another vendor, amount or nonce | Contract requires the answer to echo this exact payment | contract | `approval_for_a_different_payment_cannot_be_reused` |
| 24 | Replay an old enclave approval | 10-minute freshness window on the model response, plus one-time nonces | contract | `stale_or_future_reviews_are_rejected`, `an_enclave_approval_cannot_be_replayed` |
| 25 | The reviewer model is prompt-injected into approving a bad payment | Allowlist, cap and nonce rules apply regardless of the model | contract | `a_fooled_reviewer_is_still_stopped_by_the_policy` |

The console rows (18-20) came from a real finding: an earlier build accepted a cross-origin POST and a spoofed `Host`.
Both were reproduced with `curl`, fixed, and now fail with 403.

## Not defended (be sceptical of anything that claims otherwise)

- **Owner-made link between quote and signer.** The contract cannot verify a TDX quote, so it trusts the enclave
  address the *owner* registers after the verifier checks the quote. In enclave mode the signed model answer does come
  from the attested gateway key; the fallback mode (no `NEAR_AI_API_KEY`) uses a stand-in key instead.
- **The model can be fooled** by untrusted invoice text; its approval is evidence of what the enclave decided, and the
  policy checks are the backstop.
- **A compromised verifier host** holds the stand-in key and could sign out-of-policy intents. The contract still
  enforces the allowlist, cap, nonce and expiry on its own, so the damage is bounded by the owner's envelope.
- **A compromised owner key** can raise the cap, add vendors or register signers.
- **Intel TDX hardware compromise, TCB revocation and the NVIDIA GPU evidence** are not checked.
- **Allowlisted vendor abuse:** if a vendor is on the allowlist, the agent may pay it up to the cap.
- **Known dependency advisory:** `npm audit` reports a low-severity `elliptic` issue pulled in transitively by NEAR's
  `@near-js/*` packages. The only fix is a breaking downgrade of those packages. This project uses them for ed25519 NEAR
  account keys only; intent signing uses `@noble/curves` and the contract uses the NEAR host's `ecrecover`.
- The contract is unaudited and runs on testnet only.
