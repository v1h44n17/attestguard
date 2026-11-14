# AttestGuard: a TEE-attested spending firewall for AI agents

**Track:** AI Security & Defense (also fits Agent Economy) · **Built on:** NEAR testnet, NEAR AI Cloud attestations

A prompt-injected agent can be talked into draining a treasury, and an ordinary wallet signature cannot prove *why*
a payment was approved. AttestGuard puts a **spend envelope** contract between the agent and the money. A payment only
leaves the treasury if it fits the owner's policy **and** the exact payment intent was signed by a key that is bound to a
verified Intel TDX quote.

```
                    ┌───────────────────────── off-chain verifier (< 1 ms) ──────────────────────────┐
 AI agent ──intent─▶│ 1. verify TDX quote (Intel root → PCK → QE → TD report → RTMR replay → compose) │
 (may be injected)  │ 2. review intent against the envelope (allowlist, 24h cap, nonce, expiry)       │
                    │ 3. only if clean: sign the intent with the attested key                          │
                    └──────────────────────────────────────┬───────────────────────────────────────────┘
                                                           │ propose_payment(vendor, amount, nonce, exp, sig)
                                                           ▼
                    ┌──────────────── envelope contract (NEAR) ────────────────────┐
                    │ same policy checks, again, on chain                           │
                    │ ecrecover(sig) must be a registered signer bound to the quote │
                    │ OK      → Promise::transfer to vendor + EVENT_JSON approved   │
                    │ BLOCKED → no transfer       + EVENT_JSON blocked (all reasons)│
                    └───────────────────────────────────────────────────────────────┘
```

A compromised agent can still *ask* for anything. It cannot get the attested key to sign an out-of-policy intent, and
the contract rejects any signature from another key. The checks are repeated on chain, so a lying verifier cannot
widen the owner's limits either.

## Live on NEAR testnet

| | |
|---|---|
| Envelope contract | `envelope.attestguard-env-9713.testnet` |
| Blocked: $7,000 to an unknown wallet, injected agent | [`5Ec3rJJh…2`](https://testnet.nearblocks.io/txns/5Ec3rJJhfDsTsFDN3PCctKckHUHg7ULZhQZnEpULsJ42) |
| Approved: $3,000 to the allowlisted vendor, attested | [`Ghrn18Xo…5`](https://testnet.nearblocks.io/txns/Ghrn18XoPdFCYCCHRcUdWFcnx6e65MxLLge1GTdVrw45) |

Amounts use a demo scale on testnet ($1 = 0.000001 NEAR), so the $5,000 daily cap is 0.005 NEAR.

## Run it

Requires Node 24+, Rust (via `rustup`), and [`cargo-near`](https://github.com/near/cargo-near).

```bash
make setup     # npm ci in verifier/
make test      # contract unit + sandbox tests, verifier tests
make lint      # fmt, clippy -D warnings, wasm32 check, tsc
make bench     # off-chain gate latency, fails if p99 > 5 ms
```

Deploy your own copy to testnet (needs ~2.1 NEAR on a testnet account whose key is in `~/.near-credentials`;
create one with `near create-account <name>.testnet --useFaucet`):

```bash
make deploy MASTER=<name>.testnet   # builds, creates envelope/agent/vendor sub-accounts, deploys, writes verifier/.env
make demo                           # both scenarios in the terminal
make start                          # console at http://localhost:8787, click "Simulate Demo Scenario"
```

The console server holds the agent key and listens on `127.0.0.1` only.

## What is verified, and where

**Contract** (`contracts/attest-guard-envelope`, near-sdk 5.29)
- Allowlist (`IterableSet`), nonces (`LookupSet`), signers (`LookupMap`): O(1) lookups.
- Rolling 24 h cap: a fixed 24-slot hourly ring buffer, so the check costs the same however many payments were made.
- Intent signature: `env::ecrecover` over `sha256("attestguard-intent-v1\ncontract\nagent\nvendor\namount\nnonce\nexpiry\nquote_hash")`;
  high-S signatures are rejected. The contract id and agent are inside the digest, so a signature cannot be replayed
  against another envelope.
- A blocked proposal **succeeds** with a `BLOCKED` decision listing every violated rule, because a panic would revert the
  `EVENT_JSON` log. Approved proposals transfer funds; if the vendor account cannot receive them, a callback returns
  the spend to the window.
- Owner controls: add/remove vendors, cap, pause, register/revoke signers, withdraw.

**Verifier** (`verifier/src/quote.ts`), run locally with no network access on the real NEAR AI Cloud attestation in
`docs/sample_attestation.json`: quote structure; attestation-key ECDSA signature; Quoting-Enclave report binding; PCK
chain to the pinned Intel SGX Root CA key and validity dates; PCK signature over the QE report; TD report data binds
the signer address and nonce; published measurements equal the signed ones; the 28-event log replays to RTMR0–3;
the app compose file hashes to the measured compose hash. Each check has a test that tampers with exactly that input.

## Performance

Measured by `make bench` (Apple silicon, Node 24, 2000 iterations, no network):

| step | p50 | p99 |
|---|---|---|
| TDX quote verification (10 checks) | 0.26 ms | 0.9 ms |
| policy review | < 1 µs | < 1 µs |
| sign intent (secp256k1) | 0.13 ms | 0.28 ms |
| **full gate** | **0.39 ms** | **0.71 ms** |

On-chain finality on testnet is a separate 2–5 s.

## Tests

- `cargo test`: 34 unit tests (every violation, cap window rollover, nonce replay, tampered amount/vendor/contract,
  high-S and malformed signatures, access control, failed-transfer rollback) plus a sandbox test that deploys the
  real wasm to a local NEAR node and checks balances.
- `npm test` in `verifier/`: 34 tests. A shared known-answer vector pins the intent digest and signature to the same
  bytes in Rust and TypeScript.

## Honest limitations

- **The signing key is not generated inside the enclave.** NEAR AI Cloud does not expose a hook to sign arbitrary
  intents, so a local secp256k1 key stands in for it (shown as "demo stand-in key" in the console). The contract binds
  signers to the SHA-256 of the verified quote, but that binding is made by the owner after the verifier checks the
  quote; the contract cannot verify a TDX quote itself. The sample enclave address `0xb98a…e779` is registered too,
  but nothing here can make that enclave sign our intents.
- **Not checked:** Intel TCB level and certificate revocation (needs Intel's PCS online), and the NVIDIA GPU evidence.
- **Agent prompts are scripted.** No LLM is called; everything after the prompt (attestation, review, signing,
  transaction, contract decision) is real.
- **Settlement is a plain NEAR transfer.** NEAR Intents and Chain Signatures are not integrated.
- **Not defended:** compromised Intel TDX hardware, stolen owner key. The owner key can raise the cap or add vendors.
- Contract is unaudited and was built for a hackathon.

## Layout

```
contracts/attest-guard-envelope/   Rust contract, unit tests (src/tests.rs), sandbox test (tests/)
verifier/                          quote verifier, intent signing, policy mirror, NEAR client, server, demo, bench, deploy
frontend/                          dependency-free console (index.html, style.css, app.js)
tests/                             verifier tests (node --test)
docs/                              architecture, demo script, sample attestation
```
