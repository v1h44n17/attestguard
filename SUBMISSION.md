# Submission assets (not part of the product; delete before or after submitting)

## X post (tag @NEARProtocol and #NEARHackathon, attach a screen recording of the console)

I built AttestGuard at NEAR HACKATHON: a spending firewall for AI agents.

A prompt-injected agent tries to wire $7K to an unknown wallet: blocked on-chain. A legit $3K invoice settles. Intel TDX quote verified in ~1 ms.

https://github.com/v1h44n17/attestguard
@NEARProtocol #NEARHackathon

(counts as 274 characters on X; limit 280)

## Form description (paste into "What did you build?")

AttestGuard is a spending firewall for AI agents on NEAR. Agents can now hold wallets, but a prompt-injected agent can be tricked into draining a treasury, and a plain wallet signature cannot prove why a payment was approved.

AttestGuard puts a spend envelope contract between the agent and the money. A payment leaves the treasury only if it fits the owner's policy AND the exact payment intent was signed by a key bound to a verified Intel TDX quote from NEAR AI Cloud.

Contract (Rust, near-sdk): vendor allowlist, rolling 24-hour cap (a fixed 24-slot ring buffer, constant cost), nonce replay protection, intent expiry, pause switch, and on-chain secp256k1 signature recovery over the exact intent (contract and agent ids included, high-S rejected). Approved payments run a real Promise transfer with a rollback callback; blocked ones succeed, listing every violated rule in an EVENT_JSON log.

Verifier (TypeScript): checks the real NEAR AI Cloud attestation locally with no network: quote signature, Quoting Enclave binding, PCK chain to the pinned Intel SGX Root CA, TD report data binding the signer and nonce, measurements, a 28-event RTMR replay, and the compose hash. The full gate (verify, review, sign) takes about 0.4 ms median, 0.7 ms p99.

Console: a terminal-style dashboard with a one-click scenario. A prompt-injected $7K transfer to an unknown wallet is blocked on testnet with three violations; a $3K payment to an allowlisted vendor is approved and settles. Both have live transaction hashes.

Tests: 34 contract unit tests, a sandbox test deploying the real wasm to a local NEAR node, and 34 verifier tests, including one tampering test per attestation check.

Honest limits: the signing key is a stand-in, not generated inside the enclave, because NEAR AI Cloud has no intent-signing hook; TCB revocation and GPU evidence are not checked; agent prompts are scripted; settlement is a plain NEAR transfer, not Intents.

(1941 characters; limit 2,000)


## UPDATED form description (use the site's "Request changes" link; replaces the text above)

AttestGuard is a spending firewall for AI agents on NEAR. A prompt-injected agent can be tricked into draining a treasury, and a wallet signature cannot prove why a payment was approved.

A spend-envelope contract sits between the agent and the money. A payment leaves the treasury only if a reviewer model running inside NEAR AI Cloud's TEE approved that exact payment AND the owner's policy allows it.

Enclave-attested approvals (the core): NEAR AI Cloud's enclave key signs every model answer (EIP-191 over sha256(request):sha256(response)), and that is the key an Intel TDX quote binds. The contract hashes the bytes, recovers the signer with ecrecover, and requires a registered enclave key, the owner's registered model and system-prompt hash, a review under 10 minutes old, and an APPROVE echoing this vendor, amount and nonce. Editing a REJECT into an APPROVE breaks the signature; the demo does exactly that and the contract blocks it on testnet.

Policy on chain regardless of the model: vendor allowlist, rolling 24-hour cap, one-time nonces, pause switch, real transfers with rollback, EVENT_JSON logs. A fooled model still cannot pay an unlisted wallet.

Verifier (TypeScript): checks the NEAR AI Cloud TDX attestation locally (Intel root to quote, measurements, RTMR replay, compose hash), including a live quote fetched with our own nonce, in about 2 ms.

Evidence: live testnet transactions, a deployed code hash matching the repo build, 53 contract tests (one feeds a review captured live from NEAR AI Cloud to the contract unmodified), 64 verifier tests, a 25-attack threat model, CI green.

Honest limits: the owner links the enclave address to the contract (it cannot verify TDX itself); the GPU model enclave's own attestation, Intel revocation and TCB are not checked; the model can be fooled by invoice text, so policy is enforced on chain; demo invoices are scripted; settlement is a plain NEAR transfer, not Intents.

(1942 characters; limit 2,000)

## Reply to your own X post (attach demo/attestguard-demo-enclave-mode.mp4)

Update: the approval now comes from the enclave itself. A reviewer model runs inside NEAR AI Cloud's TEE; its key signs the answer; the contract verifies that signature on chain. A forged REJECT->APPROVE edit breaks the signature and is blocked on testnet. 25 attacks mapped to tests: https://github.com/v1h44n17/attestguard/blob/main/docs/THREAT_MODEL.md
