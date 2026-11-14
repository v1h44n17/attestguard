# Submission assets (not part of the product; delete before or after submitting)

## X post (tag @NEARProtocol and #NEARHackathon, attach a screen recording of the console)

I built AttestGuard at NEAR HACKATHON: a spending firewall for AI agents.

A prompt-injected agent tries to wire $7K to an unknown wallet. Blocked on-chain, 3 violations logged. A legit $3K
invoice to an approved vendor settles. Intel TDX quote verified locally in ~1 ms.

Live on testnet. Code: https://github.com/v1h44n17/attestguard

@NEARProtocol #NEARHackathon

## Form description (paste into "What did you build?")

AttestGuard is a spending firewall for AI agents on NEAR. Agents can now hold wallets, but a prompt-injected agent can be tricked into draining a treasury, and a plain wallet signature cannot prove why a payment was approved.

AttestGuard puts a spend envelope contract between the agent and the money. A payment leaves the treasury only if it fits the owner's policy AND the exact payment intent was signed by a key bound to a verified Intel TDX quote from NEAR AI Cloud.

Contract (Rust, near-sdk): vendor allowlist, rolling 24-hour cap (a fixed 24-slot ring buffer, constant cost), nonce replay protection, intent expiry, pause switch, and on-chain secp256k1 signature recovery over the exact intent (contract and agent ids included, high-S rejected). Approved payments run a real Promise transfer with a rollback callback; blocked ones succeed, listing every violated rule in an EVENT_JSON log.

Verifier (TypeScript): checks the real NEAR AI Cloud attestation locally with no network: quote signature, Quoting Enclave binding, PCK chain to the pinned Intel SGX Root CA, TD report data binding the signer and nonce, measurements, a 28-event RTMR replay, and the compose hash. The full gate (verify, review, sign) takes about 0.4 ms median, 0.7 ms p99.

Console: a terminal-style dashboard with a one-click scenario. A prompt-injected $7K transfer to an unknown wallet is blocked on testnet with three violations; a $3K payment to an allowlisted vendor is approved and settles. Both have live transaction hashes.

Tests: 34 contract unit tests, a sandbox test deploying the real wasm to a local NEAR node, and 34 verifier tests, including one tampering test per attestation check.

Honest limits: the signing key is a stand-in, not generated inside the enclave, because NEAR AI Cloud has no intent-signing hook; TCB revocation and GPU evidence are not checked; agent prompts are scripted; settlement is a plain NEAR transfer, not Intents.

(1941 characters; limit 2,000)
