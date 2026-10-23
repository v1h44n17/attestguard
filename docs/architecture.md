# Architecture & Spend Envelope Schema

## Spend Envelope Schema (NEAR Smart Contract)
The contract will store the following state:
- `owner`: AccountId (The business)
- `agent_account`: AccountId (The AI agent)
- `max_amount_per_day`: u128 (In yoctoNEAR or USDC decimals)
- `allowlisted_vendors`: UnorderedSet<AccountId>
- `nonce`: String (To prevent replay attacks)

## Data Flow
1. Agent calls `propose_payment(amount, vendor, nonce)`.
2. Contract calls out to the Attestation Verifier (Python/Node.js off-chain agent).
3. Verifier checks `sample_attestation.json` to ensure the `intel_quote` is valid and the `event_log` matches the expected DeepSeek model.
4. If valid, the Verifier submits a signed transaction to release the funds via NEAR Intents.
