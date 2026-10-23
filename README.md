# AttestGuard: The TEE Attested Spending Firewall
**Track:** AI Security & Defense

## The Problem
AI agents can now hold wallets and execute cross-chain payments. However, a prompt-injected agent can be tricked into draining a treasury, and a standard wallet signature cannot prove *why* a payment was approved. Current policy files are not cryptographically secure.

## The Solution
AttestGuard is a safety layer that sits between the AI agent and NEAR Intents. It uses NEAR AI Cloud (Intel TDX secure enclaves) to run a reviewer model that checks every payment against a pre-signed spend envelope (max amount, allowlisted vendors). Funds are released only when the TEE returns a cryptographically signed attestation proving the model's reasoning matches the rules.

## How it Works (The Flow)
1. **Business:** Sets a spend envelope (e.g., Max $5,000/day to Vendor X).
2. **Agent:** Proposes a payment via NEAR Intents.
3. **Reviewer:** NEAR AI Cloud runs the model inside a TEE.
4. **Attestation:** The TEE returns an `intel_quote` proving the model ran securely.
5. **Firewall:** AttestGuard verifies the quote and the reasoning. If it exceeds the envelope, it blocks the transaction.
6. **Settlement:** If approved, NEAR Chain Signatures sign the transaction, and NEAR Intents settles it.

## How to Run It (Demo)
*To be completed during the hackathon.*
- Step 1: `npm install` or `pip install -r requirements.txt`
- Step 2: Run `python demo_blocked.py` to see a prompt-injected agent get blocked.
- Step 3: Run `python demo_settled.py` to see a valid payment settle via NEAR Intents.

## Threat Model
* **Defended:** Prompt injection, agent impersonation, unauthorized spending.
* **Not Defended:** Compromised Intel TDX hardware, stolen business signing keys. Production requires MPC fallback.
