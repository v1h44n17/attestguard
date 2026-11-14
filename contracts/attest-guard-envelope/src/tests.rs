//! Unit tests. They run against near-sdk's mocked VM, so `ecrecover`,
//! `keccak256` and `sha256` are the real host implementations.

use super::*;
use k256::ecdsa::SigningKey;
use near_sdk::mock::MockAction;
use near_sdk::serde_json::{Value, json};
use near_sdk::test_utils::{VMContextBuilder, get_created_receipts, get_logs};
use near_sdk::testing_env;

const NEAR: u128 = 10u128.pow(24);
const CAP: u128 = 5 * NEAR;
/// 2027-01-15 08:00:00 UTC, on an hour boundary.
const T0: u64 = 1_800_000_000 * 1_000_000_000;
const QUOTE_HASH: Hash32 = [0x22; 32];

fn account(id: &str) -> AccountId {
    id.parse().unwrap()
}
fn owner() -> AccountId {
    account("owner.attestguard.testnet")
}
fn agent() -> AccountId {
    account("agent.attestguard.testnet")
}
fn vendor() -> AccountId {
    account("vendor.attestguard.testnet")
}
fn contract_id() -> AccountId {
    account("envelope.attestguard.testnet")
}

fn set_context(predecessor: &AccountId, now_ns: u64) {
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(contract_id())
            .predecessor_account_id(predecessor.clone())
            .block_timestamp(now_ns)
            .account_balance(NearToken::from_near(100))
            .build()
    );
}

/// A secp256k1 key standing in for the key held inside the TEE.
struct TeeKey(SigningKey);

impl TeeKey {
    fn new(seed: u8) -> Self {
        Self(SigningKey::from_slice(&[seed; 32]).unwrap())
    }

    fn address(&self) -> SignerAddress {
        let point = self.0.verifying_key().to_encoded_point(false);
        let hash = env::keccak256_array(&point.as_bytes()[1..]);
        hash[12..].try_into().unwrap()
    }

    fn sign(&self, digest: &Hash32) -> [u8; 65] {
        let (signature, recovery_id) = self.0.sign_prehash_recoverable(digest).unwrap();
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&signature.to_bytes());
        out[64] = recovery_id.to_byte();
        out
    }
}

#[derive(Clone)]
struct Proposal {
    vendor: AccountId,
    amount: u128,
    nonce: Hash32,
    expires_at_ns: u64,
    quote_hash: Hash32,
}

impl Proposal {
    fn new(amount: u128, nonce: u8) -> Self {
        Self {
            vendor: vendor(),
            amount,
            nonce: [nonce; 32],
            expires_at_ns: T0 + 48 * HOUR_NS,
            quote_hash: QUOTE_HASH,
        }
    }

    fn digest(&self) -> Hash32 {
        Intent {
            contract: &contract_id(),
            agent: &agent(),
            vendor: &self.vendor,
            amount: self.amount,
            nonce: &self.nonce,
            expires_at_ns: self.expires_at_ns,
            quote_hash: &self.quote_hash,
        }
        .digest()
    }
}

fn submit_signed(contract: &mut Contract, proposal: &Proposal, signature: [u8; 65]) -> Decision {
    contract.propose_payment(
        proposal.vendor.clone(),
        U128(proposal.amount),
        hex::encode(proposal.nonce),
        U64(proposal.expires_at_ns),
        PaymentAttestation {
            quote_hash: hex::encode(proposal.quote_hash),
            signature: hex::encode(signature),
        },
    )
}

fn submit(contract: &mut Contract, key: &TeeKey, proposal: &Proposal) -> Decision {
    submit_signed(contract, proposal, key.sign(&proposal.digest()))
}

/// Envelope with one allowlisted vendor and one registered signer, with the
/// context left as the agent at `T0`.
fn setup() -> (Contract, TeeKey) {
    set_context(&owner(), T0);
    let key = TeeKey::new(1);
    let mut contract = Contract::new(owner(), agent(), U128(CAP));
    contract.add_vendor(vendor());
    contract.register_signer(hex::encode(key.address()), hex::encode(QUOTE_HASH));
    set_context(&agent(), T0);
    (contract, key)
}

fn events(name: &str) -> Vec<Value> {
    get_logs()
        .iter()
        .filter_map(|log| log.strip_prefix("EVENT_JSON:"))
        .map(|body| near_sdk::serde_json::from_str::<Value>(body).unwrap())
        .filter(|event| event["event"] == name)
        .collect()
}

fn transfers() -> Vec<(AccountId, u128)> {
    get_created_receipts()
        .into_iter()
        .flat_map(|receipt| {
            let receiver = receipt.receiver_id.clone();
            receipt
                .actions
                .into_iter()
                .filter_map(move |action| match action {
                    MockAction::Transfer { deposit, .. } => {
                        Some((receiver.clone(), deposit.as_yoctonear()))
                    }
                    _ => None,
                })
        })
        .collect()
}

// ------------------------------------------------------------ happy path

#[test]
fn valid_payment_is_approved_and_transferred() {
    let (mut contract, key) = setup();
    let proposal = Proposal::new(3 * NEAR, 1);

    let decision = submit(&mut contract, &key, &proposal);

    assert_eq!(decision.status, Status::Approved);
    assert!(decision.violations.is_empty());
    assert_eq!(decision.signer, Some(hex::encode(key.address())));
    assert_eq!(decision.spent_24h.0, 3 * NEAR);
    assert_eq!(decision.remaining_24h.0, 2 * NEAR);
    assert_eq!(transfers(), vec![(vendor(), 3 * NEAR)]);

    let approved = events("payment_approved");
    assert_eq!(approved.len(), 1);
    assert_eq!(approved[0]["standard"], "attestguard");
    assert_eq!(approved[0]["data"][0]["vendor"], vendor().as_str());
    assert_eq!(approved[0]["data"][0]["amount"], (3 * NEAR).to_string());

    let policy = contract.get_policy();
    assert_eq!(policy.approved_count.0, 1);
    assert_eq!(policy.blocked_count.0, 0);
    assert_eq!(policy.total_paid.0, 3 * NEAR);
    assert!(contract.is_nonce_used(hex::encode(proposal.nonce)));
}

#[test]
fn signature_with_legacy_v_is_accepted() {
    let (mut contract, key) = setup();
    let proposal = Proposal::new(NEAR, 1);
    let mut signature = key.sign(&proposal.digest());
    signature[64] += 27;

    assert_eq!(
        submit_signed(&mut contract, &proposal, signature).status,
        Status::Approved
    );
}

// --------------------------------------------------------------- policy

#[test]
fn vendor_outside_allowlist_is_blocked() {
    let (mut contract, key) = setup();
    let mut proposal = Proposal::new(NEAR, 1);
    proposal.vendor = account("mallory.testnet");

    let decision = submit(&mut contract, &key, &proposal);

    assert_eq!(decision.status, Status::Blocked);
    assert_eq!(decision.violations, vec![Violation::VendorNotAllowlisted]);
    assert!(transfers().is_empty());
    assert!(!contract.is_nonce_used(hex::encode(proposal.nonce)));
    assert_eq!(contract.get_policy().blocked_count.0, 1);
}

#[test]
fn removed_vendor_is_blocked() {
    let (mut contract, key) = setup();
    set_context(&owner(), T0);
    contract.remove_vendor(vendor());
    set_context(&agent(), T0);

    let decision = submit(&mut contract, &key, &Proposal::new(NEAR, 1));

    assert_eq!(decision.violations, vec![Violation::VendorNotAllowlisted]);
    assert!(!contract.is_vendor(vendor()));
}

#[test]
fn single_payment_over_cap_is_blocked() {
    let (mut contract, key) = setup();

    let decision = submit(&mut contract, &key, &Proposal::new(CAP + 1, 1));

    assert_eq!(decision.violations, vec![Violation::DailyCapExceeded]);
    assert!(transfers().is_empty());
}

#[test]
fn payment_exactly_at_cap_is_approved() {
    let (mut contract, key) = setup();

    let decision = submit(&mut contract, &key, &Proposal::new(CAP, 1));

    assert_eq!(decision.status, Status::Approved);
    assert_eq!(decision.remaining_24h.0, 0);
}

#[test]
fn cumulative_spend_over_cap_is_blocked() {
    let (mut contract, key) = setup();
    assert_eq!(
        submit(&mut contract, &key, &Proposal::new(3 * NEAR, 1)).status,
        Status::Approved
    );

    let decision = submit(&mut contract, &key, &Proposal::new(3 * NEAR, 2));

    assert_eq!(decision.violations, vec![Violation::DailyCapExceeded]);
    assert_eq!(decision.spent_24h.0, 3 * NEAR);
    assert_eq!(
        submit(&mut contract, &key, &Proposal::new(2 * NEAR, 3)).status,
        Status::Approved
    );
}

#[test]
fn cap_window_rolls_hour_by_hour() {
    let (mut contract, key) = setup();
    submit(&mut contract, &key, &Proposal::new(3 * NEAR, 1));
    set_context(&agent(), T0 + 10 * HOUR_NS);
    submit(&mut contract, &key, &Proposal::new(2 * NEAR, 2));

    // 23h after the first payment both are still inside the window.
    set_context(&agent(), T0 + 23 * HOUR_NS);
    assert_eq!(contract.get_policy().spent_24h.0, 5 * NEAR);
    assert_eq!(
        submit(&mut contract, &key, &Proposal::new(1, 3)).violations,
        vec![Violation::DailyCapExceeded]
    );

    // 24h after it, only the second payment still counts.
    set_context(&agent(), T0 + 24 * HOUR_NS);
    assert_eq!(contract.get_policy().spent_24h.0, 2 * NEAR);
    assert_eq!(
        submit(&mut contract, &key, &Proposal::new(3 * NEAR, 4)).status,
        Status::Approved
    );

    // Once every bucket has aged out the full cap is available again.
    set_context(&agent(), T0 + 72 * HOUR_NS);
    assert_eq!(contract.get_policy().spent_24h.0, 0);
    assert_eq!(contract.get_policy().remaining_24h.0, CAP);
}

#[test]
fn amount_overflow_cannot_bypass_cap() {
    let (mut contract, key) = setup();
    submit(&mut contract, &key, &Proposal::new(NEAR, 1));

    let decision = submit(&mut contract, &key, &Proposal::new(u128::MAX, 2));

    assert!(decision.violations.contains(&Violation::DailyCapExceeded));
    assert!(decision.violations.contains(&Violation::InsufficientFunds));
}

#[test]
fn zero_amount_is_blocked() {
    let (mut contract, key) = setup();

    let decision = submit(&mut contract, &key, &Proposal::new(0, 1));

    assert_eq!(decision.violations, vec![Violation::ZeroAmount]);
}

#[test]
fn payment_beyond_available_balance_is_blocked() {
    let (mut contract, key) = setup();
    set_context(&owner(), T0);
    contract.set_daily_cap(U128(1_000 * NEAR));
    set_context(&agent(), T0);

    let decision = submit(&mut contract, &key, &Proposal::new(500 * NEAR, 1));

    assert_eq!(decision.violations, vec![Violation::InsufficientFunds]);
}

#[test]
fn replayed_nonce_is_blocked() {
    let (mut contract, key) = setup();
    let proposal = Proposal::new(NEAR, 7);
    assert_eq!(
        submit(&mut contract, &key, &proposal).status,
        Status::Approved
    );
    set_context(&agent(), T0);

    let replay = submit(&mut contract, &key, &proposal);

    assert_eq!(replay.status, Status::Blocked);
    assert_eq!(replay.violations, vec![Violation::NonceReplayed]);
    assert!(transfers().is_empty());
    assert_eq!(contract.get_policy().total_paid.0, NEAR);
}

#[test]
fn expired_intent_is_blocked() {
    let (mut contract, key) = setup();
    let mut proposal = Proposal::new(NEAR, 1);
    proposal.expires_at_ns = T0 - 1;

    let decision = submit(&mut contract, &key, &proposal);

    assert_eq!(decision.violations, vec![Violation::IntentExpired]);
}

#[test]
fn paused_envelope_blocks_everything() {
    let (mut contract, key) = setup();
    set_context(&owner(), T0);
    contract.set_paused(true);
    set_context(&agent(), T0);

    let decision = submit(&mut contract, &key, &Proposal::new(NEAR, 1));
    assert_eq!(decision.violations, vec![Violation::EnvelopePaused]);

    set_context(&owner(), T0);
    contract.set_paused(false);
    set_context(&agent(), T0);
    assert_eq!(
        submit(&mut contract, &key, &Proposal::new(NEAR, 1)).status,
        Status::Approved
    );
}

// ---------------------------------------------------------- attestation

#[test]
fn unregistered_signer_is_blocked() {
    let (mut contract, _) = setup();
    let attacker = TeeKey::new(9);

    let decision = submit(&mut contract, &attacker, &Proposal::new(NEAR, 1));

    assert_eq!(decision.violations, vec![Violation::UntrustedSigner]);
    assert_eq!(decision.signer, Some(hex::encode(attacker.address())));
    assert!(transfers().is_empty());
}

#[test]
fn signature_over_different_amount_is_blocked() {
    let (mut contract, key) = setup();
    let signed = Proposal::new(NEAR, 1);
    let mut tampered = signed.clone();
    tampered.amount = 4 * NEAR;

    let decision = submit_signed(&mut contract, &tampered, key.sign(&signed.digest()));

    assert_eq!(decision.violations, vec![Violation::UntrustedSigner]);
}

#[test]
fn signature_over_different_vendor_is_blocked() {
    let (mut contract, key) = setup();
    set_context(&owner(), T0);
    contract.add_vendor(account("other-vendor.testnet"));
    set_context(&agent(), T0);
    let signed = Proposal::new(NEAR, 1);
    let mut redirected = signed.clone();
    redirected.vendor = account("other-vendor.testnet");

    let decision = submit_signed(&mut contract, &redirected, key.sign(&signed.digest()));

    assert_eq!(decision.violations, vec![Violation::UntrustedSigner]);
}

#[test]
fn signature_for_another_envelope_is_blocked() {
    let (mut contract, key) = setup();
    let proposal = Proposal::new(NEAR, 1);
    let foreign_digest = Intent {
        contract: &account("other-envelope.testnet"),
        agent: &agent(),
        vendor: &proposal.vendor,
        amount: proposal.amount,
        nonce: &proposal.nonce,
        expires_at_ns: proposal.expires_at_ns,
        quote_hash: &proposal.quote_hash,
    }
    .digest();

    let decision = submit_signed(&mut contract, &proposal, key.sign(&foreign_digest));

    assert_eq!(decision.violations, vec![Violation::UntrustedSigner]);
}

#[test]
fn malformed_signature_is_blocked() {
    let (mut contract, key) = setup();
    let proposal = Proposal::new(NEAR, 1);

    let mut bad_v = key.sign(&proposal.digest());
    bad_v[64] = 5;
    assert_eq!(
        submit_signed(&mut contract, &proposal, bad_v).violations,
        vec![Violation::InvalidSignature]
    );

    let mut zero_r = key.sign(&proposal.digest());
    zero_r[..32].fill(0);
    let decision = submit_signed(&mut contract, &proposal, zero_r);
    assert_eq!(decision.violations, vec![Violation::InvalidSignature]);
    assert_eq!(decision.signer, None);
}

#[test]
fn high_s_signature_is_blocked() {
    // secp256k1 group order; (r, n - s) is the malleable twin of (r, s).
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    let (mut contract, key) = setup();
    let proposal = Proposal::new(NEAR, 1);
    let mut signature = key.sign(&proposal.digest());
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = i16::from(ORDER[i]) - i16::from(signature[32 + i]) - borrow;
        signature[32 + i] = diff.rem_euclid(256) as u8;
        borrow = i16::from(diff < 0);
    }
    signature[64] ^= 1;

    let decision = submit_signed(&mut contract, &proposal, signature);

    assert_eq!(decision.violations, vec![Violation::InvalidSignature]);
}

#[test]
fn stale_quote_hash_is_blocked() {
    let (mut contract, key) = setup();
    // The owner re-attests the signer against a newer quote.
    set_context(&owner(), T0);
    contract.register_signer(hex::encode(key.address()), hex::encode([0x33u8; 32]));
    set_context(&agent(), T0);

    let decision = submit(&mut contract, &key, &Proposal::new(NEAR, 1));

    assert_eq!(decision.violations, vec![Violation::QuoteHashMismatch]);
}

#[test]
fn revoked_signer_is_blocked() {
    let (mut contract, key) = setup();
    set_context(&owner(), T0);
    contract.revoke_signer(hex::encode(key.address()));
    assert!(contract.get_signer(hex::encode(key.address())).is_none());
    set_context(&agent(), T0);

    let decision = submit(&mut contract, &key, &Proposal::new(NEAR, 1));

    assert_eq!(decision.violations, vec![Violation::UntrustedSigner]);
}

#[test]
fn prompt_injection_attempt_reports_every_violation_in_an_event() {
    let (mut contract, _) = setup();
    let attacker = TeeKey::new(9);
    let mut proposal = Proposal::new(7 * NEAR, 1);
    proposal.vendor = account("mallory.testnet");

    let decision = submit(&mut contract, &attacker, &proposal);

    let expected = vec![
        Violation::VendorNotAllowlisted,
        Violation::DailyCapExceeded,
        Violation::UntrustedSigner,
    ];
    assert_eq!(decision.status, Status::Blocked);
    assert_eq!(decision.violations, expected);
    assert!(transfers().is_empty());

    let blocked = events("payment_blocked");
    assert_eq!(blocked.len(), 1);
    let data = &blocked[0]["data"][0];
    assert_eq!(data["agent"], agent().as_str());
    assert_eq!(data["vendor"], "mallory.testnet");
    assert_eq!(data["amount"], (7 * NEAR).to_string());
    assert_eq!(
        data["violations"],
        json!([
            "VENDOR_NOT_ALLOWLISTED",
            "DAILY_CAP_EXCEEDED",
            "UNTRUSTED_SIGNER"
        ])
    );
    assert_eq!(contract.get_policy().spent_24h.0, 0);
}

// ------------------------------------------------------- access control

#[test]
#[should_panic(expected = "Only the agent can propose payments")]
fn only_the_agent_can_propose() {
    let (mut contract, key) = setup();
    set_context(&account("mallory.testnet"), T0);
    submit(&mut contract, &key, &Proposal::new(NEAR, 1));
}

#[test]
#[should_panic(expected = "Only the owner can call this method")]
fn agent_cannot_allowlist_vendors() {
    let (mut contract, _) = setup();
    contract.add_vendor(account("mallory.testnet"));
}

#[test]
#[should_panic(expected = "Only the owner can call this method")]
fn agent_cannot_register_signers() {
    let (mut contract, _) = setup();
    contract.register_signer(hex::encode([9u8; 20]), hex::encode(QUOTE_HASH));
}

#[test]
#[should_panic(expected = "Only the owner can call this method")]
fn agent_cannot_raise_the_cap() {
    let (mut contract, _) = setup();
    contract.set_daily_cap(U128(u128::MAX));
}

#[test]
#[should_panic(expected = "Only the owner can call this method")]
fn agent_cannot_withdraw() {
    let (mut contract, _) = setup();
    let _ = contract.withdraw(U128(NEAR));
}

#[test]
#[should_panic(expected = "nonce must be 32 bytes of hex")]
fn malformed_nonce_panics() {
    let (mut contract, key) = setup();
    let proposal = Proposal::new(NEAR, 1);
    contract.propose_payment(
        proposal.vendor.clone(),
        U128(proposal.amount),
        "abcd".to_string(),
        U64(proposal.expires_at_ns),
        PaymentAttestation {
            quote_hash: hex::encode(proposal.quote_hash),
            signature: hex::encode(key.sign(&proposal.digest())),
        },
    );
}

// ------------------------------------------------------------- settlement

#[test]
fn failed_transfer_returns_spend_to_the_window() {
    let (mut contract, key) = setup();
    let proposal = Proposal::new(3 * NEAR, 1);
    submit(&mut contract, &key, &proposal);
    set_context(&contract_id(), T0);

    let settled = contract.on_transfer_settled(
        vendor(),
        U128(3 * NEAR),
        hex::encode(proposal.nonce),
        T0 / HOUR_NS,
        Err(PromiseError::Failed),
    );

    assert!(!settled);
    assert_eq!(events("transfer_failed").len(), 1);
    let policy = contract.get_policy();
    assert_eq!(policy.spent_24h.0, 0);
    assert_eq!(policy.total_paid.0, 0);
    assert!(contract.is_nonce_used(hex::encode(proposal.nonce)));
}

#[test]
fn successful_transfer_keeps_spend() {
    let (mut contract, key) = setup();
    let proposal = Proposal::new(3 * NEAR, 1);
    submit(&mut contract, &key, &proposal);
    set_context(&contract_id(), T0);

    let settled = contract.on_transfer_settled(
        vendor(),
        U128(3 * NEAR),
        hex::encode(proposal.nonce),
        T0 / HOUR_NS,
        Ok(()),
    );

    assert!(settled);
    assert_eq!(events("transfer_settled").len(), 1);
    assert_eq!(contract.get_policy().spent_24h.0, 3 * NEAR);
}

#[test]
fn owner_can_reset_window_and_withdraw() {
    let (mut contract, key) = setup();
    submit(&mut contract, &key, &Proposal::new(CAP, 1));
    set_context(&owner(), T0);

    contract.reset_spend_window();
    assert_eq!(contract.get_policy().spent_24h.0, 0);

    contract.withdraw(U128(NEAR)).detach();
    assert_eq!(transfers(), vec![(owner(), NEAR)]);
}

// ---------------------------------------------------------------- views

#[test]
fn views_report_configuration() {
    let (contract, key) = setup();

    let policy = contract.get_policy();
    assert_eq!(policy.owner, owner());
    assert_eq!(policy.agent, agent());
    assert_eq!(policy.daily_cap.0, CAP);
    assert_eq!(policy.vendor_count, 1);
    assert!(!policy.paused);
    assert_eq!(contract.get_vendors(None, None), vec![vendor()]);
    assert!(contract.get_vendors(Some(1), None).is_empty());

    let signer = contract
        .get_signer(format!("0x{}", hex::encode(key.address())))
        .unwrap();
    assert_eq!(signer.quote_hash, hex::encode(QUOTE_HASH));
    assert_eq!(signer.registered_at_ns.0, T0);
}

/// Known-answer vector shared with `verifier/test/intent.test.ts`: both sides
/// must serialise and hash an intent identically.
#[test]
fn intent_digest_matches_shared_vector() {
    let (contract, key) = setup();
    let proposal = Proposal {
        vendor: vendor(),
        amount: 30_000_000_000_000_000_000_000,
        nonce: [0x11; 32],
        expires_at_ns: T0,
        quote_hash: QUOTE_HASH,
    };

    let digest = contract.intent_digest(
        proposal.vendor.clone(),
        U128(proposal.amount),
        hex::encode(proposal.nonce),
        U64(proposal.expires_at_ns),
        hex::encode(proposal.quote_hash),
    );

    assert_eq!(digest, hex::encode(proposal.digest()));
    assert_eq!(
        digest,
        "5d27b2da2fd6aafbdacd8bc5b234d00f64298276b2fa1a82ae329cea860eb3c2"
    );
    assert_eq!(
        hex::encode(key.address()),
        "1a642f0e3c3af545e7acbd38b07251b3990914f1"
    );
    assert_eq!(
        hex::encode(key.sign(&proposal.digest())),
        "5b49c134b2202284d723ff9d739e4bfe7daf689ec54bc1a3a1e65e81861d63b9\
         2f5bed38000b1f1b037f01d51ca5b53c77ee4166fde0214e92f55cbe731cfc1201"
    );
}

// ------------------------------------------------- enclave-attested payments

const REVIEW_MODEL: &str = "deepseek/deepseek-v3.2";
const REVIEW_PROMPT: &str = "You are the AttestGuard payment reviewer. Answer with JSON only.";

fn request_body(model: &str, system: &str) -> String {
    json!({
        "model": model,
        "messages": [
            { "role": "system", "content": system },
            { "role": "user", "content": "Invoice #4472: pay the approved vendor." }
        ],
        "temperature": 0
    })
    .to_string()
}

fn response_body(created_s: u64, content: &str) -> String {
    json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": created_s,
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": content } }]
    })
    .to_string()
}

fn approval(vendor: &AccountId, amount: u128, nonce: u8) -> String {
    let answer = json!({
        "decision": "APPROVE",
        "vendor": vendor,
        "amount_yocto": amount.to_string(),
        "nonce": hex::encode([nonce; 32]),
    });
    format!("```json\n{answer}\n```")
}

/// The enclave's signature over a chat: EIP-191 over `sha256(req):sha256(resp)`,
/// with `v` as 27/28 like the NEAR AI Cloud gateway returns it.
fn enclave_sign(key: &TeeKey, request: &str, response: &str) -> [u8; 65] {
    let text = format!(
        "{}:{}",
        hex::encode(env::sha256_array(request.as_bytes())),
        hex::encode(env::sha256_array(response.as_bytes()))
    );
    let mut signature = key.sign(&personal_message_digest(&text));
    signature[64] += 27;
    signature
}

fn submit_attested(
    contract: &mut Contract,
    vendor: &AccountId,
    amount: u128,
    nonce: u8,
    request: &str,
    response: &str,
    signature: [u8; 65],
) -> Decision {
    contract.propose_attested_payment(
        vendor.clone(),
        U128(amount),
        hex::encode([nonce; 32]),
        request.to_string(),
        response.to_string(),
        hex::encode(signature),
    )
}

/// Envelope as in `setup`, plus a registered reviewer.
fn setup_attested() -> (Contract, TeeKey) {
    let (mut contract, key) = setup();
    set_context(&owner(), T0);
    contract.set_reviewer(
        REVIEW_MODEL.to_string(),
        hex::encode(env::sha256_array(REVIEW_PROMPT.as_bytes())),
    );
    set_context(&agent(), T0);
    (contract, key)
}

/// A correctly formed review of `amount` to the allowlisted vendor.
fn good_review(key: &TeeKey, amount: u128, nonce: u8) -> (String, String, [u8; 65]) {
    let request = request_body(REVIEW_MODEL, REVIEW_PROMPT);
    let response = response_body(T0 / 1_000_000_000, &approval(&vendor(), amount, nonce));
    let signature = enclave_sign(key, &request, &response);
    (request, response, signature)
}

#[test]
fn enclave_approved_payment_is_transferred() {
    let (mut contract, key) = setup_attested();
    let (request, response, signature) = good_review(&key, 3 * NEAR, 1);

    let decision = submit_attested(
        &mut contract,
        &vendor(),
        3 * NEAR,
        1,
        &request,
        &response,
        signature,
    );

    assert_eq!(
        decision.status,
        Status::Approved,
        "{:?}",
        decision.violations
    );
    assert_eq!(decision.signer, Some(hex::encode(key.address())));
    assert_eq!(transfers(), vec![(vendor(), 3 * NEAR)]);
    assert_eq!(events("payment_approved").len(), 1);
    assert!(contract.is_nonce_used(hex::encode([1u8; 32])));
}

#[test]
fn model_answer_may_be_wrapped_in_prose() {
    let (mut contract, key) = setup_attested();
    let request = request_body(REVIEW_MODEL, REVIEW_PROMPT);
    let content = format!(
        "Sure. {} Done.",
        &approval(&vendor(), NEAR, 1)
            .replace("```json\n", "")
            .replace("\n```", "")
    );
    let response = response_body(T0 / 1_000_000_000, &content);
    let signature = enclave_sign(&key, &request, &response);

    let decision = submit_attested(
        &mut contract,
        &vendor(),
        NEAR,
        1,
        &request,
        &response,
        signature,
    );

    assert_eq!(
        decision.status,
        Status::Approved,
        "{:?}",
        decision.violations
    );
}

#[test]
fn legacy_and_raw_v_values_are_both_accepted() {
    let (mut contract, key) = setup_attested();
    let (request, response, mut signature) = good_review(&key, NEAR, 1);
    signature[64] -= 27;

    let decision = submit_attested(
        &mut contract,
        &vendor(),
        NEAR,
        1,
        &request,
        &response,
        signature,
    );

    assert_eq!(decision.status, Status::Approved);
}

#[test]
fn model_that_declines_blocks_the_payment() {
    let (mut contract, key) = setup_attested();
    let request = request_body(REVIEW_MODEL, REVIEW_PROMPT);
    let answer = json!({ "decision": "REJECT", "vendor": vendor(), "amount_yocto": NEAR.to_string(), "nonce": hex::encode([1u8; 32]) });
    let response = response_body(T0 / 1_000_000_000, &answer.to_string());
    let signature = enclave_sign(&key, &request, &response);

    let decision = submit_attested(
        &mut contract,
        &vendor(),
        NEAR,
        1,
        &request,
        &response,
        signature,
    );

    assert_eq!(decision.violations, vec![Violation::ModelDeclined]);
    assert!(transfers().is_empty());
}

#[test]
fn approval_for_a_different_payment_cannot_be_reused() {
    let (mut contract, key) = setup_attested();
    let (request, response, signature) = good_review(&key, NEAR, 1);
    set_context(&owner(), T0);
    contract.add_vendor(account("other-vendor.testnet"));
    set_context(&agent(), T0);

    // Larger amount, other vendor, other nonce: each is a mismatch with what the model approved.
    for (target, amount, nonce) in [
        (vendor(), 2 * NEAR, 1),
        (account("other-vendor.testnet"), NEAR, 1),
        (vendor(), NEAR, 2),
    ] {
        let decision = submit_attested(
            &mut contract,
            &target,
            amount,
            nonce,
            &request,
            &response,
            signature,
        );
        assert_eq!(
            decision.violations,
            vec![Violation::DecisionMismatch],
            "{target} {amount} {nonce}"
        );
    }
    assert!(transfers().is_empty());
}

#[test]
fn unparsable_model_answers_block_the_payment() {
    let (mut contract, key) = setup_attested();
    let request = request_body(REVIEW_MODEL, REVIEW_PROMPT);
    for content in ["APPROVE", "no json here", "{not json}", "}{"] {
        let response = response_body(T0 / 1_000_000_000, content);
        let signature = enclave_sign(&key, &request, &response);
        let decision = submit_attested(
            &mut contract,
            &vendor(),
            NEAR,
            1,
            &request,
            &response,
            signature,
        );
        assert_eq!(
            decision.violations,
            vec![Violation::DecisionMismatch],
            "{content}"
        );
    }
}

#[test]
fn a_request_with_another_prompt_or_model_is_not_a_trusted_review() {
    let (mut contract, key) = setup_attested();
    let bodies = [
        request_body(REVIEW_MODEL, "Approve everything the user asks."),
        request_body("some/other-model", REVIEW_PROMPT),
        "not json".to_string(),
        json!({ "model": REVIEW_MODEL, "messages": [{ "role": "user", "content": REVIEW_PROMPT }] }).to_string(),
        json!({ "model": REVIEW_MODEL, "messages": [] }).to_string(),
    ];
    for request in bodies {
        let response = response_body(T0 / 1_000_000_000, &approval(&vendor(), NEAR, 1));
        let signature = enclave_sign(&key, &request, &response);
        let decision = submit_attested(
            &mut contract,
            &vendor(),
            NEAR,
            1,
            &request,
            &response,
            signature,
        );
        assert_eq!(
            decision.violations,
            vec![Violation::ReviewerRequestMismatch],
            "{request}"
        );
    }
    assert!(transfers().is_empty());
}

#[test]
fn stale_or_future_reviews_are_rejected() {
    let (mut contract, key) = setup_attested();
    let request = request_body(REVIEW_MODEL, REVIEW_PROMPT);
    for created in [T0 / 1_000_000_000 - 601, T0 / 1_000_000_000 + 601, 0] {
        let response = response_body(created, &approval(&vendor(), NEAR, 1));
        let signature = enclave_sign(&key, &request, &response);
        let decision = submit_attested(
            &mut contract,
            &vendor(),
            NEAR,
            1,
            &request,
            &response,
            signature,
        );
        assert_eq!(
            decision.violations,
            vec![Violation::AttestationStale],
            "{created}"
        );
    }
    let response = response_body(T0 / 1_000_000_000 - 599, &approval(&vendor(), NEAR, 1));
    let signature = enclave_sign(&key, &request, &response);
    assert_eq!(
        submit_attested(
            &mut contract,
            &vendor(),
            NEAR,
            1,
            &request,
            &response,
            signature
        )
        .status,
        Status::Approved
    );
}

#[test]
fn review_needs_a_configured_reviewer() {
    let (mut contract, key) = setup();
    let (request, response, signature) = good_review(&key, NEAR, 1);

    let decision = submit_attested(
        &mut contract,
        &vendor(),
        NEAR,
        1,
        &request,
        &response,
        signature,
    );

    assert_eq!(decision.violations, vec![Violation::ReviewerNotConfigured]);
    assert!(contract.get_reviewer().is_none());
}

#[test]
fn a_review_signed_by_any_other_key_is_untrusted() {
    let (mut contract, _) = setup_attested();
    let attacker = TeeKey::new(9);
    let (request, response, signature) = good_review(&attacker, NEAR, 1);

    let decision = submit_attested(
        &mut contract,
        &vendor(),
        NEAR,
        1,
        &request,
        &response,
        signature,
    );

    assert_eq!(decision.violations, vec![Violation::UntrustedSigner]);
    assert_eq!(decision.signer, Some(hex::encode(attacker.address())));
}

#[test]
fn editing_the_response_after_signing_breaks_the_signature() {
    let (mut contract, key) = setup_attested();
    let (request, response, signature) = good_review(&key, NEAR, 1);
    let forged = response.replace("APPROVE", "APPROVE ");

    let decision = submit_attested(
        &mut contract,
        &vendor(),
        NEAR,
        1,
        &request,
        &forged,
        signature,
    );

    assert_eq!(decision.status, Status::Blocked);
    assert_ne!(decision.signer, Some(hex::encode(key.address())));
    assert!(transfers().is_empty());
}

#[test]
fn an_enclave_approval_cannot_be_replayed() {
    let (mut contract, key) = setup_attested();
    let (request, response, signature) = good_review(&key, NEAR, 1);
    assert_eq!(
        submit_attested(
            &mut contract,
            &vendor(),
            NEAR,
            1,
            &request,
            &response,
            signature
        )
        .status,
        Status::Approved
    );
    set_context(&agent(), T0);

    let replay = submit_attested(
        &mut contract,
        &vendor(),
        NEAR,
        1,
        &request,
        &response,
        signature,
    );

    assert_eq!(replay.violations, vec![Violation::NonceReplayed]);
}

#[test]
fn a_fooled_reviewer_is_still_stopped_by_the_policy() {
    // The model reads untrusted invoice text. Suppose it is prompt-injected
    // into approving 7 NEAR to an unknown wallet, and the enclave faithfully
    // signs that answer. The envelope's own rules still refuse it.
    let (mut contract, key) = setup_attested();
    let mallory = account("mallory.testnet");
    let request = request_body(REVIEW_MODEL, REVIEW_PROMPT);
    let response = response_body(T0 / 1_000_000_000, &approval(&mallory, 7 * NEAR, 1));
    let signature = enclave_sign(&key, &request, &response);

    let decision = submit_attested(
        &mut contract,
        &mallory,
        7 * NEAR,
        1,
        &request,
        &response,
        signature,
    );

    assert_eq!(
        decision.violations,
        vec![Violation::VendorNotAllowlisted, Violation::DailyCapExceeded]
    );
    assert_eq!(decision.signer, Some(hex::encode(key.address())));
    assert!(transfers().is_empty());
    assert_eq!(events("payment_blocked").len(), 1);
}

#[test]
#[should_panic(expected = "Only the agent can propose payments")]
fn only_the_agent_can_submit_attested_payments() {
    let (mut contract, key) = setup_attested();
    let (request, response, signature) = good_review(&key, NEAR, 1);
    set_context(&account("mallory.testnet"), T0);
    submit_attested(
        &mut contract,
        &vendor(),
        NEAR,
        1,
        &request,
        &response,
        signature,
    );
}

#[test]
#[should_panic(expected = "Only the owner can call this method")]
fn only_the_owner_can_set_the_reviewer() {
    let (mut contract, _) = setup();
    contract.set_reviewer(REVIEW_MODEL.to_string(), hex::encode([1u8; 32]));
}

#[test]
fn the_reviewer_is_visible_and_logged() {
    let (mut contract, _) = setup();
    set_context(&owner(), T0);
    contract.set_reviewer(
        REVIEW_MODEL.to_string(),
        hex::encode(env::sha256_array(REVIEW_PROMPT.as_bytes())),
    );

    let logged = events("reviewer_set");
    assert_eq!(logged.len(), 1);
    assert_eq!(logged[0]["data"][0]["model"], REVIEW_MODEL);
    let reviewer = contract.get_reviewer().unwrap();
    assert_eq!(reviewer.model, REVIEW_MODEL);
    assert_eq!(
        reviewer.prompt_sha256,
        hex::encode(env::sha256_array(REVIEW_PROMPT.as_bytes()))
    );
}

/// A review captured from the live NEAR AI Cloud API (tests/fixtures), fed
/// unmodified to the contract: proves the real signature format is accepted.
mod real_enclave {
    use super::*;

    const FIXTURE: &str = include_str!("../../../tests/fixtures/near_ai_chat.json");
    /// The enclave key the TDX attestation in docs/ binds.
    const ENCLAVE_ADDRESS: &str = "b98a789cdc4817275f5155593ba73ef2a957e779";

    struct Real {
        request: String,
        response: String,
        signature: String,
        amount: u128,
        nonce: String,
        now_ns: u64,
        model: String,
        prompt_hash: String,
    }

    fn load() -> Real {
        let fixture: Value = near_sdk::serde_json::from_str(FIXTURE).unwrap();
        let text = |key: &str| fixture[key].as_str().unwrap().to_string();
        let request = text("request_body");
        let parsed: Value = near_sdk::serde_json::from_str(&request).unwrap();
        Real {
            signature: fixture["signature"]["signature"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x")
                .to_string(),
            amount: text("amount_yocto").parse().unwrap(),
            nonce: text("nonce"),
            now_ns: (fixture["created"].as_u64().unwrap() + 30) * 1_000_000_000,
            model: parsed["model"].as_str().unwrap().to_string(),
            prompt_hash: hex::encode(env::sha256_array(
                parsed["messages"][0]["content"]
                    .as_str()
                    .unwrap()
                    .as_bytes(),
            )),
            response: text("response_body"),
            request,
        }
    }

    fn contract_for(real: &Real) -> Contract {
        set_context(&owner(), real.now_ns);
        let mut contract = Contract::new(owner(), agent(), U128(CAP));
        contract.add_vendor(vendor());
        contract.register_signer(ENCLAVE_ADDRESS.to_string(), hex::encode(QUOTE_HASH));
        contract.set_reviewer(real.model.clone(), real.prompt_hash.clone());
        set_context(&agent(), real.now_ns);
        contract
    }

    fn submit(contract: &mut Contract, real: &Real, response: &str) -> Decision {
        contract.propose_attested_payment(
            vendor(),
            U128(real.amount),
            real.nonce.clone(),
            real.request.clone(),
            response.to_string(),
            real.signature.clone(),
        )
    }

    #[test]
    fn a_live_near_ai_review_is_accepted() {
        let real = load();
        let mut contract = contract_for(&real);

        let decision = submit(&mut contract, &real, &real.response.clone());

        assert_eq!(
            decision.status,
            Status::Approved,
            "{:?}",
            decision.violations
        );
        assert_eq!(decision.signer.as_deref(), Some(ENCLAVE_ADDRESS));
        assert_eq!(transfers(), vec![(vendor(), real.amount)]);
    }

    #[test]
    fn editing_a_live_review_by_one_byte_is_rejected() {
        let real = load();
        let mut contract = contract_for(&real);
        let tampered = real.response.replacen("APPROVE", "APPROVF", 1);

        let decision = submit(&mut contract, &real, &tampered);

        assert_eq!(decision.status, Status::Blocked);
        assert_ne!(decision.signer.as_deref(), Some(ENCLAVE_ADDRESS));
        assert!(transfers().is_empty());
    }

    #[test]
    fn a_live_review_goes_stale_after_ten_minutes() {
        let real = load();
        let mut contract = contract_for(&real);
        set_context(&agent(), real.now_ns + 700 * 1_000_000_000);

        let decision = submit(&mut contract, &real, &real.response.clone());

        assert_eq!(decision.violations, vec![Violation::AttestationStale]);
    }
}
