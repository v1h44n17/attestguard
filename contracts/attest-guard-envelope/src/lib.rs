//! AttestGuard spend envelope.
//!
//! A treasury contract that only releases funds to an AI agent's proposed
//! payment when two independent conditions hold:
//!
//! 1. **Policy** – the payment fits the owner's envelope: allowlisted vendor,
//!    rolling 24-hour cap, unused nonce, unexpired intent, sufficient funds.
//! 2. **Attestation** – the exact payment intent was signed (secp256k1) by a
//!    key the owner registered together with the SHA-256 of the TEE quote that
//!    vouches for it. The signature is checked on-chain with `ecrecover`.
//!
//! Policy violations do not panic: the call succeeds, returns a `BLOCKED`
//! decision and emits a NEP-297 `EVENT_JSON` log, so every blocked attempt
//! leaves an auditable on-chain trace. (A panic would revert the log.)

use near_sdk::json_types::{U64, U128};
use near_sdk::serde::Serialize;
use near_sdk::serde_json::Value;
use near_sdk::store::{IterableSet, LookupMap, LookupSet};
use near_sdk::{
    AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault, Promise, PromiseError, env, near,
    require,
};

#[cfg(test)]
mod tests;

/// 20-byte Ethereum-style address: `keccak256(pubkey)[12..]`.
pub type SignerAddress = [u8; 20];
/// 32-byte hash (nonce, quote hash, digest).
pub type Hash32 = [u8; 32];

const HOUR_NS: u64 = 3_600_000_000_000;
/// The spending cap covers the current hour bucket plus the 23 before it.
const WINDOW_HOURS: u64 = 24;
const WINDOW_SLOTS: usize = WINDOW_HOURS as usize;
const CALLBACK_GAS: Gas = Gas::from_tgas(8);
const MAX_PAGE: u32 = 100;
/// An enclave-signed review is only accepted this long after the model produced it.
const MAX_REVIEW_AGE_NS: u64 = 600_000_000_000;
/// Domain separator: first line of every signed payment intent.
pub const INTENT_DOMAIN: &str = "attestguard-intent-v1";

const EVENT_STANDARD: &str = "attestguard";
const EVENT_VERSION: &str = "1.0.0";

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Vendors,
    Nonces,
    Signers,
}

/// One hour of spending. A slot is live only while `hour` is inside the window.
#[near(serializers = [borsh])]
#[derive(Clone, Copy, Default)]
pub struct SpendBucket {
    hour: u64,
    spent: u128,
}

/// The model and system prompt the owner trusts to review payments.
#[near(serializers = [borsh])]
#[derive(Clone)]
pub struct ReviewerConfig {
    model: String,
    prompt_hash: Hash32,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct ReviewerView {
    pub model: String,
    pub prompt_sha256: String,
}

#[near(serializers = [borsh])]
#[derive(Clone)]
pub struct SignerRecord {
    quote_hash: Hash32,
    registered_at_ns: u64,
}

/// Why a payment was refused. Every failed check is reported, not just the first.
#[near(serializers = [json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Violation {
    EnvelopePaused,
    ZeroAmount,
    VendorNotAllowlisted,
    DailyCapExceeded,
    NonceReplayed,
    IntentExpired,
    InsufficientFunds,
    InvalidSignature,
    UntrustedSigner,
    QuoteHashMismatch,
    ReviewerNotConfigured,
    ReviewerRequestMismatch,
    ModelDeclined,
    DecisionMismatch,
    AttestationStale,
}

#[near(serializers = [json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Approved,
    Blocked,
}

/// Attestation accompanying a payment intent.
#[near(serializers = [json])]
#[derive(Clone)]
pub struct PaymentAttestation {
    /// Hex SHA-256 of the raw TEE quote the signing key is bound to.
    pub quote_hash: String,
    /// Hex 65-byte recoverable secp256k1 signature `r || s || v` over the
    /// intent digest. `v` may be 0/1 or 27/28.
    pub signature: String,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct Decision {
    pub status: Status,
    pub violations: Vec<Violation>,
    pub vendor: AccountId,
    pub amount: U128,
    pub nonce: String,
    /// Hex address recovered from the signature, if recovery succeeded.
    pub signer: Option<String>,
    pub spent_24h: U128,
    pub remaining_24h: U128,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct PolicyView {
    pub owner: AccountId,
    pub agent: AccountId,
    pub daily_cap: U128,
    pub spent_24h: U128,
    pub remaining_24h: U128,
    pub available_balance: U128,
    pub paused: bool,
    pub vendor_count: u32,
    pub approved_count: U64,
    pub blocked_count: U64,
    pub total_paid: U128,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct SignerView {
    pub address: String,
    pub quote_hash: String,
    pub registered_at_ns: U64,
}

/// The fields a TEE signer commits to. Serialised by [`Intent::digest`].
pub struct Intent<'a> {
    pub contract: &'a AccountId,
    pub agent: &'a AccountId,
    pub vendor: &'a AccountId,
    pub amount: u128,
    pub nonce: &'a Hash32,
    pub expires_at_ns: u64,
    pub quote_hash: &'a Hash32,
}

impl Intent<'_> {
    /// Canonical newline-delimited message. Binding the contract and agent
    /// account ids stops a signature being replayed against another envelope.
    pub fn message(&self) -> String {
        format!(
            "{INTENT_DOMAIN}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.contract,
            self.agent,
            self.vendor,
            self.amount,
            hex::encode(self.nonce),
            self.expires_at_ns,
            hex::encode(self.quote_hash),
        )
    }

    pub fn digest(&self) -> Hash32 {
        env::sha256_array(self.message().as_bytes())
    }
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner: AccountId,
    agent: AccountId,
    daily_cap: u128,
    paused: bool,
    vendors: IterableSet<AccountId>,
    used_nonces: LookupSet<Hash32>,
    signers: LookupMap<SignerAddress, SignerRecord>,
    reviewer: Option<ReviewerConfig>,
    /// Ring buffer of hourly spend, indexed by `hour % 24`. Fixed size, so the
    /// rolling-window sum costs the same no matter how many payments were made.
    window: [SpendBucket; WINDOW_SLOTS],
    approved_count: u64,
    blocked_count: u64,
    total_paid: u128,
}

#[near]
impl Contract {
    #[init]
    pub fn new(owner: AccountId, agent: AccountId, daily_cap: U128) -> Self {
        Self {
            owner,
            agent,
            daily_cap: daily_cap.0,
            paused: false,
            vendors: IterableSet::new(StorageKey::Vendors),
            used_nonces: LookupSet::new(StorageKey::Nonces),
            signers: LookupMap::new(StorageKey::Signers),
            reviewer: None,
            window: [SpendBucket::default(); WINDOW_SLOTS],
            approved_count: 0,
            blocked_count: 0,
            total_paid: 0,
        }
    }

    // ---------------------------------------------------------------- agent

    /// Propose a payment. Callable only by the agent account.
    ///
    /// Returns `APPROVED` and transfers `amount` yoctoNEAR to `vendor`, or
    /// returns `BLOCKED` with every violated rule. Malformed input (bad hex,
    /// wrong lengths) and calls from any other account panic instead.
    pub fn propose_payment(
        &mut self,
        vendor: AccountId,
        amount: U128,
        nonce: String,
        expires_at_ns: U64,
        attestation: PaymentAttestation,
    ) -> Decision {
        require!(
            env::predecessor_account_id() == self.agent,
            "Only the agent can propose payments"
        );
        let nonce_bytes: Hash32 = decode_hex(&nonce, "nonce");
        let quote_hash: Hash32 = decode_hex(&attestation.quote_hash, "quote_hash");
        let signature: [u8; 65] = decode_hex(&attestation.signature, "signature");
        let digest = Intent {
            contract: &env::current_account_id(),
            agent: &self.agent,
            vendor: &vendor,
            amount: amount.0,
            nonce: &nonce_bytes,
            expires_at_ns: expires_at_ns.0,
            quote_hash: &quote_hash,
        }
        .digest();
        let signer = recover_signer(&digest, &signature);
        let mut auth = Authorization {
            signer,
            violations: Vec::new(),
        };
        match signer.and_then(|address| self.signers.get(&address)) {
            None if signer.is_none() => auth.violations.push(Violation::InvalidSignature),
            None => auth.violations.push(Violation::UntrustedSigner),
            Some(record) if record.quote_hash != quote_hash => {
                auth.violations.push(Violation::QuoteHashMismatch)
            }
            Some(_) => {}
        }
        self.decide(vendor, amount.0, nonce_bytes, Some(expires_at_ns.0), auth)
    }

    /// Propose a payment authorised by the enclave itself.
    ///
    /// `request_body` and `response_body` are the exact bytes of a NEAR AI
    /// Cloud chat completion, and `enclave_signature` is the signature the
    /// cloud returns for it: an EIP-191 personal signature by the enclave key
    /// over `sha256(request):sha256(response)`. The contract recomputes both
    /// hashes, recovers the signer, and requires that signer to be registered.
    /// It then requires that the request used the owner's registered model and
    /// system prompt, that the review is recent, and that the model's JSON
    /// answer is `APPROVE` for exactly this vendor, amount and nonce.
    ///
    /// The model reads untrusted invoice text, so its approval is evidence of
    /// what the enclave decided, not a replacement for the policy checks, which
    /// still apply in full.
    pub fn propose_attested_payment(
        &mut self,
        vendor: AccountId,
        amount: U128,
        nonce: String,
        request_body: String,
        response_body: String,
        enclave_signature: String,
    ) -> Decision {
        require!(
            env::predecessor_account_id() == self.agent,
            "Only the agent can propose payments"
        );
        let nonce_bytes: Hash32 = decode_hex(&nonce, "nonce");
        let signature: [u8; 65] = decode_hex(&enclave_signature, "enclave_signature");
        let text = format!(
            "{}:{}",
            hex::encode(env::sha256_array(request_body.as_bytes())),
            hex::encode(env::sha256_array(response_body.as_bytes()))
        );
        let signer = recover_signer(&personal_message_digest(&text), &signature);
        let mut auth = Authorization {
            signer,
            violations: Vec::new(),
        };
        match signer {
            None => auth.violations.push(Violation::InvalidSignature),
            Some(address) if self.signers.get(&address).is_none() => {
                auth.violations.push(Violation::UntrustedSigner)
            }
            Some(_) => {}
        }
        auth.violations.extend(self.review_violations(
            &vendor,
            amount.0,
            &hex::encode(nonce_bytes),
            &request_body,
            &response_body,
        ));
        self.decide(vendor, amount.0, nonce_bytes, None, auth)
    }

    /// Transfer callback. If the vendor account could not receive the funds
    /// they return to the contract, so the spend is taken back off the window.
    /// The nonce stays consumed either way.
    #[private]
    pub fn on_transfer_settled(
        &mut self,
        vendor: AccountId,
        amount: U128,
        nonce: String,
        hour: u64,
        #[callback_result] result: Result<(), PromiseError>,
    ) -> bool {
        let settled = result.is_ok();
        if !settled {
            let bucket = &mut self.window[slot(hour)];
            if bucket.hour == hour {
                bucket.spent = bucket.spent.saturating_sub(amount.0);
            }
            self.total_paid = self.total_paid.saturating_sub(amount.0);
        }
        emit(
            if settled {
                "transfer_settled"
            } else {
                "transfer_failed"
            },
            EventData::Transfer {
                vendor: &vendor,
                amount,
                nonce: &nonce,
            },
        );
        settled
    }

    // ---------------------------------------------------------------- owner

    pub fn add_vendor(&mut self, vendor: AccountId) {
        self.assert_owner();
        if self.vendors.insert(vendor.clone()) {
            emit("vendor_added", EventData::Vendor { vendor: &vendor });
        }
    }

    pub fn remove_vendor(&mut self, vendor: AccountId) {
        self.assert_owner();
        if self.vendors.remove(&vendor) {
            emit("vendor_removed", EventData::Vendor { vendor: &vendor });
        }
    }

    pub fn set_daily_cap(&mut self, daily_cap: U128) {
        self.assert_owner();
        self.daily_cap = daily_cap.0;
        emit("daily_cap_set", EventData::DailyCap { daily_cap });
    }

    pub fn set_agent(&mut self, agent: AccountId) {
        self.assert_owner();
        emit("agent_set", EventData::Agent { agent: &agent });
        self.agent = agent;
    }

    /// Kill switch: while paused every proposal is blocked.
    pub fn set_paused(&mut self, paused: bool) {
        self.assert_owner();
        self.paused = paused;
        emit("paused_set", EventData::Paused { paused });
    }

    /// Trust `address` as an attestation signer, bound to the quote that
    /// vouches for it. The owner (in practice the off-chain verifier, after it
    /// has checked the quote) is responsible for that binding being true.
    pub fn register_signer(&mut self, address: String, quote_hash: String) {
        self.assert_owner();
        let key: SignerAddress = decode_hex(&address, "address");
        let quote: Hash32 = decode_hex(&quote_hash, "quote_hash");
        self.signers.insert(
            key,
            SignerRecord {
                quote_hash: quote,
                registered_at_ns: env::block_timestamp(),
            },
        );
        emit(
            "signer_registered",
            EventData::Signer {
                address: hex::encode(key),
                quote_hash: Some(hex::encode(quote)),
            },
        );
    }

    /// Set the model and system prompt (by SHA-256) whose enclave-signed
    /// reviews `propose_attested_payment` accepts.
    pub fn set_reviewer(&mut self, model: String, prompt_sha256: String) {
        self.assert_owner();
        let prompt_hash: Hash32 = decode_hex(&prompt_sha256, "prompt_sha256");
        emit(
            "reviewer_set",
            EventData::Reviewer {
                model: &model,
                prompt_sha256: hex::encode(prompt_hash),
            },
        );
        self.reviewer = Some(ReviewerConfig { model, prompt_hash });
    }

    pub fn revoke_signer(&mut self, address: String) {
        self.assert_owner();
        let key: SignerAddress = decode_hex(&address, "address");
        if self.signers.remove(&key).is_some() {
            emit(
                "signer_revoked",
                EventData::Signer {
                    address: hex::encode(key),
                    quote_hash: None,
                },
            );
        }
    }

    /// Zero the rolling spend window. An explicit, logged owner action; the
    /// owner could equally raise the cap, so this grants no extra power.
    pub fn reset_spend_window(&mut self) {
        self.assert_owner();
        self.window = [SpendBucket::default(); WINDOW_SLOTS];
        emit("spend_window_reset", EventData::Empty {});
    }

    /// Return unspent funds to the owner.
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        self.assert_owner();
        require!(
            amount.0 <= self.available_balance(),
            "Amount exceeds available balance"
        );
        emit("withdrawn", EventData::Amount { amount });
        Promise::new(self.owner.clone()).transfer(NearToken::from_yoctonear(amount.0))
    }

    // ---------------------------------------------------------------- views

    pub fn get_policy(&self) -> PolicyView {
        let spent = self.spent_in_window(env::block_timestamp() / HOUR_NS);
        PolicyView {
            owner: self.owner.clone(),
            agent: self.agent.clone(),
            daily_cap: U128(self.daily_cap),
            spent_24h: U128(spent),
            remaining_24h: U128(self.daily_cap.saturating_sub(spent)),
            available_balance: U128(self.available_balance()),
            paused: self.paused,
            vendor_count: self.vendors.len(),
            approved_count: U64(self.approved_count),
            blocked_count: U64(self.blocked_count),
            total_paid: U128(self.total_paid),
        }
    }

    pub fn get_vendors(&self, from_index: Option<u32>, limit: Option<u32>) -> Vec<AccountId> {
        self.vendors
            .iter()
            .skip(from_index.unwrap_or(0) as usize)
            .take(limit.unwrap_or(MAX_PAGE).min(MAX_PAGE) as usize)
            .cloned()
            .collect()
    }

    pub fn get_reviewer(&self) -> Option<ReviewerView> {
        self.reviewer.as_ref().map(|reviewer| ReviewerView {
            model: reviewer.model.clone(),
            prompt_sha256: hex::encode(reviewer.prompt_hash),
        })
    }

    pub fn is_vendor(&self, vendor: AccountId) -> bool {
        self.vendors.contains(&vendor)
    }

    pub fn is_nonce_used(&self, nonce: String) -> bool {
        self.used_nonces
            .contains(&decode_hex::<32>(&nonce, "nonce"))
    }

    pub fn get_signer(&self, address: String) -> Option<SignerView> {
        let key: SignerAddress = decode_hex(&address, "address");
        self.signers.get(&key).map(|record| SignerView {
            address: hex::encode(key),
            quote_hash: hex::encode(record.quote_hash),
            registered_at_ns: U64(record.registered_at_ns),
        })
    }

    /// Hex digest a signer must sign for this intent. Lets off-chain code
    /// confirm it serialises intents exactly as the contract does.
    pub fn intent_digest(
        &self,
        vendor: AccountId,
        amount: U128,
        nonce: String,
        expires_at_ns: U64,
        quote_hash: String,
    ) -> String {
        hex::encode(
            Intent {
                contract: &env::current_account_id(),
                agent: &self.agent,
                vendor: &vendor,
                amount: amount.0,
                nonce: &decode_hex(&nonce, "nonce"),
                expires_at_ns: expires_at_ns.0,
                quote_hash: &decode_hex(&quote_hash, "quote_hash"),
            }
            .digest(),
        )
    }
}

impl Contract {
    fn assert_owner(&self) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Only the owner can call this method"
        );
    }

    /// Balance not locked up paying for the contract's own storage.
    fn available_balance(&self) -> u128 {
        let storage_cost = env::storage_byte_cost()
            .as_yoctonear()
            .saturating_mul(u128::from(env::storage_usage()));
        env::account_balance()
            .as_yoctonear()
            .saturating_sub(storage_cost)
    }

    /// Sum of the buckets whose hour lies in `(hour - 24, hour]`.
    fn spent_in_window(&self, hour: u64) -> u128 {
        self.window
            .iter()
            .filter(|bucket| bucket.hour <= hour && bucket.hour + WINDOW_HOURS > hour)
            .fold(0u128, |sum, bucket| sum.saturating_add(bucket.spent))
    }

    fn payment_event<'a>(&'a self, decision: &'a Decision) -> EventData<'a> {
        EventData::Payment {
            agent: &self.agent,
            vendor: &decision.vendor,
            amount: decision.amount,
            nonce: &decision.nonce,
            signer: &decision.signer,
            violations: &decision.violations,
            spent_24h: decision.spent_24h,
            remaining_24h: decision.remaining_24h,
        }
    }

    /// Policy checks shared by both entry points, then settlement.
    /// `expires_at_ns` is `None` when expiry is enforced by review freshness.
    fn decide(
        &mut self,
        vendor: AccountId,
        amount: u128,
        nonce_bytes: Hash32,
        expires_at_ns: Option<u64>,
        auth: Authorization,
    ) -> Decision {
        let now = env::block_timestamp();
        let hour = now / HOUR_NS;
        let spent = self.spent_in_window(hour);

        let mut violations = Vec::new();
        if self.paused {
            violations.push(Violation::EnvelopePaused);
        }
        if amount == 0 {
            violations.push(Violation::ZeroAmount);
        }
        if !self.vendors.contains(&vendor) {
            violations.push(Violation::VendorNotAllowlisted);
        }
        if spent
            .checked_add(amount)
            .is_none_or(|total| total > self.daily_cap)
        {
            violations.push(Violation::DailyCapExceeded);
        }
        if self.used_nonces.contains(&nonce_bytes) {
            violations.push(Violation::NonceReplayed);
        }
        if expires_at_ns.is_some_and(|expiry| now > expiry) {
            violations.push(Violation::IntentExpired);
        }
        if amount > self.available_balance() {
            violations.push(Violation::InsufficientFunds);
        }
        violations.extend(auth.violations);
        let signer = auth.signer;

        let status = if violations.is_empty() {
            self.used_nonces.insert(nonce_bytes);
            self.record_spend(hour, amount);
            self.approved_count += 1;
            self.total_paid += amount;
            Status::Approved
        } else {
            self.blocked_count += 1;
            Status::Blocked
        };
        let spent_after = self.spent_in_window(hour);
        let decision = Decision {
            status,
            violations,
            vendor: vendor.clone(),
            amount: U128(amount),
            nonce: hex::encode(nonce_bytes),
            signer: signer.map(hex::encode),
            spent_24h: U128(spent_after),
            remaining_24h: U128(self.daily_cap.saturating_sub(spent_after)),
        };

        match status {
            Status::Approved => {
                emit("payment_approved", self.payment_event(&decision));
                Promise::new(vendor.clone())
                    .transfer(NearToken::from_yoctonear(amount))
                    .then(
                        Self::ext(env::current_account_id())
                            .with_static_gas(CALLBACK_GAS)
                            .on_transfer_settled(
                                vendor,
                                U128(amount),
                                decision.nonce.clone(),
                                hour,
                            ),
                    )
                    .detach();
            }
            Status::Blocked => emit("payment_blocked", self.payment_event(&decision)),
        }
        decision
    }

    /// Everything about the enclave-signed review except its signature:
    /// registered reviewer, recent, approving exactly this payment.
    fn review_violations(
        &self,
        vendor: &AccountId,
        amount: u128,
        nonce_hex: &str,
        request_body: &str,
        response_body: &str,
    ) -> Vec<Violation> {
        let Some(reviewer) = &self.reviewer else {
            return vec![Violation::ReviewerNotConfigured];
        };
        let mut violations = Vec::new();
        let request = near_sdk::serde_json::from_str::<Value>(request_body).ok();
        let system_prompt = request
            .as_ref()
            .and_then(|r| r["messages"].get(0))
            .filter(|m| m["role"] == "system")
            .and_then(|m| m["content"].as_str());
        let request_matches = request
            .as_ref()
            .is_some_and(|r| r["model"].as_str() == Some(reviewer.model.as_str()))
            && system_prompt
                .is_some_and(|prompt| env::sha256_array(prompt.as_bytes()) == reviewer.prompt_hash);
        if !request_matches {
            violations.push(Violation::ReviewerRequestMismatch);
        }

        let response = near_sdk::serde_json::from_str::<Value>(response_body).ok();
        let created_ns = response
            .as_ref()
            .and_then(|r| r["created"].as_u64())
            .and_then(|seconds| seconds.checked_mul(1_000_000_000));
        if created_ns
            .is_none_or(|created| env::block_timestamp().abs_diff(created) > MAX_REVIEW_AGE_NS)
        {
            violations.push(Violation::AttestationStale);
        }

        let answer = response
            .as_ref()
            .and_then(|r| r["choices"].get(0))
            .and_then(|choice| choice["message"]["content"].as_str())
            .and_then(extract_json_object);
        match answer {
            None => violations.push(Violation::DecisionMismatch),
            Some(answer) => {
                if answer["decision"].as_str() != Some("APPROVE") {
                    violations.push(Violation::ModelDeclined);
                } else if answer["vendor"].as_str() != Some(vendor.as_str())
                    || answer["amount_yocto"].as_str() != Some(amount.to_string().as_str())
                    || answer["nonce"].as_str() != Some(nonce_hex)
                {
                    violations.push(Violation::DecisionMismatch);
                }
            }
        }
        violations
    }

    fn record_spend(&mut self, hour: u64, amount: u128) {
        let bucket = &mut self.window[slot(hour)];
        if bucket.hour != hour {
            *bucket = SpendBucket { hour, spent: 0 };
        }
        bucket.spent += amount;
    }
}

fn slot(hour: u64) -> usize {
    (hour % WINDOW_HOURS) as usize
}

/// Recover the Ethereum-style address that signed `digest`, rejecting
/// malleable (high-S) signatures.
pub fn recover_signer(digest: &Hash32, signature: &[u8; 65]) -> Option<SignerAddress> {
    let v = match signature[64] {
        v @ 0..=1 => v,
        v @ 27..=28 => v - 27,
        _ => return None,
    };
    let public_key = env::ecrecover(digest, &signature[..64], v, true)?;
    let hash = env::keccak256_array(public_key);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Some(address)
}

/// Outcome of checking who authorised a payment.
struct Authorization {
    signer: Option<SignerAddress>,
    violations: Vec<Violation>,
}

/// EIP-191 `personal_sign` digest of `message`.
pub fn personal_message_digest(message: &str) -> Hash32 {
    env::keccak256_array(
        format!("\x19Ethereum Signed Message:\n{}{message}", message.len()).as_bytes(),
    )
}

/// The first complete `{...}` span of a model answer, parsed as JSON. Lets a
/// model wrap its answer in a code fence or a sentence; anything that does not
/// parse is treated as no answer at all.
fn extract_json_object(content: &str) -> Option<Value> {
    let start = content.find('{')?;
    let end = content.rfind('}')?;
    near_sdk::serde_json::from_str(content.get(start..=end)?).ok()
}

/// Decode fixed-length hex, with or without a `0x` prefix. Panics on bad input.
fn decode_hex<const N: usize>(value: &str, field: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let digits = value.strip_prefix("0x").unwrap_or(value);
    if hex::decode_to_slice(digits, &mut out).is_err() {
        env::panic_str(&format!("{field} must be {N} bytes of hex"));
    }
    out
}

/// Payload of a NEP-297 event. Untagged: each variant serialises as a plain
/// object of its fields.
#[derive(Serialize)]
#[serde(crate = "near_sdk::serde", untagged)]
enum EventData<'a> {
    Payment {
        agent: &'a AccountId,
        vendor: &'a AccountId,
        amount: U128,
        nonce: &'a str,
        signer: &'a Option<String>,
        violations: &'a [Violation],
        spent_24h: U128,
        remaining_24h: U128,
    },
    Transfer {
        vendor: &'a AccountId,
        amount: U128,
        nonce: &'a str,
    },
    Vendor {
        vendor: &'a AccountId,
    },
    Agent {
        agent: &'a AccountId,
    },
    DailyCap {
        daily_cap: U128,
    },
    Amount {
        amount: U128,
    },
    Paused {
        paused: bool,
    },
    Reviewer {
        model: &'a str,
        prompt_sha256: String,
    },
    Signer {
        address: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        quote_hash: Option<String>,
    },
    Empty {},
}

#[derive(Serialize)]
#[serde(crate = "near_sdk::serde")]
struct Event<'a> {
    standard: &'a str,
    version: &'a str,
    event: &'a str,
    data: [EventData<'a>; 1],
}

fn emit(event: &str, data: EventData) {
    let event = Event {
        standard: EVENT_STANDARD,
        version: EVENT_VERSION,
        event,
        data: [data],
    };
    let body = near_sdk::serde_json::to_string(&event)
        .unwrap_or_else(|_| env::panic_str("event serialisation failed"));
    env::log_str(&format!("EVENT_JSON:{body}"));
}
