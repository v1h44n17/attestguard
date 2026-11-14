//! End-to-end tests against a local NEAR sandbox node: the compiled wasm is
//! deployed, real transactions are signed and balances are checked on chain.
//!
//! Intent digests and signer addresses are computed here with independent
//! libraries (`sha2`, `sha3`, `k256`), not with contract code, so these tests
//! also prove an off-chain signer can interoperate with the contract.

use k256::ecdsa::SigningKey;
use near_api::{AccountId, NearGas, NearToken};
use near_sdk::serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

const NEAR: u128 = 10u128.pow(24);
const QUOTE_HASH: [u8; 32] = [0x22; 32];

struct Env {
    network: near_api::NetworkConfig,
    signer: std::sync::Arc<near_api::Signer>,
    contract: near_api::Contract,
    owner: AccountId,
    agent: AccountId,
    vendor: AccountId,
    tee_key: SigningKey,
    // Dropping the sandbox stops the node, so it has to live as long as `Env`.
    _sandbox: near_sandbox::Sandbox,
}

struct Proposal {
    vendor: AccountId,
    amount: u128,
    nonce: [u8; 32],
    expires_at_ns: u64,
}

fn address_of(key: &SigningKey) -> String {
    let point = key.verifying_key().to_encoded_point(false);
    hex::encode(&Keccak256::digest(&point.as_bytes()[1..])[12..])
}

fn far_future_ns() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    now + 3_600_000_000_000
}

impl Env {
    async fn start() -> testresult::TestResult<Self> {
        let wasm = std::fs::read(cargo_near_build::build_with_cli(Default::default())?)?;
        let sandbox = near_sandbox::Sandbox::start_sandbox().await?;
        let network = near_api::NetworkConfig::from_rpc_url("sandbox", sandbox.rpc_addr.parse()?);
        let signer = near_api::Signer::from_secret_key(
            near_sandbox::config::DEFAULT_GENESIS_ACCOUNT_PRIVATE_KEY.parse()?,
        )?;

        let mut accounts = Vec::new();
        for name in ["owner", "agent", "vendor", "envelope"] {
            let id: AccountId = format!("{name}.sandbox").parse()?;
            sandbox
                .create_account(id.clone())
                .initial_balance(NearToken::from_near(20))
                .send()
                .await?;
            accounts.push(id);
        }
        let [owner, agent, vendor, envelope]: [AccountId; 4] = accounts.try_into().unwrap();

        near_api::Contract::deploy(envelope.clone())
            .use_code(wasm)
            .with_init_call(
                "new",
                json!({ "owner": owner, "agent": agent, "daily_cap": (5 * NEAR).to_string() }),
            )?
            .with_signer(signer.clone())
            .send_to(&network)
            .await?
            .assert_success();

        let env = Self {
            network,
            signer,
            contract: near_api::Contract(envelope),
            owner,
            agent,
            vendor,
            tee_key: SigningKey::from_slice(&[1; 32])?,
            _sandbox: sandbox,
        };
        env.as_owner("add_vendor", json!({ "vendor": env.vendor }))
            .await?;
        env.as_owner(
            "register_signer",
            json!({ "address": address_of(&env.tee_key), "quote_hash": hex::encode(QUOTE_HASH) }),
        )
        .await?;
        Ok(env)
    }

    async fn as_owner(&self, method: &str, args: Value) -> testresult::TestResult<()> {
        self.contract
            .call_function(method, args)
            .transaction()
            .with_signer(self.owner.clone(), self.signer.clone())
            .send_to(&self.network)
            .await?
            .assert_success();
        Ok(())
    }

    fn proposal(&self, amount: u128, nonce: u8) -> Proposal {
        Proposal {
            vendor: self.vendor.clone(),
            amount,
            nonce: [nonce; 32],
            expires_at_ns: far_future_ns(),
        }
    }

    fn sign(&self, key: &SigningKey, proposal: &Proposal) -> String {
        let message = format!(
            "attestguard-intent-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.contract.account_id(),
            self.agent,
            proposal.vendor,
            proposal.amount,
            hex::encode(proposal.nonce),
            proposal.expires_at_ns,
            hex::encode(QUOTE_HASH),
        );
        let (signature, recovery_id) = key
            .sign_prehash_recoverable(&Sha256::digest(message.as_bytes()))
            .unwrap();
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery_id.to_byte());
        hex::encode(bytes)
    }

    fn args(&self, key: &SigningKey, proposal: &Proposal) -> Value {
        json!({
            "vendor": proposal.vendor,
            "amount": proposal.amount.to_string(),
            "nonce": hex::encode(proposal.nonce),
            "expires_at_ns": proposal.expires_at_ns.to_string(),
            "attestation": {
                "quote_hash": hex::encode(QUOTE_HASH),
                "signature": self.sign(key, proposal),
            },
        })
    }

    /// Submit as the agent; returns the decision JSON and every log line.
    async fn propose(
        &self,
        key: &SigningKey,
        proposal: &Proposal,
    ) -> testresult::TestResult<(Value, Vec<String>)> {
        let outcome = self
            .contract
            .call_function("propose_payment", self.args(key, proposal))
            .transaction()
            .gas(NearGas::from_tgas(60))
            .with_signer(self.agent.clone(), self.signer.clone())
            .send_to(&self.network)
            .await?
            .assert_success();
        let logs = outcome.logs().into_iter().map(str::to_owned).collect();
        Ok((outcome.json()?, logs))
    }

    async fn balance(&self, account: &AccountId) -> testresult::TestResult<u128> {
        Ok(near_api::Account(account.clone())
            .tokens()
            .near_balance()
            .fetch_from(&self.network)
            .await?
            .total
            .as_yoctonear())
    }

    async fn policy(&self) -> testresult::TestResult<Value> {
        Ok(self
            .contract
            .call_function("get_policy", ())
            .read_only()
            .fetch_from(&self.network)
            .await?
            .data)
    }
}

fn event<'a>(logs: &'a [String], name: &str) -> Option<&'a String> {
    logs.iter().find(|log| {
        log.starts_with("EVENT_JSON:") && log.contains(&format!("\"event\":\"{name}\""))
    })
}

#[tokio::test]
async fn envelope_enforces_policy_and_attestation_on_chain() -> testresult::TestResult<()> {
    let env = Env::start().await?;
    let attacker_key = SigningKey::from_slice(&[9; 32])?;
    let mallory: AccountId = "mallory.sandbox".parse()?;
    let vendor_start = env.balance(&env.vendor).await?;
    let envelope_start = env.balance(env.contract.account_id()).await?;

    // The contract and this test must agree on the digest of an intent.
    let probe = env.proposal(NEAR, 0xaa);
    let on_chain_digest: String = env
        .contract
        .call_function(
            "intent_digest",
            json!({
                "vendor": probe.vendor,
                "amount": probe.amount.to_string(),
                "nonce": hex::encode(probe.nonce),
                "expires_at_ns": probe.expires_at_ns.to_string(),
                "quote_hash": hex::encode(QUOTE_HASH),
            }),
        )
        .read_only()
        .fetch_from(&env.network)
        .await?
        .data;
    let signature = hex::decode(env.sign(&env.tee_key, &probe))?;
    let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(
        &hex::decode(&on_chain_digest)?,
        &k256::ecdsa::Signature::from_slice(&signature[..64])?,
        k256::ecdsa::RecoveryId::from_byte(signature[64]).unwrap(),
    )?;
    assert_eq!(&recovered, env.tee_key.verifying_key());

    // 1. Prompt-injected agent: 7 NEAR to an unknown wallet, self-signed.
    let attack = Proposal {
        vendor: mallory.clone(),
        ..env.proposal(7 * NEAR, 1)
    };
    let (decision, logs) = env.propose(&attacker_key, &attack).await?;
    assert_eq!(decision["status"], "BLOCKED");
    assert_eq!(
        decision["violations"],
        json!([
            "VENDOR_NOT_ALLOWLISTED",
            "DAILY_CAP_EXCEEDED",
            "UNTRUSTED_SIGNER"
        ])
    );
    assert!(event(&logs, "payment_blocked").is_some(), "{logs:?}");
    assert_eq!(env.balance(&env.vendor).await?, vendor_start);
    // Nothing left the treasury (it only gained its share of the gas fee).
    assert!(env.balance(env.contract.account_id()).await? >= envelope_start);

    // 2. Legitimate payment: 3 NEAR to the allowlisted vendor, TEE-signed.
    let valid = env.proposal(3 * NEAR, 2);
    let (decision, logs) = env.propose(&env.tee_key, &valid).await?;
    assert_eq!(decision["status"], "APPROVED", "{decision}");
    assert_eq!(decision["signer"], address_of(&env.tee_key));
    assert_eq!(decision["remaining_24h"], (2 * NEAR).to_string());
    assert!(event(&logs, "payment_approved").is_some(), "{logs:?}");
    assert!(event(&logs, "transfer_settled").is_some(), "{logs:?}");
    assert_eq!(env.balance(&env.vendor).await?, vendor_start + 3 * NEAR);

    // 3. Replaying the same signed intent pays nothing.
    let (decision, _) = env.propose(&env.tee_key, &valid).await?;
    assert_eq!(decision["status"], "BLOCKED");
    assert_eq!(
        decision["violations"],
        json!(["DAILY_CAP_EXCEEDED", "NONCE_REPLAYED"])
    );

    // 4. A fresh, correctly signed intent that would break the 24h cap.
    let (decision, _) = env
        .propose(&env.tee_key, &env.proposal(3 * NEAR, 3))
        .await?;
    assert_eq!(decision["violations"], json!(["DAILY_CAP_EXCEEDED"]));

    // 5. In-policy payment signed by a key that was never attested.
    let (decision, _) = env.propose(&attacker_key, &env.proposal(NEAR, 4)).await?;
    assert_eq!(decision["violations"], json!(["UNTRUSTED_SIGNER"]));

    // 6. A TEE signature for 1 NEAR cannot be reused for 2 NEAR.
    let signed = env.proposal(NEAR, 5);
    let mut args = env.args(&env.tee_key, &signed);
    args["amount"] = json!((2 * NEAR).to_string());
    let outcome = env
        .contract
        .call_function("propose_payment", args)
        .transaction()
        .gas(NearGas::from_tgas(60))
        .with_signer(env.agent.clone(), env.signer.clone())
        .send_to(&env.network)
        .await?
        .assert_success();
    assert_eq!(
        outcome.json::<Value>()?["violations"],
        json!(["UNTRUSTED_SIGNER"])
    );

    // 7. Only the agent account may propose at all.
    env.contract
        .call_function(
            "propose_payment",
            env.args(&env.tee_key, &env.proposal(NEAR, 6)),
        )
        .transaction()
        .gas(NearGas::from_tgas(60))
        .with_signer(env.owner.clone(), env.signer.clone())
        .send_to(&env.network)
        .await?
        .assert_failure();

    // 8. Only the owner may change the envelope.
    env.contract
        .call_function("add_vendor", json!({ "vendor": mallory }))
        .transaction()
        .with_signer(env.agent.clone(), env.signer.clone())
        .send_to(&env.network)
        .await?
        .assert_failure();

    // 9. An approved payment to an account that does not exist bounces: the
    //    funds come back and the spend is returned to the window.
    let ghost: AccountId = "ghost.sandbox".parse()?;
    env.as_owner("add_vendor", json!({ "vendor": ghost }))
        .await?;
    let bounced = Proposal {
        vendor: ghost,
        ..env.proposal(NEAR, 7)
    };
    let (decision, logs) = env.propose(&env.tee_key, &bounced).await?;
    assert_eq!(decision["status"], "APPROVED");
    assert!(event(&logs, "transfer_failed").is_some(), "{logs:?}");

    let policy = env.policy().await?;
    assert_eq!(policy["spent_24h"], (3 * NEAR).to_string());
    assert_eq!(policy["total_paid"], (3 * NEAR).to_string());
    assert_eq!(policy["approved_count"], "2");
    assert_eq!(policy["blocked_count"], "5");
    assert_eq!(env.balance(&env.vendor).await?, vendor_start + 3 * NEAR);
    Ok(())
}
