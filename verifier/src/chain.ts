/** NEAR client for the envelope contract. */
import { createRequire } from 'node:module';

// The @near-js ESM builds use extensionless imports that Node's native ESM
// loader rejects, so load their CommonJS builds instead (types stay ESM).
const load = createRequire(import.meta.url);
const { Account, Connection } = load('@near-js/accounts') as typeof import('@near-js/accounts');
const { KeyPair } = load('@near-js/crypto') as typeof import('@near-js/crypto');
const { InMemoryKeyStore } = load('@near-js/keystores') as typeof import('@near-js/keystores');
const { JsonRpcProvider } = load('@near-js/providers') as typeof import('@near-js/providers');
// The package exposes its action constructors at runtime as `actionCreators`,
// but its typings do not declare them, so describe the two used here.
interface ActionCreators {
  deployContract(code: Uint8Array): Action;
  functionCall(methodName: string, args: object, gas: bigint, deposit: bigint): Action;
}
const { actionCreators } = load('@near-js/transactions') as { actionCreators: ActionCreators };
const { InMemorySigner } = load('@near-js/signers') as typeof import('@near-js/signers');
type Account = InstanceType<typeof Account>;
type Action = Parameters<Account['signAndSendTransaction']>[0]['actions'][number];
type KeyPairString = Parameters<typeof KeyPair.fromString>[0];

export { actionCreators, KeyPair };
import type { Config } from './config.ts';
import type { PolicySnapshot, Violation } from './policy.ts';

/** Accounts on one network, each signing with the key given for it. */
export async function connectAccounts(
  networkId: string,
  rpcUrl: string,
  keys: Record<string, string>,
): Promise<Record<string, Account>> {
  const keyStore = new InMemoryKeyStore();
  for (const [accountId, key] of Object.entries(keys)) {
    await keyStore.setKey(networkId, accountId, KeyPair.fromString(key as KeyPairString));
  }
  const connection = new Connection(networkId, new JsonRpcProvider({ url: rpcUrl }), new InMemorySigner(keyStore), '');
  return Object.fromEntries(Object.keys(keys).map((accountId) => [accountId, new Account(connection, accountId)]));
}

const PROPOSE_GAS = 60_000_000_000_000n;
const ADMIN_GAS = 30_000_000_000_000n;
const EVENT_PREFIX = 'EVENT_JSON:';

export interface PolicyView {
  owner: string;
  agent: string;
  daily_cap: string;
  spent_24h: string;
  remaining_24h: string;
  available_balance: string;
  paused: boolean;
  vendor_count: number;
  approved_count: string;
  blocked_count: string;
  total_paid: string;
}

export interface SignerView {
  address: string;
  quote_hash: string;
  registered_at_ns: string;
}

export interface Decision {
  status: 'APPROVED' | 'BLOCKED';
  violations: Violation[];
  vendor: string;
  amount: string;
  nonce: string;
  signer: string | null;
  spent_24h: string;
  remaining_24h: string;
}

export interface Submission {
  vendor: string;
  amount: bigint;
  nonce: string;
  expiresAtNs: bigint;
  quoteHash: string;
  signature: string;
}

export interface ProposalOutcome {
  txHash: string;
  decision: Decision;
  /** Raw `EVENT_JSON:` log lines from every receipt of the transaction. */
  events: string[];
  /** Time from submission to a final result, in milliseconds. */
  chainMs: number;
}

/** The parts of a final transaction outcome this client reads. */
interface TxOutcome {
  status: { SuccessValue?: string; Failure?: unknown };
  transaction: { hash: string };
  receipts_outcome: { outcome: { logs: string[] } }[];
}

export class EnvelopeClient {
  readonly contractId: string;
  private readonly agent: Account;
  private readonly owner: Account | null;

  private constructor(contractId: string, agent: Account, owner: Account | null) {
    this.contractId = contractId;
    this.agent = agent;
    this.owner = owner;
  }

  static async connect(config: Config): Promise<EnvelopeClient> {
    const keys: Record<string, string> = { [config.agentId]: config.agentKey };
    if (config.ownerId && config.ownerKey) keys[config.ownerId] = config.ownerKey;
    const accounts = await connectAccounts(config.networkId, config.rpcUrl, keys);
    return new EnvelopeClient(
      config.contractId,
      accounts[config.agentId]!,
      config.ownerId && config.ownerKey ? accounts[config.ownerId]! : null,
    );
  }

  get canAdminister(): boolean {
    return this.owner !== null;
  }

  private view<T>(methodName: string, args: object = {}): Promise<T> {
    return this.agent.viewFunction({ contractId: this.contractId, methodName, args }) as Promise<T>;
  }

  policy(): Promise<PolicyView> {
    return this.view('get_policy');
  }

  vendors(): Promise<string[]> {
    return this.view('get_vendors');
  }

  signer(address: string): Promise<SignerView | null> {
    return this.view('get_signer', { address });
  }

  isNonceUsed(nonce: string): Promise<boolean> {
    return this.view('is_nonce_used', { nonce });
  }

  /** Digest the contract expects a signer to sign for this intent. */
  intentDigest(submission: Omit<Submission, 'signature'>): Promise<string> {
    return this.view('intent_digest', {
      vendor: submission.vendor,
      amount: submission.amount.toString(),
      nonce: submission.nonce,
      expires_at_ns: submission.expiresAtNs.toString(),
      quote_hash: submission.quoteHash,
    });
  }

  async snapshot(): Promise<PolicySnapshot> {
    const [policy, vendors] = await Promise.all([this.policy(), this.vendors()]);
    return {
      dailyCap: BigInt(policy.daily_cap),
      spent24h: BigInt(policy.spent_24h),
      availableBalance: BigInt(policy.available_balance),
      paused: policy.paused,
      vendors: new Set(vendors),
    };
  }

  /** Submit a proposal as the agent and wait for the contract's decision. */
  async propose(submission: Submission): Promise<ProposalOutcome> {
    const started = performance.now();
    const outcome: TxOutcome = await this.agent.functionCall({
      contractId: this.contractId,
      methodName: 'propose_payment',
      args: {
        vendor: submission.vendor,
        amount: submission.amount.toString(),
        nonce: submission.nonce,
        expires_at_ns: submission.expiresAtNs.toString(),
        attestation: { quote_hash: submission.quoteHash, signature: submission.signature },
      },
      gas: PROPOSE_GAS,
    });
    const chainMs = performance.now() - started;
    const status = outcome.status;
    if (typeof status.SuccessValue !== 'string') {
      throw new Error(`propose_payment failed: ${JSON.stringify(outcome.status)}`);
    }
    return {
      txHash: outcome.transaction.hash,
      decision: JSON.parse(Buffer.from(status.SuccessValue, 'base64').toString('utf8')) as Decision,
      events: outcome.receipts_outcome
        .flatMap((receipt) => receipt.outcome.logs)
        .filter((log) => log.startsWith(EVENT_PREFIX)),
      chainMs,
    };
  }

  private async ownerCall(methodName: string, args: object): Promise<string> {
    if (!this.owner) throw new Error('No owner key configured: set OWNER_ACCOUNT_ID to use owner actions.');
    const outcome: TxOutcome = await this.owner.functionCall({
      contractId: this.contractId,
      methodName,
      args,
      gas: ADMIN_GAS,
    });
    return outcome.transaction.hash;
  }

  registerSigner(address: string, quoteHash: string): Promise<string> {
    return this.ownerCall('register_signer', { address, quote_hash: quoteHash });
  }

  resetSpendWindow(): Promise<string> {
    return this.ownerCall('reset_spend_window', {});
  }
}

export function parseEvent(log: string): { event: string; data: unknown[] } {
  return JSON.parse(log.slice(EVENT_PREFIX.length)) as { event: string; data: unknown[] };
}
