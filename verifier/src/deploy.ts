/**
 * Deploy a fresh envelope to NEAR testnet and write `verifier/.env`.
 *
 *   npm run deploy -- <master-account> [--suffix v2]
 *
 * Signs with the master account's key from ~/.near-credentials. Creates three
 * sub-accounts (envelope, agent, vendor), deploys and initialises the
 * contract with the master account as owner, allowlists the vendor, and
 * registers the attestation signers after verifying the TDX quote locally.
 */
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { actionCreators, connectAccounts, KeyPair } from './chain.ts';
import { DEFAULT_RPC, readNearCredentials, REPO_ROOT } from './config.ts';
import { addressOf } from './intent.ts';
import { verifyAttestation, type GatewayAttestation } from './quote.ts';
import { yoctoToNear } from './scenario.ts';

const NETWORK = 'testnet';
const WASM_PATH = join(REPO_ROOT, 'contracts', 'attest-guard-envelope', 'target', 'near', 'attest_guard_envelope.wasm');
const ENV_PATH = join(REPO_ROOT, 'verifier', '.env');
const YOCTO_PER_USD = 10n ** 18n;
const DAILY_CAP_USD = 5000n;
const YOCTO_PER_BYTE = 10n ** 19n;
const NEAR = 10n ** 24n;
/** Beyond code storage: contract state plus the treasury the demo pays from. */
const ENVELOPE_FLOAT = (NEAR * 8n) / 100n;
const AGENT_FUNDS = NEAR / 2n;
const VENDOR_FUNDS = NEAR / 500n;
const MASTER_RESERVE = NEAR / 50n;
const GAS = 30_000_000_000_000n;

async function exists(account: Awaited<ReturnType<typeof connectAccounts>>[string]): Promise<boolean> {
  try {
    await account.state();
    return true;
  } catch {
    return false;
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const suffixAt = args.indexOf('--suffix');
  const suffix = suffixAt >= 0 ? `-${args[suffixAt + 1]}` : '';
  const master = args.find((arg, i) => !arg.startsWith('--') && (suffixAt < 0 || i !== suffixAt + 1));
  if (!master) throw new Error('Usage: npm run deploy -- <master-account> [--suffix v2]');
  const masterKey = readNearCredentials(NETWORK, master);
  if (!masterKey) throw new Error(`No key for ${master} in ~/.near-credentials/${NETWORK}. Run \`near login\` first.`);
  if (!existsSync(WASM_PATH)) {
    throw new Error(`Contract not built. Run \`cargo near build non-reproducible-wasm\` in contracts/attest-guard-envelope.`);
  }

  const wasm = readFileSync(WASM_PATH);
  const attestation = (
    JSON.parse(readFileSync(join(REPO_ROOT, 'docs', 'sample_attestation.json'), 'utf8')) as {
      gateway_attestation: GatewayAttestation;
    }
  ).gateway_attestation;
  const report = verifyAttestation(attestation);
  if (!report.ok) throw new Error('The sample TDX attestation did not verify; refusing to register its signer.');

  const ids = {
    envelope: `envelope${suffix}.${master}`,
    agent: `agent${suffix}.${master}`,
    vendor: `vendor${suffix}.${master}`,
  };
  const keys = { envelope: KeyPair.fromRandom('ed25519'), agent: KeyPair.fromRandom('ed25519'), vendor: KeyPair.fromRandom('ed25519') };
  if (existsSync(ENV_PATH)) {
    throw new Error(`${ENV_PATH} already exists and holds the keys of an earlier deployment. Move it aside first.`);
  }
  const devSignerKey = randomBytes(32);
  // Persist every key before spending anything, so an interrupted deploy can
  // never strand funds in an account whose key is lost.
  writeFileSync(
    ENV_PATH,
    [
      `NEAR_NETWORK=${NETWORK}`,
      `ENVELOPE_CONTRACT_ID=${ids.envelope}`,
      `AGENT_ACCOUNT_ID=${ids.agent}`,
      `AGENT_PRIVATE_KEY=${keys.agent.toString()}`,
      `VENDOR_ACCOUNT_ID=${ids.vendor}`,
      `OWNER_ACCOUNT_ID=${master}`,
      `DEV_SIGNER_PRIVATE_KEY=${devSignerKey.toString('hex')}`,
      `YOCTO_PER_USD=${YOCTO_PER_USD}`,
      `# Keys for the other accounts created by this deployment.`,
      `ENVELOPE_PRIVATE_KEY=${keys.envelope.toString()}`,
      `VENDOR_PRIVATE_KEY=${keys.vendor.toString()}`,
      '',
    ].join('\n'),
    { mode: 0o600 },
  );
  console.log(`keys saved to ${ENV_PATH} before any funds move`);

  const rpcUrl = process.env.NEAR_RPC_URL ?? DEFAULT_RPC[NETWORK]!;
  const accounts = await connectAccounts(NETWORK, rpcUrl, {
    [master]: masterKey,
    [ids.envelope]: keys.envelope.toString(),
    [ids.agent]: keys.agent.toString(),
    [ids.vendor]: keys.vendor.toString(),
  });
  const owner = accounts[master]!;
  const envelope = accounts[ids.envelope]!;

  for (const id of Object.values(ids)) {
    if (await exists(accounts[id]!)) throw new Error(`${id} already exists. Pass --suffix <name> to deploy alongside it.`);
  }
  const envelopeFunds = BigInt(wasm.length) * YOCTO_PER_BYTE + ENVELOPE_FLOAT;
  const needed = envelopeFunds + AGENT_FUNDS + VENDOR_FUNDS + MASTER_RESERVE;
  const available = BigInt((await owner.getAccountBalance()).available);
  if (available < needed) {
    throw new Error(
      `${master} has ${yoctoToNear(available)} NEAR available but this deployment needs ${yoctoToNear(needed)} NEAR ` +
        `(${(wasm.length / 1024).toFixed(0)} KB of contract code costs ${yoctoToNear(BigInt(wasm.length) * YOCTO_PER_BYTE)} NEAR in storage). ` +
        `Top it up from a testnet faucet and run this again.`,
    );
  }

  const step = async (label: string, action: () => Promise<unknown>): Promise<void> => {
    process.stdout.write(`${label} ... `);
    await action();
    console.log('done');
  };
  const ownerCall = (methodName: string, callArgs: object): Promise<unknown> =>
    owner.functionCall({ contractId: ids.envelope, methodName, args: callArgs, gas: GAS });

  await step(`create ${ids.envelope}`, () => owner.createAccount(ids.envelope, keys.envelope.getPublicKey(), envelopeFunds));
  await step(`create ${ids.agent}`, () => owner.createAccount(ids.agent, keys.agent.getPublicKey(), AGENT_FUNDS));
  await step(`create ${ids.vendor}`, () => owner.createAccount(ids.vendor, keys.vendor.getPublicKey(), VENDOR_FUNDS));
  await step(`deploy ${(wasm.length / 1024).toFixed(0)} KB contract and initialise it atomically`, () =>
    envelope.signAndSendTransaction({
      receiverId: ids.envelope,
      actions: [
        actionCreators.deployContract(wasm),
        actionCreators.functionCall(
          'new',
          { owner: master, agent: ids.agent, daily_cap: (DAILY_CAP_USD * YOCTO_PER_USD).toString() },
          GAS,
          0n,
        ),
      ],
    }),
  );
  await step(`allowlist ${ids.vendor}`, () => ownerCall('add_vendor', { vendor: ids.vendor }));

  await step(`register TEE signer 0x${report.signingAddress}`, () =>
    ownerCall('register_signer', { address: report.signingAddress, quote_hash: report.quoteHash }),
  );
  await step(`register dev signer 0x${addressOf(devSignerKey)}`, () =>
    ownerCall('register_signer', { address: addressOf(devSignerKey), quote_hash: report.quoteHash }),
  );

  console.log('\nDeployed. Start the console with: npm start');
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
