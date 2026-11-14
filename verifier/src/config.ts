/** Runtime configuration, read from the environment (see `.env.example`). */
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export interface Config {
  networkId: string;
  rpcUrl: string;
  explorerUrl: string;
  contractId: string;
  agentId: string;
  agentKey: string;
  vendorId: string;
  /** Recipient used by the simulated attack. Never needs to exist. */
  attackerId: string;
  ownerId: string | null;
  ownerKey: string | null;
  /** Hex secp256k1 key that signs intents in place of the enclave key. */
  devSignerKey: string;
  /** Display scale: how many yoctoNEAR stand for one demo dollar. */
  yoctoPerUsd: bigint;
  port: number;
  attestationPath: string;
  /** NEAR AI Cloud API key. When set, payments are reviewed by the enclave-hosted model. */
  nearAiKey: string | null;
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set. Run \`npm run deploy\` or copy .env.example to .env and fill it in.`);
  }
  return value;
}

/** Key from the standard near-cli credentials directory, if present. */
export function readNearCredentials(networkId: string, accountId: string): string | null {
  const path = join(homedir(), '.near-credentials', networkId, `${accountId}.json`);
  if (!existsSync(path)) return null;
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as { private_key?: string; secret_key?: string };
  return parsed.private_key ?? parsed.secret_key ?? null;
}

export const DEFAULT_RPC: Record<string, string> = {
  testnet: 'https://test.rpc.fastnear.com',
  mainnet: 'https://free.rpc.fastnear.com',
};

export const REPO_ROOT = join(import.meta.dirname, '..', '..');

export function loadConfig(): Config {
  const networkId = process.env.NEAR_NETWORK ?? 'testnet';
  const ownerId = process.env.OWNER_ACCOUNT_ID ?? null;
  const ownerKey = process.env.OWNER_PRIVATE_KEY ?? (ownerId ? readNearCredentials(networkId, ownerId) : null);
  return {
    networkId,
    rpcUrl: process.env.NEAR_RPC_URL ?? DEFAULT_RPC[networkId] ?? required('NEAR_RPC_URL'),
    explorerUrl: process.env.EXPLORER_URL ?? `https://${networkId === 'mainnet' ? '' : 'testnet.'}nearblocks.io`,
    contractId: required('ENVELOPE_CONTRACT_ID'),
    agentId: required('AGENT_ACCOUNT_ID'),
    agentKey: required('AGENT_PRIVATE_KEY'),
    vendorId: required('VENDOR_ACCOUNT_ID'),
    attackerId: process.env.ATTACKER_ACCOUNT_ID ?? `mallory-drain.${networkId}`,
    ownerId,
    ownerKey,
    devSignerKey: required('DEV_SIGNER_PRIVATE_KEY'),
    yoctoPerUsd: BigInt(process.env.YOCTO_PER_USD ?? '1000000000000000000'),
    port: Number(process.env.PORT ?? 8787),
    attestationPath: process.env.ATTESTATION_PATH ?? join(REPO_ROOT, 'docs', 'sample_attestation.json'),
    nearAiKey: process.env.NEAR_AI_API_KEY || null,
  };
}
