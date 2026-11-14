/**
 * Terminal demo: runs the blocked attack and then the approved payment
 * against the live contract, printing each stage with its latency.
 *
 *   npm run demo            both scenarios
 *   npm run demo -- attack  only the attack
 *   npm run demo -- valid   only the valid payment
 */
import { readFileSync } from 'node:fs';
import { EnvelopeClient } from './chain.ts';
import { loadConfig } from './config.ts';
import type { GatewayAttestation } from './quote.ts';
import { formatMicros, runScenario, type DemoContext, type Level, type ScenarioName, type Step } from './scenario.ts';

const COLOR: Record<Level, string> = { info: '\x1b[36m', ok: '\x1b[32m', warn: '\x1b[33m', block: '\x1b[31m' };
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';

function print(step: Step): void {
  const latency = step.micros === undefined ? '' : `  ${DIM}${formatMicros(step.micros)}${RESET}`;
  console.log(`${COLOR[step.level]}${BOLD}[${step.stage}]${RESET} ${COLOR[step.level]}${step.title}${RESET}${latency}`);
  for (const line of step.lines) console.log(`  ${DIM}${line}${RESET}`);
}

async function main(): Promise<void> {
  const requested = process.argv[2];
  if (requested !== undefined && requested !== 'attack' && requested !== 'valid') {
    throw new Error(`Unknown scenario "${requested}". Use "attack" or "valid".`);
  }
  const scenarios: ScenarioName[] = requested ? [requested] : ['attack', 'valid'];

  const config = loadConfig();
  const attestation = (JSON.parse(readFileSync(config.attestationPath, 'utf8')) as { gateway_attestation: GatewayAttestation })
    .gateway_attestation;
  const context: DemoContext = { config, client: await EnvelopeClient.connect(config), attestation };

  console.log(`${BOLD}AttestGuard${RESET}  envelope ${config.contractId} on ${config.networkId}\n`);
  for (const scenario of scenarios) {
    console.log(`${BOLD}=== ${scenario === 'attack' ? 'Scenario 1: prompt-injected agent' : 'Scenario 2: legitimate payment'} ===${RESET}`);
    await runScenario(context, scenario, print);
    console.log();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
