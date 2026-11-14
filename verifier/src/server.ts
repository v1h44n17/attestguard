/**
 * Console server: serves the dashboard and exposes the verifier over HTTP.
 *
 * It holds the agent key, so it listens on localhost only.
 *
 *   GET  /api/state           envelope policy, signers and the quote report
 *   POST /api/run/:scenario   run `attack` or `valid`; streams NDJSON steps
 *   POST /api/reset           owner action: zero the rolling spend window
 */
import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createServer, type ServerResponse } from 'node:http';
import { extname, join, normalize, sep } from 'node:path';
import { EnvelopeClient } from './chain.ts';
import { loadConfig, REPO_ROOT } from './config.ts';
import { verifyAttestation, type GatewayAttestation } from './quote.ts';
import { devSignerAddress, runScenario, type DemoContext, type ScenarioName } from './scenario.ts';

const FRONTEND_DIR = join(REPO_ROOT, 'frontend');
const CONTENT_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  response.end(JSON.stringify(body));
}

async function state(context: DemoContext, client: EnvelopeClient): Promise<object> {
  const { config } = context;
  const report = verifyAttestation(context.attestation);
  const devAddress = devSignerAddress(config);
  const [policy, vendors, teeSigner, devSigner] = await Promise.all([
    client.policy(),
    client.vendors(),
    client.signer(report.signingAddress),
    client.signer(devAddress),
  ]);
  return {
    network: config.networkId,
    explorerUrl: config.explorerUrl,
    contractId: config.contractId,
    agentId: config.agentId,
    vendorId: config.vendorId,
    attackerId: config.attackerId,
    canReset: client.canAdminister,
    yoctoPerUsd: config.yoctoPerUsd.toString(),
    policy,
    vendors,
    signers: [
      { role: 'tee', address: report.signingAddress, registered: teeSigner?.quote_hash === report.quoteHash },
      { role: 'dev', address: devAddress, registered: devSigner?.quote_hash === report.quoteHash },
    ],
    attestation: report,
  };
}

async function serveStatic(pathname: string, response: ServerResponse): Promise<void> {
  const relative = normalize(pathname === '/' ? 'index.html' : pathname.slice(1));
  const file = join(FRONTEND_DIR, relative);
  if (relative.startsWith('..') || !file.startsWith(FRONTEND_DIR + sep)) {
    sendJson(response, 400, { error: 'bad path' });
    return;
  }
  try {
    const body = await readFile(file);
    response.writeHead(200, {
      'content-type': CONTENT_TYPES[extname(file)] ?? 'application/octet-stream',
      'cache-control': 'no-store',
    });
    response.end(body);
  } catch {
    sendJson(response, 404, { error: 'not found' });
  }
}

async function main(): Promise<void> {
  const config = loadConfig();
  const attestation = (JSON.parse(readFileSync(config.attestationPath, 'utf8')) as { gateway_attestation: GatewayAttestation })
    .gateway_attestation;
  const client = await EnvelopeClient.connect(config);
  const context: DemoContext = { config, client, attestation };
  // Transactions from one agent key must be sent one at a time.
  let busy = false;

  const server = createServer((request, response) => {
    const { pathname } = new URL(request.url ?? '/', 'http://localhost');
    const route = `${request.method} ${pathname}`;
    const fail = (error: unknown): void => {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`${route} failed: ${message}`);
      if (response.headersSent) response.end(JSON.stringify({ type: 'error', message }) + '\n');
      else sendJson(response, 500, { error: message });
    };

    if (route === 'GET /api/state') {
      state(context, client).then((body) => sendJson(response, 200, body), fail);
      return;
    }

    const scenario = /^POST \/api\/run\/(attack|valid)$/.exec(route)?.[1] as ScenarioName | undefined;
    if (scenario || route === 'POST /api/reset') {
      if (busy) {
        sendJson(response, 409, { error: 'Another transaction is in flight; try again in a moment.' });
        return;
      }
      busy = true;
      const done = (): void => {
        busy = false;
      };
      if (scenario) {
        response.writeHead(200, { 'content-type': 'application/x-ndjson; charset=utf-8', 'cache-control': 'no-store' });
        const write = (message: object): void => void response.write(JSON.stringify(message) + '\n');
        runScenario(context, scenario, (step) => write({ type: 'step', step }))
          .then((result) => {
            write({ type: 'result', result });
            response.end();
          }, fail)
          .finally(done);
      } else {
        client
          .resetSpendWindow()
          .then((txHash) => sendJson(response, 200, { txHash }), fail)
          .finally(done);
      }
      return;
    }

    if (request.method === 'GET') {
      serveStatic(pathname, response).catch(fail);
      return;
    }
    sendJson(response, 404, { error: 'not found' });
  });

  server.listen(config.port, '127.0.0.1', () => {
    const report = verifyAttestation(attestation);
    console.log(`AttestGuard console   http://localhost:${config.port}`);
    console.log(`envelope contract     ${config.contractId} (${config.networkId})`);
    console.log(`TDX quote             ${report.ok ? 'verified' : 'REJECTED'} in ${(report.micros / 1000).toFixed(2)} ms`);
  });
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
