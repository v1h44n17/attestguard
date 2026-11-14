/**
 * Console server: serves the dashboard and exposes the verifier over HTTP.
 *
 * It holds the agent key and can send transactions, so it is locked down:
 * it listens on loopback only, rejects requests whose Host is not loopback
 * (DNS rebinding), rejects cross-origin and cross-site requests (a web page
 * in the same browser cannot trigger a run), and sends a strict CSP.
 *
 *   GET  /api/state           envelope policy, signers and the quote report
 *   GET  /api/attest/live     fetch a fresh quote from NEAR AI Cloud (our nonce) and verify it
 *   POST /api/run/:scenario   run `attack` or `valid`; streams NDJSON steps
 *   POST /api/reset           owner action: zero the rolling spend window
 */
import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import {
  createServer,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type RequestListener,
  type ServerResponse,
} from 'node:http';
import { extname, join, normalize, sep } from 'node:path';
import { EnvelopeClient } from './chain.ts';
import { loadConfig, REPO_ROOT } from './config.ts';
import { verifyLive } from './live.ts';
import { verifyAttestation, type GatewayAttestation } from './quote.ts';
import { devSignerAddress, runScenario, type DemoContext, type ScenarioName } from './scenario.ts';

export const FRONTEND_DIR = join(REPO_ROOT, 'frontend');

const CONTENT_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
};

export const SECURITY_HEADERS: Record<string, string> = {
  'content-security-policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'cross-origin-resource-policy': 'same-origin',
  'cross-origin-opener-policy': 'same-origin',
  'cache-control': 'no-store',
};

/** The operations the console needs from the chain client. */
export type ConsoleClient = Pick<
  EnvelopeClient,
  'policy' | 'vendors' | 'signer' | 'canAdminister' | 'resetSpendWindow' | 'snapshot' | 'propose'
>;

export interface ConsoleDeps {
  runScenario: typeof runScenario;
  verifyLive: typeof verifyLive;
}

export interface ConsoleApp {
  context: DemoContext;
  client: ConsoleClient;
  /** Ports the server may be reached on; Host must be loopback on one of them. */
  ports: ReadonlySet<number>;
  frontendDir?: string;
  deps?: Partial<ConsoleDeps>;
}

/**
 * Whether a request may reach the console. Browsers always send `Host`, and
 * send `Origin` / `Sec-Fetch-Site` on cross-origin requests, so a page on
 * another site (or a rebinding hostname) is refused. Clients that send no
 * provenance headers at all (curl, scripts) are allowed: they are not a
 * browser an attacker can drive.
 */
export function isTrustedRequest(headers: IncomingHttpHeaders, ports: ReadonlySet<number>): boolean {
  const host = headers.host?.toLowerCase();
  if (host === undefined) return false;
  const allowed = [...ports].flatMap((port) => ['localhost', '127.0.0.1', '[::1]'].map((name) => `${name}:${port}`));
  if (!allowed.includes(host)) return false;
  const site = headers['sec-fetch-site'];
  if (site !== undefined && site !== 'same-origin' && site !== 'none') return false;
  const origin = headers.origin;
  return origin === undefined || origin === `http://${host}`;
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { ...SECURITY_HEADERS, 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(body));
}

async function state(context: DemoContext, client: ConsoleClient): Promise<object> {
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

async function serveStatic(frontendDir: string, pathname: string, response: ServerResponse): Promise<void> {
  const relative = normalize(pathname === '/' ? 'index.html' : pathname.slice(1));
  const file = join(frontendDir, relative);
  if (relative.startsWith('..') || !file.startsWith(frontendDir + sep)) {
    sendJson(response, 400, { error: 'bad path' });
    return;
  }
  try {
    const body = await readFile(file);
    response.writeHead(200, {
      ...SECURITY_HEADERS,
      'content-type': CONTENT_TYPES[extname(file)] ?? 'application/octet-stream',
    });
    response.end(body);
  } catch {
    sendJson(response, 404, { error: 'not found' });
  }
}

export function createHandler(app: ConsoleApp): RequestListener {
  const { context, client, ports } = app;
  const frontendDir = app.frontendDir ?? FRONTEND_DIR;
  const run = app.deps?.runScenario ?? runScenario;
  const live = app.deps?.verifyLive ?? verifyLive;
  // Transactions from one agent key must be sent one at a time.
  let busy = false;

  return (request: IncomingMessage, response: ServerResponse): void => {
    const method = request.method ?? 'GET';
    const { pathname } = new URL(request.url ?? '/', 'http://localhost');
    const route = `${method} ${pathname}`;
    const fail = (error: unknown): void => {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`${route} failed: ${message}`);
      if (response.headersSent) response.end(JSON.stringify({ type: 'error', message }) + '\n');
      else sendJson(response, 500, { error: message });
    };

    if (!isTrustedRequest(request.headers, ports)) {
      sendJson(response, 403, { error: 'forbidden: requests must come from this console on localhost' });
      return;
    }

    if (route === 'GET /api/state') {
      state(context, client).then((body) => sendJson(response, 200, body), fail);
      return;
    }

    if (route === 'GET /api/attest/live') {
      live().then(
        (result) =>
          sendJson(response, 200, {
            ok: result.report.ok,
            model: result.model,
            nonce: result.nonce,
            fetchMs: result.fetchMs,
            verifyMicros: result.report.micros,
            signingAddress: result.report.signingAddress,
            quoteHash: result.report.quoteHash,
            checks: result.report.checks,
          }),
        fail,
      );
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
        response.writeHead(200, { ...SECURITY_HEADERS, 'content-type': 'application/x-ndjson; charset=utf-8' });
        const write = (message: object): void => void response.write(JSON.stringify(message) + '\n');
        run(context, scenario, (step) => write({ type: 'step', step }))
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

    if (method === 'GET') {
      serveStatic(frontendDir, pathname, response).catch(fail);
      return;
    }
    sendJson(response, 404, { error: 'not found' });
  };
}

async function main(): Promise<void> {
  const config = loadConfig();
  const attestation = (JSON.parse(readFileSync(config.attestationPath, 'utf8')) as { gateway_attestation: GatewayAttestation })
    .gateway_attestation;
  const client = await EnvelopeClient.connect(config);
  const context: DemoContext = { config, client, attestation };
  const server = createServer(createHandler({ context, client, ports: new Set([config.port]) }));

  server.listen(config.port, '127.0.0.1', () => {
    const report = verifyAttestation(attestation);
    console.log(`AttestGuard console   http://localhost:${config.port}`);
    console.log(`envelope contract     ${config.contractId} (${config.networkId})`);
    console.log(`TDX quote             ${report.ok ? 'verified' : 'REJECTED'} in ${(report.micros / 1000).toFixed(2)} ms`);
  });
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
