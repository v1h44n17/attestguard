// The console server holds the agent key and can send transactions, so these
// tests pin its access rules: only same-origin requests to a loopback Host.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer, request, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import type { Config } from '../verifier/src/config.ts';
import { createHandler, isTrustedRequest, type ConsoleClient } from '../verifier/src/server.ts';
import type { GatewayAttestation } from '../verifier/src/quote.ts';
import type { ScenarioResult } from '../verifier/src/scenario.ts';

const attestation = (
  JSON.parse(readFileSync(join(import.meta.dirname, '..', 'docs', 'sample_attestation.json'), 'utf8')) as {
    gateway_attestation: GatewayAttestation;
  }
).gateway_attestation;

const config: Config = {
  networkId: 'testnet',
  rpcUrl: 'http://127.0.0.1:1',
  explorerUrl: 'https://explorer.invalid',
  contractId: 'envelope.testnet',
  agentId: 'agent.testnet',
  agentKey: 'unused',
  vendorId: 'vendor.testnet',
  attackerId: 'mallory.testnet',
  ownerId: 'owner.testnet',
  ownerKey: 'unused',
  devSignerKey: '07'.repeat(32),
  yoctoPerUsd: 10n ** 18n,
  port: 0,
  attestationPath: 'unused',
};

let resets = 0;
let runs = 0;
let release: () => void = () => {};
const client = {
  canAdminister: true,
  policy: async () => ({ daily_cap: '5', spent_24h: '0' }),
  vendors: async () => ['vendor.testnet'],
  signer: async () => null,
  resetSpendWindow: async () => {
    resets += 1;
    return 'RESET_TX';
  },
  snapshot: async () => {
    throw new Error('not used');
  },
  propose: async () => {
    throw new Error('not used');
  },
} as unknown as ConsoleClient;

const result = { scenario: 'valid', status: 'APPROVED' } as unknown as ScenarioResult;
const ports = new Set<number>();
let server: Server;
let port = 0;

before(async () => {
  server = createServer(
    createHandler({
      context: { config, client, attestation },
      client,
      ports,
      deps: {
        runScenario: async () => {
          runs += 1;
          await new Promise<void>((resolve) => (release = resolve));
          return result;
        },
        verifyLive: async () => {
          throw new Error('offline');
        },
      },
    }),
  );
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
  ports.add(port);
});

after(() => {
  release();
  server.close();
});

interface Reply {
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
}

function send(method: string, path: string, headers: Record<string, string> = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, method, path, headers: { host: `localhost:${port}`, ...headers } }, (res) => {
      let body = '';
      res.on('data', (chunk: Buffer) => (body += chunk.toString()));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('the console page and API answer same-origin requests', async () => {
  const page = await send('GET', '/');
  assert.equal(page.status, 200);
  assert.match(page.body, /AttestGuard/);
  const state = await send('GET', '/api/state', { origin: `http://localhost:${port}`, 'sec-fetch-site': 'same-origin' });
  assert.equal(state.status, 200);
  assert.equal((JSON.parse(state.body) as { contractId: string }).contractId, 'envelope.testnet');
});

test('every response carries the security headers', async () => {
  for (const path of ['/', '/api/state', '/app.js', '/missing']) {
    const reply = await send('GET', path);
    assert.match(String(reply.headers['content-security-policy']), /default-src 'none'.*frame-ancestors 'none'/, path);
    assert.equal(reply.headers['x-content-type-options'], 'nosniff', path);
    assert.equal(reply.headers['x-frame-options'], 'DENY', path);
    assert.equal(reply.headers['referrer-policy'], 'no-referrer', path);
  }
});

test('a page on another site cannot trigger a transaction', async () => {
  const before = resets;
  const evil = await send('POST', '/api/reset', { origin: 'https://evil.example' });
  assert.equal(evil.status, 403);
  const crossSite = await send('POST', '/api/reset', { 'sec-fetch-site': 'cross-site' });
  assert.equal(crossSite.status, 403);
  const sameSite = await send('POST', '/api/reset', { 'sec-fetch-site': 'same-site' });
  assert.equal(sameSite.status, 403);
  assert.equal(resets, before);
});

test('a rebinding hostname is refused', async () => {
  for (const host of ['evil.example', `evil.example:${port}`, `localhost.evil.example:${port}`, 'localhost:1']) {
    assert.equal((await send('GET', '/api/state', { host })).status, 403, host);
  }
});

test('the same-origin console can still reset the window', async () => {
  const before = resets;
  const reply = await send('POST', '/api/reset', { origin: `http://localhost:${port}`, 'sec-fetch-site': 'same-origin' });
  assert.equal(reply.status, 200);
  assert.equal(JSON.parse(reply.body).txHash, 'RESET_TX');
  assert.equal(resets, before + 1);
});

test('scripts that send no browser headers are allowed (curl)', async () => {
  const before = resets;
  assert.equal((await send('POST', '/api/reset')).status, 200);
  assert.equal(resets, before + 1);
});

test('static files cannot escape the frontend directory', async () => {
  for (const path of ['/../verifier/package.json', '/%2e%2e/verifier/package.json', '/..%2fverifier%2fpackage.json', '/../../etc/passwd']) {
    const reply = await send('GET', path);
    assert.ok(reply.status === 400 || reply.status === 404, `${path} -> ${reply.status}`);
    assert.doesNotMatch(reply.body, /attestguard-verifier|root:/);
  }
});

test('unknown routes and methods are rejected', async () => {
  assert.equal((await send('GET', '/api/nope')).status, 404);
  assert.equal((await send('DELETE', '/api/state')).status, 404);
  assert.equal((await send('POST', '/api/run/steal')).status, 404);
});

test('a failing live-verification lookup returns an error, not a crash', async () => {
  const reply = await send('GET', '/api/attest/live');
  assert.equal(reply.status, 500);
  assert.match(JSON.parse(reply.body).error, /offline/);
});

test('only one transaction runs at a time', async () => {
  const first = send('POST', '/api/run/valid');
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(runs, 1);
  const second = await send('POST', '/api/run/attack');
  assert.equal(second.status, 409);
  assert.equal((await send('POST', '/api/reset')).status, 409);
  release();
  const done = await first;
  assert.equal(done.status, 200);
  assert.match(done.body, /"type":"result"/);
  assert.equal((await send('POST', '/api/reset')).status, 200);
});

test('isTrustedRequest checks Host, Origin and Sec-Fetch-Site together', () => {
  const ok = new Set([8787]);
  assert.equal(isTrustedRequest({ host: 'localhost:8787' }, ok), true);
  assert.equal(isTrustedRequest({ host: '127.0.0.1:8787', origin: 'http://127.0.0.1:8787' }, ok), true);
  assert.equal(isTrustedRequest({ host: '[::1]:8787', 'sec-fetch-site': 'none' }, ok), true);
  assert.equal(isTrustedRequest({}, ok), false);
  assert.equal(isTrustedRequest({ host: 'localhost:8787', origin: 'http://localhost:9999' }, ok), false);
  assert.equal(isTrustedRequest({ host: 'LOCALHOST:8787' }, ok), true);
  assert.equal(isTrustedRequest({ host: 'localhost:8787', origin: 'null' }, ok), false);
});
