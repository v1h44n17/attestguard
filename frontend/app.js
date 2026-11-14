// AttestGuard console. Talks only to the local verifier server; all text is
// inserted with textContent, never as HTML.

const $ = (id) => document.getElementById(id);
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

const VALID_PAYMENT_USD = 3000n;
const buttons = ['run-all', 'run-attack', 'run-valid', 'reset'].map($);
let state = null;

const usd = (dollars) => '$' + Number(dollars).toLocaleString('en-US');
const yoctoToUsd = (yocto) => BigInt(yocto) / BigInt(state.yoctoPerUsd);
const micros = (value) => (value < 1000 ? `${value.toFixed(0)} µs` : `${(value / 1000).toFixed(2)} ms`);

function near(yocto, digits = 4) {
  const scaled = (BigInt(yocto) * 10n ** BigInt(digits)) / 10n ** 24n;
  return (Number(scaled) / 10 ** digits).toFixed(digits);
}

function setStatus(text) {
  $('status').textContent = text;
}

function setBusy(busy) {
  for (const button of buttons) button.disabled = busy || (button.id === 'reset' && !state?.canReset);
}

// ---------------------------------------------------------------- state

function renderState() {
  const { policy } = state;
  const cap = yoctoToUsd(policy.daily_cap);
  const spent = yoctoToUsd(policy.spent_24h);
  $('network').textContent = state.network;
  $('contract').textContent = state.contractId;
  $('contract').href = `${state.explorerUrl}/address/${state.contractId}`;
  $('agent').textContent = state.agentId;
  $('spent').textContent = usd(spent);
  $('cap').textContent = usd(cap);
  $('remaining').textContent = usd(yoctoToUsd(policy.remaining_24h));
  $('treasury').textContent = near(policy.available_balance);
  const fill = $('bar-fill');
  fill.style.width = `${cap === 0n ? 0 : Math.min(100, Number((spent * 100n) / cap))}%`;
  fill.classList.toggle('high', cap !== 0n && spent * 2n > cap);
  $('approved-count').textContent = policy.approved_count;
  $('blocked-count').textContent = policy.blocked_count;
  $('scale').textContent = `$1 = ${near(state.yoctoPerUsd, 6)} NEAR`;

  $('vendors').replaceChildren(...state.vendors.map((vendor) => el('li', '', vendor)));
  $('signers').replaceChildren(
    ...state.signers.map((signer) => {
      const item = el('li', signer.registered ? '' : 'off', `0x${signer.address}`);
      const role =
        signer.role === 'tee'
          ? 'NEAR AI Cloud enclave key, bound by the TDX report data'
          : 'demo stand-in key (not inside a TEE)';
      item.append(el('span', 'note', `${role}${signer.registered ? '' : ' · not registered on chain'}`));
      return item;
    }),
  );

  const { attestation } = state;
  const tag = $('quote-status');
  tag.textContent = attestation.ok ? 'VERIFIED' : 'REJECTED';
  tag.className = `tag ${attestation.ok ? 'ok' : 'block'}`;
  $('checks').replaceChildren(
    ...attestation.checks.map((check) => {
      const item = el('li', check.ok ? '' : 'bad', check.id.replaceAll('_', ' '));
      item.title = check.detail;
      return item;
    }),
  );
  $('quote-hash').textContent = attestation.quoteHash;
  $('quote-latency').textContent = micros(attestation.micros);

  document.querySelector('#card-attack .recipient').textContent = state.attackerId;
  document.querySelector('#card-valid .recipient').textContent = state.vendorId;
}

async function loadState() {
  const response = await fetch('/api/state');
  const body = await response.json();
  if (!response.ok) throw new Error(body.error ?? 'could not load state');
  state = body;
  renderState();
}

// ------------------------------------------------------------- terminal

const terminal = $('terminal');

function log(className, text) {
  terminal.append(el('div', `line ${className}`, text));
  terminal.scrollTop = terminal.scrollHeight;
}

function logStep(step) {
  const head = el('div', `line head ${step.level}`, `[${step.stage}] ${step.title}`);
  if (step.micros !== undefined) head.append(el('span', 'latency', `   ${micros(step.micros)}`));
  terminal.append(head);
  for (const line of step.lines) {
    terminal.append(el('div', `line sub${line.startsWith('EVENT_JSON:') ? ' event' : ''}`, line));
  }
  terminal.scrollTop = terminal.scrollHeight;
}

// ---------------------------------------------------------------- cards

function resetCard(card) {
  card.dataset.state = 'running';
  card.querySelector('.stamp').textContent = 'RUNNING';
  card.querySelector('.violations').replaceChildren();
  for (const stage of card.querySelectorAll('.pipeline li')) stage.className = '';
  for (const metric of card.querySelectorAll('.metrics dd')) metric.textContent = '–';
  const link = card.querySelector('.tx a');
  link.textContent = '–';
  link.removeAttribute('href');
}

function showStep(card, step) {
  const stage = card.querySelector(`.pipeline li[data-stage="${step.stage}"]`);
  if (stage) stage.className = step.level;
  if (step.stage === 'review' && step.level === 'block') {
    card.querySelector('.violations').replaceChildren(el('li', '', 'reviewer refused to sign'));
  }
}

function showResult(card, result) {
  const blocked = result.status === 'BLOCKED';
  card.dataset.state = blocked ? 'blocked' : 'approved';
  card.querySelector('.stamp').textContent = result.status;
  const list = card.querySelector('.violations');
  if (blocked) {
    list.replaceChildren(
      ...result.violations.map((violation) => {
        const item = el('li', '', `✗ ${violation}`);
        return item;
      }),
    );
  } else {
    list.replaceChildren(
      el('li', 'pass', '✓ vendor allowlisted'),
      el('li', 'pass', '✓ inside the rolling 24h cap'),
      el('li', 'pass', '✓ intent signed by an attested key'),
      el('li', 'pass', `✓ ${near(result.amountYocto)} NEAR transferred on chain`),
    );
  }
  card.querySelector('.gate').textContent = micros(result.latency.gateMicros);
  card.querySelector('.quote').textContent = micros(result.latency.quoteVerifyMicros);
  card.querySelector('.chain').textContent = `${(result.latency.chainMs / 1000).toFixed(2)} s`;
  const link = card.querySelector('.tx a');
  link.textContent = result.txHash;
  link.href = result.explorerUrl;
}

// ------------------------------------------------------------- scenarios

async function* ndjson(response) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let newline;
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      if (line) yield JSON.parse(line);
    }
  }
}

async function runScenario(name) {
  const card = $(`card-${name}`);
  resetCard(card);
  log('rule', '─'.repeat(72));
  setStatus(name === 'attack' ? 'running the prompt-injection attack…' : 'running the legitimate payment…');
  try {
    const response = await fetch(`/api/run/${name}`, { method: 'POST' });
    if (!response.ok) throw new Error((await response.json()).error ?? `HTTP ${response.status}`);
    let result = null;
    for await (const message of ndjson(response)) {
      if (message.type === 'step') {
        logStep(message.step);
        showStep(card, message.step);
      } else if (message.type === 'result') {
        result = message.result;
      } else if (message.type === 'error') {
        throw new Error(message.message);
      }
    }
    if (!result) throw new Error('the run ended without a result');
    showResult(card, result);
    return result;
  } catch (error) {
    card.dataset.state = 'error';
    card.querySelector('.stamp').textContent = 'ERROR';
    log('head block', `[error] ${error.message}`);
    throw error;
  }
}

async function resetWindow() {
  setStatus('owner: resetting the 24h spend window…');
  const response = await fetch('/api/reset', { method: 'POST' });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`);
  log('head info', `[owner] spend window reset`);
  log('sub', `${state.explorerUrl}/txns/${body.txHash}`);
}

/** Run `task` with the controls locked, then refresh the on-chain state. */
async function guarded(task) {
  setBusy(true);
  try {
    await task();
    setStatus('done');
  } catch (error) {
    setStatus(`failed: ${error.message}`);
  } finally {
    await loadState().catch(() => {});
    setBusy(false);
  }
}

async function runDemo() {
  await runScenario('attack');
  await loadState();
  // The demo payment must fit the window; if an earlier run used it up, the
  // owner resets it first (logged above the run, and visible on chain).
  if (state.canReset && yoctoToUsd(state.policy.remaining_24h) < VALID_PAYMENT_USD) await resetWindow();
  await runScenario('valid');
}

async function verifyLiveQuote() {
  const button = $('verify-live');
  const result = $('live-result');
  button.disabled = true;
  result.textContent = 'asking NEAR AI Cloud for a fresh quote with a random nonce…';
  try {
    const response = await fetch('/api/attest/live');
    const body = await response.json();
    if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`);
    const failedChecks = body.checks.filter((check) => !check.ok).map((check) => check.id);
    result.replaceChildren(
      el('span', body.ok ? 'ok' : 'block', body.ok ? `✓ LIVE QUOTE VERIFIED (${body.checks.length} checks)` : `✗ REJECTED: ${failedChecks.join(', ')}`),
      el('span', '', `model ${body.model}`),
      el('span', '', `our nonce ${body.nonce.slice(0, 16)}… echoed by the enclave`),
      el('span', '', `signer 0x${body.signingAddress.slice(0, 16)}…`),
      el('span', '', `fetched ${(body.fetchMs / 1000).toFixed(1)} s · verified in ${micros(body.verifyMicros)}`),
    );
    log(body.ok ? 'head ok' : 'head block', `[live] NEAR AI Cloud quote ${body.ok ? 'verified' : 'rejected'}, nonce ${body.nonce}`);
    for (const check of body.checks) log('sub', `${check.ok ? '✓' : '✗'} ${check.id.padEnd(20)} ${check.detail}`);
  } catch (error) {
    result.textContent = `failed: ${error.message}`;
  } finally {
    button.disabled = false;
  }
}

$('run-all').addEventListener('click', () => guarded(runDemo));
$('run-attack').addEventListener('click', () => guarded(() => runScenario('attack')));
$('run-valid').addEventListener('click', () => guarded(() => runScenario('valid')));
$('reset').addEventListener('click', () => guarded(resetWindow));
$('verify-live').addEventListener('click', verifyLiveQuote);
$('clear').addEventListener('click', () => terminal.replaceChildren());

loadState().then(
  () => {
    setBusy(false);
    $('verify-live').disabled = false;
    setStatus('ready');
    log('head info', `[console] connected to ${state.contractId} on ${state.network}`);
  },
  (error) => setStatus(`cannot reach the verifier: ${error.message}`),
);
