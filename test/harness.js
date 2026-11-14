import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHmac } from 'node:crypto';
import { decide, REASON } from '../src/decide.js';
import { proveDecision, verifyProof, VKEY_PATH } from '../src/prove.js';
import { policy, parseParams, commitmentOf, handleTurn, publicInputsHash, toHex32, VFY_VKEY, isTurnEnvelope } from '../src/vfy.js';
import { utils as ethersUtils } from 'ethers';
const { keccak256, solidityPack: solidityPacked } = ethersUtils;

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SECRET_HEX = 'ab'.repeat(32);
const secret = Buffer.from(SECRET_HEX, 'hex');
import net from 'node:net';
async function getFreePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
    s.on('error', reject);
  });
}
const PORT = await getFreePort();

const baseInput = {
  registered_vk: '0x7d3a1234567890abcdef1234567890abcdef1234567890abcdef123456f291',
  proof_vk: '0x7d3a1234567890abcdef1234567890abcdef1234567890abcdef123456f291',
  minimum: '1000',
  public_balance: '1460',
  expiry_block: 19842201,
  current_block: 19832000,
  recipient: '0xDe42444444444444444444444444444444449f01',
  condition_recipient: '0xDe42444444444444444444444444444444449f01',
  amount: '500',
  max_transfer: '1000',
  proof_tx: '0xa4c144444444444444444444444444444444444444444444444444448ff1',
};

let failed = 0;
function check(name, cond, detail) {
  if (cond) console.log('  ok  ', name);
  else {
    failed += 1;
    console.error('  FAIL', name, detail ?? '');
  }
}

function envelope(overrides = {}, inputOverrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: overrides.task_id ?? 'gk_test_1',
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60_000).toISOString(),
    ...overrides,
    input: { ...baseInput, ...inputOverrides, ...(overrides.input ?? {}) },
  };
}

console.log('1) decision logic');
{
  const ok = decide(baseInput);
  check('valid → APPROVE/VALID_PROOF', ok.decision === 'APPROVE' && ok.reason_code === REASON.VALID_PROOF && ok.includeProof);

  const vk = decide({ ...baseInput, proof_vk: '0xa4c1b8ff' });
  check('vk sub', vk.reason_code === REASON.VK_SUBSTITUTION && vk.circuitDecision === 0n);

  const thr = decide({ ...baseInput, public_balance: '999' });
  check('threshold = min-1', thr.reason_code === REASON.THRESHOLD_MISMATCH);
  const thrEq = decide({ ...baseInput, public_balance: '1000' });
  check('threshold = min still approve', thrEq.decision === 'APPROVE');

  const rcpt = decide({ ...baseInput, recipient: '0x01' });
  check('recipient mismatch', rcpt.reason_code === REASON.RECIPIENT_MISMATCH);

  const expEq = decide({ ...baseInput, current_block: 19842201 });
  check('current == expiry is expired', expEq.reason_code === REASON.EXPIRED_CONDITION);
  const expOk = decide({ ...baseInput, current_block: 19842200 });
  check('current == expiry-1 approve', expOk.decision === 'APPROVE');

  const amt = decide({ ...baseInput, amount: '1001' });
  check('amount overflow', amt.reason_code === REASON.AMOUNT_OVERFLOW);
  const amtEq = decide({ ...baseInput, amount: '1000' });
  check('amount == max approve', amtEq.decision === 'APPROVE');

  const reuse = decide(baseInput, { seenProofTx: true });
  check('reuse rejects without proof', reuse.reason_code === REASON.PROOF_REUSED && reuse.includeProof === false);

  const multi = decide({ ...baseInput, proof_vk: '0x11', public_balance: '1' });
  check('priority prefers VK_SUBSTITUTION', multi.reason_code === REASON.VK_SUBSTITUTION);
}

console.log('2) groth16 proofs verify');
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const proofCases = [
  ['valid approve', envelope({ task_id: 'gk_valid' }), 1n],
  ['vk reject', envelope({ task_id: 'gk_vk' }, { proof_vk: '0xa4c1b8ff' }), 0n],
  ['threshold reject', envelope({ task_id: 'gk_thr' }, { public_balance: '999' }), 0n],
  ['recipient reject', envelope({ task_id: 'gk_rcpt' }, { recipient: '0x01' }), 0n],
  ['expired reject', envelope({ task_id: 'gk_exp' }, { current_block: 19842201 }), 0n],
  ['overflow reject', envelope({ task_id: 'gk_amt' }, { amount: '1001' }), 0n],
];
for (const [name, task, decision] of proofCases) {
  const t0 = Date.now();
  const { proof, public_signals } = await proveDecision(task, { circuitDecision: decision, salt: 0n });
  const ok = await verifyProof(proof, public_signals, vkey);
  const ms = Date.now() - t0;
  check(`${name} verified in ${ms}ms`, ok === true && public_signals[11] === String(decision), { ok, d: public_signals[11] });
}

console.log('2b) Steal the VFY policy + proof');
const TEST_PARAMS = '7,40,30,0';
const TEST_SALT = 987654321n;
const vparams = parseParams(TEST_PARAMS);
check('policy extract', JSON.stringify(policy({ selfBalance: '95', opponentBalance: '105' }, vparams)) === '{"type":"EXTRACT","amount":7}');
check('policy hold at opp <= p2', policy({ selfBalance: '95', opponentBalance: '30' }, vparams).type === 'HOLD');
const fp = parseParams('5,50,20,0');
check('policy fortify', JSON.stringify(policy({ selfBalance: '49', opponentBalance: '105' }, fp)) === '{"type":"FORTIFY"}');
check('policy hold', policy({ selfBalance: '60', opponentBalance: '20' }, fp).type === 'HOLD');
let threw = false; try { parseParams('11,0,0,0'); } catch { threw = true; }
check('param p0 > 10 rejected', threw);
const vcommit = await commitmentOf(vparams, TEST_SALT);
const vfyVkey = JSON.parse(fs.readFileSync(VFY_VKEY, 'utf8'));
const turnEnv = (over = {}) => ({
  protocolVersion: 'v1', eventId: 'steal-the-vfy', mode: 'practice', matchId: '9f4e1b2a-1c2d-4e5f-8a9b-0c1d2e3f4a5b', turn: 3,
  issuedAt: new Date().toISOString(), deadlineAt: new Date(Date.now() + 300000).toISOString(),
  state: { selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
  strategyCommitment: { hash: toHex32(vcommit) }, resolverVersion: 'v1', nonce: '3c2f1a', ...over,
});
check('turn envelope detected', isTurnEnvelope(turnEnv()));
{
  const t0 = Date.now();
  const { body, proved } = await handleTurn(turnEnv(), { params: vparams, salt: TEST_SALT });
  const ok = await verifyProof(body.proof, body.public_signals, vfyVkey);
  check(`turn proof verifies in ${Date.now() - t0}ms`, proved && ok);
  check('nested proof present', body.policyProof.proof && body.policyProof.public_signals.length === 9);
  check('echo matchId/turn', body.matchId === turnEnv().matchId && body.turn === 3);
  check('extract amount 7', body.action.type === 'EXTRACT' && body.action.amount === 7);
  // reference hash computed independently (ethers solidityPacked uint256 x8)
  const ref = keccak256(solidityPacked(Array(8).fill('uint256'), [vcommit, BigInt('0x9f4e1b2a1c2d4e5f8a9b0c1d2e3f4a5b'), 3n, 95n, 105n, 2n, 7n, 1n]));
  check('publicInputsHash matches reference', body.policyProof.publicInputsHash === ref, body.policyProof.publicInputsHash + ' vs ' + ref);
  check('public signals carry state', body.public_signals[1] === vcommit.toString() && body.public_signals[3] === '3' && body.public_signals[4] === '95' && body.public_signals[5] === '105' && body.public_signals[6] === '2' && body.public_signals[7] === '7' && body.public_signals[8] === '1');
  const h = await handleTurn(turnEnv({ state: { selfBalance: '95', opponentBalance: '30' } }), { params: vparams, salt: TEST_SALT });
  check('HOLD omits amount', h.body.action.type === 'HOLD' && !('amount' in h.body.action) && (await verifyProof(h.body.proof, h.body.public_signals, vfyVkey)));
  const mm = await handleTurn(turnEnv({ strategyCommitment: { hash: '0x1234' } }), { params: vparams, salt: TEST_SALT });
  check('commitment mismatch -> HOLD unproved', mm.proved === false && mm.body.action.type === 'HOLD');
}

console.log('3) HTTP endpoint');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gk-seen-'));
const env = {
  ...process.env,
  PORT: String(PORT),
  AGENT_GAMES_HMAC_SECRET: SECRET_HEX,
  SEEN_PATH: path.join(tmp, 'seen.json'),
  AGENT_GAMES_SALT: '0',
  STRATEGY_PARAMS: '7,40,30,0',
  STRATEGY_SALT: '987654321',
  TASK_LOG: path.join(tmp, 'tasks.log'),
};
const child = spawn(process.execPath, ['src/server.js'], {
  cwd: root,
  env,
  stdio: ['ignore', 'pipe', 'pipe'],
});
let out = '';
child.stdout.on('data', (d) => { out += d.toString(); });
child.stderr.on('data', (d) => { out += d.toString(); });

function sign(body) {
  return createHmac('sha256', secret).update(body).digest('hex');
}

async function post(payload, { badSig = false, raw } = {}) {
  const body = raw ?? JSON.stringify(payload);
  const headers = { 'content-type': 'application/json', 'x-agent-games-signature': badSig ? '00'.repeat(32) : sign(body) };
  const res = await fetch(`http://127.0.0.1:${PORT}/agent`, { method: 'POST', headers, body });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json, text, sig: res.headers.get('x-agent-games-signature') };
}

function waitListen() {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('server start timeout\n' + out)), 8000);
    const iv = setInterval(() => {
      if (out.includes('listening')) {
        clearTimeout(t); clearInterval(iv); resolve();
      }
    }, 50);
    child.on('exit', (code) => {
      if (!out.includes('listening')) {
        clearTimeout(t); clearInterval(iv);
        reject(new Error('server exited ' + code + '\n' + out));
      }
    });
  });
}

try {
  await waitListen();

  const health = await fetch(`http://127.0.0.1:${PORT}/health`);
  check('health', (await health.json()).ok === true);

  const pre = await post({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
  check('preflight 200', pre.status === 200 && pre.json.ok === true && pre.json.protocolVersion === 'v1');
  check('preflight signed', pre.sig === sign(pre.text));

  const bad = await post(envelope({ task_id: 'gk_bad' }), { badSig: true });
  check('bad hmac 401', bad.status === 401);

  const valid = await post(envelope({ task_id: 'gk_http_valid' }));
  check('valid approve+proof', valid.status === 200 && valid.json.decision === 'APPROVE' && valid.json.reason_code === 'VALID_PROOF' && valid.json.proof && valid.json.public_signals?.length === 13);
  check('valid response signed', valid.sig === sign(valid.text));
  const vOk = await verifyProof(valid.json.proof, valid.json.public_signals, vkey);
  check('http proof verifies', vOk === true);

  const again = await post(envelope({ task_id: 'gk_http_valid' }));
  check('idempotent same body', again.text === valid.text);

  const vk = await post(envelope({ task_id: 'gk_http_vk' }, { proof_vk: '0xa4c1b8ff' }));
  check('http VK_SUBSTITUTION', vk.json.reason_code === 'VK_SUBSTITUTION' && vk.json.decision === 'REJECT' && vk.json.proof);

  const reuse = await post(envelope({ task_id: 'gk_http_reuse' }, { proof_tx: baseInput.proof_tx }));
  check('reuse after approve has no proof', reuse.json.reason_code === 'PROOF_REUSED' && reuse.json.decision === 'REJECT' && !reuse.json.proof);

  const turn = await post(turnEnv());
  check('turn 200 signed', turn.status === 200 && turn.sig === sign(turn.text));
  check('turn EXTRACT proved', turn.json.action?.type === 'EXTRACT' && (await verifyProof(turn.json.proof, turn.json.public_signals, vfyVkey)));
  const turnAgain = await post(turnEnv());
  check('turn idempotent', turnAgain.text === turn.text);
  const pre2 = await post({ protocolVersion: 'v1', eventId: 'steal-the-vfy', type: 'agent-games.preflight.v1', nonce: 'x' });
  check('preflight w/ eventId', pre2.json.ok === true);
} finally {
  child.kill('SIGTERM');
  setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1000);
}

if (failed) {
  console.error(`\n${failed} check(s) failed`);
  process.exit(1);
}
console.log('\nAll checks passed');
process.exit(0);
