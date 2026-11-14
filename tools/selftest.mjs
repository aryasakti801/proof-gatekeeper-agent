// Self-signed live test against the running agent. Reads the secret from .env; never prints it.
import fs from 'node:fs';
import { createHmac } from 'node:crypto';
import { decodeSecret } from '../src/hmac.js';
import { parseParams, parseSalt, commitmentOf, toHex32 } from '../src/vfy.js';
const text = fs.readFileSync(new URL('../.env', import.meta.url), 'utf8');
const get = (k) => (text.match(new RegExp(`^${k}=(.*)$`, 'm')) || [])[1]?.trim().replace(/^['"]|['"]$/g, '');
const secret = decodeSecret(get('AGENT_GAMES_HMAC_SECRET'));
const url = process.argv[2] || 'http://127.0.0.1:8787/agent';
const sign = (b) => createHmac('sha256', secret).update(b).digest('hex');
const commit = toHex32(await commitmentOf(parseParams(get('STRATEGY_PARAMS')), parseSalt(get('STRATEGY_SALT'))));
const id = Date.now().toString(16);
const cases = {
  preflight: { type: 'agent-games.preflight.v1', agent_id: 'agt_selftest', issued_at: new Date().toISOString(), nonce: id },
  gatekeeper: { type: 'agent-games.proof-gatekeeper.v1', task_id: 'selftest_' + id, mode: 'practice', issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: { registered_vk: '0x7d3a01', proof_vk: '0xa4c1ff', minimum: '1000', public_balance: '1460', expiry_block: 8430000, current_block: 8420000, recipient: '0xDe429f01', condition_recipient: '0xDe429f01', amount: '500', max_transfer: '1000', proof_tx: '0x' + id } },
  turn: { protocolVersion: 'v1', eventId: 'steal-the-vfy', mode: 'practice', matchId: '00000000-0000-4000-8000-' + id.padStart(12, '0').slice(-12), turn: 1, issuedAt: new Date().toISOString(), deadlineAt: new Date(Date.now() + 300000).toISOString(),
    state: { selfBalance: '100', opponentBalance: '100', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, strategyCommitment: { hash: commit }, resolverVersion: 'v1', nonce: id },
};
for (const [name, payload] of Object.entries(cases)) {
  const body = JSON.stringify(payload);
  const t0 = Date.now();
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'x-agent-games-signature': sign(body) }, body });
  const t = await r.text();
  const j = JSON.parse(t);
  const sigOk = r.headers.get('x-agent-games-signature') === sign(t);
  const summary = name === 'turn' ? { action: j.action, pih: j.policyProof?.publicInputsHash?.slice(0, 12), proof: !!j.proof, nested: !!j.policyProof?.proof, signals: j.public_signals?.length }
    : name === 'gatekeeper' ? { decision: j.decision, reason_code: j.reason_code, proof: !!j.proof, signals: j.public_signals?.length } : j;
  console.log(name, r.status, 'signed:', sigOk, `${Date.now() - t0}ms`, JSON.stringify(summary));
}
