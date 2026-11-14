// Generates public, reproducible proof examples (demo inputs only; never the live strategy salt/params).
import fs from 'node:fs';
import { decide } from '../src/decide.js';
import { proveDecision, verifyProof, VKEY_PATH } from '../src/prove.js';
import { parseParams, commitmentOf, handleTurn, toHex32, VFY_VKEY } from '../src/vfy.js';
const out = new URL('../examples/', import.meta.url);
const task = {
  type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_example_vk_substitution', mode: 'practice',
  input: { registered_vk: '0x7d3a00000000000000000000000000000000000000000000000000000000f291', proof_vk: '0xa4c100000000000000000000000000000000000000000000000000000000b8ff',
    minimum: '1000', public_balance: '1460', expiry_block: 8430000, current_block: 8420000,
    recipient: '0xDe42000000000000000000000000000000009f01', condition_recipient: '0xDe42000000000000000000000000000000009f01',
    amount: '500', max_transfer: '1000', proof_tx: '0xa8000000000000000000000000000000000000000000000000000000000000002c' },
};
const v = decide(task.input);
const t0 = Date.now();
const g = await proveDecision(task, { circuitDecision: v.circuitDecision, salt: 0n });
const gms = Date.now() - t0;
const gOk = await verifyProof(g.proof, g.public_signals, JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8')));
fs.writeFileSync(new URL('gatekeeper-task.json', out), JSON.stringify(task, null, 2) + '\n');
fs.writeFileSync(new URL('gatekeeper-response.json', out), JSON.stringify({ decision: v.decision, reason_code: v.reason_code, proof_tx: task.input.proof_tx, ...g }, null, 2) + '\n');

const params = parseParams('5,50,20,0'); // demo strategy, NOT the live one
const salt = 123456789n;
const commitment = await commitmentOf(params, salt);
const env = { protocolVersion: 'v1', eventId: 'steal-the-vfy', mode: 'practice', matchId: '9f4e1b2a-1c2d-4e5f-8a9b-0c1d2e3f4a5b', turn: 3,
  state: { selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
  strategyCommitment: { hash: toHex32(commitment) }, resolverVersion: 'v1', nonce: '3c2f1a' };
const t1 = Date.now();
const { body } = await handleTurn(env, { params, salt, placement: 'top', now: () => new Date('2026-11-14T13:00:00Z') });
const vms = Date.now() - t1;
const vOk = await verifyProof(body.proof, body.public_signals, JSON.parse(fs.readFileSync(VFY_VKEY, 'utf8')));
fs.writeFileSync(new URL('vfy-turn.json', out), JSON.stringify(env, null, 2) + '\n');
fs.writeFileSync(new URL('vfy-response.json', out), JSON.stringify(body, null, 2) + '\n');
console.log(JSON.stringify({ gatekeeper: { decision: v.decision, reason: v.reason_code, verified: gOk, ms: gms }, vfy: { action: body.action, pih: body.policyProof.publicInputsHash, verified: vOk, ms: vms } }));
process.exit(gOk && vOk ? 0 : 1);
