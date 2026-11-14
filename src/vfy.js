/**
 * Steal the VFY — policy, commitment, public-inputs hash and Groth16 policy proof.
 *
 * Circuit: official vfy-policy.wasm / vfy-policy_final.zkey (template VfyPolicyProof).
 * Inputs (reverse-engineered from the official wasm, nPublic = 9):
 *   public : commitment, matchId, turnNumber, selfBalance, opponentBalance,
 *            action (0 HOLD, 1 FORTIFY, 2 EXTRACT), amount, circuitVersion (v1 -> 1)
 *   private: strategyParams[8], salt
 *   output : Poseidon(matchId, turnNumber, circuitVersion)
 * Public signals order: [out, commitment, matchId, turnNumber, selfBalance,
 *                        opponentBalance, action, amount, circuitVersion]
 *
 * Constraints enforced by the circuit:
 *   commitment == Poseidon(strategyParams[0..7], salt)
 *   strategyParams[4..7] == 0
 *   1 <= p0 <= 10          (EXTRACT amount)
 *   p3 in {0,1}            (1 = never extract)
 *   fortify = selfBalance < p1
 *   extract = !fortify && opponentBalance > p2 && p3 == 0
 *   action  = fortify ? FORTIFY : extract ? EXTRACT : HOLD
 *   amount  = action == EXTRACT ? p0 : 0
 *
 * The real parameter values and salt live in .env only (STRATEGY_PARAMS,
 * STRATEGY_SALT) and are never logged or committed.
 */
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { groth16 } from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import { keccak_256 } from '@noble/hashes/sha3';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const VFY_WASM = path.join(root, 'circuits', 'vfy-policy.wasm');
export const VFY_ZKEY = path.join(root, 'circuits', 'vfy-policy_final.zkey');
export const VFY_VKEY = path.join(root, 'circuits', 'vfy_verification_key.json');

export const ACTION_CODE = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };
export const CIRCUIT_VERSION = 'v1';
const CIRCUIT_VERSION_NUM = 1n;
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let poseidonP;
async function poseidon(values) {
  poseidonP ??= buildPoseidon();
  const P = await poseidonP;
  return BigInt(P.F.toString(P(values.map(BigInt))));
}

export function parseParams(str) {
  const arr = String(str ?? '').split(',').map((s) => s.trim()).filter(Boolean).map((s) => BigInt(s));
  if (arr.length < 4 || arr.length > 8) throw new Error('STRATEGY_PARAMS must have 4..8 integers');
  while (arr.length < 8) arr.push(0n);
  const [p0, , , p3] = arr;
  if (p0 < 1n || p0 > 10n) throw new Error('p0 (extract amount) must be 1..10');
  if (p3 !== 0n && p3 !== 1n) throw new Error('p3 must be 0 or 1');
  if (arr.slice(4).some((v) => v !== 0n)) throw new Error('params[4..7] must be 0');
  return arr;
}

export function parseSalt(str) {
  if (str == null || String(str).trim() === '') throw new Error('STRATEGY_SALT missing');
  const s = String(str).trim();
  const v = /^0x/i.test(s) ? BigInt(s) : BigInt(s);
  if (v <= 0n || v >= FIELD) throw new Error('STRATEGY_SALT out of field range');
  return v;
}

export async function commitmentOf(params, salt) {
  return poseidon([...params, salt]);
}

export function toHex32(x) {
  return '0x' + BigInt(x).toString(16).padStart(64, '0');
}

/** Pure policy mirroring the circuit exactly. */
export function policy(state, params) {
  const self = BigInt(state.selfBalance);
  const opp = BigInt(state.opponentBalance);
  const [p0, p1, p2, p3] = params;
  if (self < p1) return { type: 'FORTIFY' };
  if (opp > p2 && p3 === 0n) return { type: 'EXTRACT', amount: Number(p0) };
  return { type: 'HOLD' };
}

export function matchIdToBigInt(matchId) {
  const hex = String(matchId).replace(/-/g, '').replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]+$/.test(hex)) throw new Error('matchId is not hex/uuid');
  return BigInt('0x' + hex);
}

function word(x) {
  const b = BigInt(x);
  if (b < 0n || b >= 1n << 256n) throw new Error('word out of range');
  return Buffer.from(b.toString(16).padStart(64, '0'), 'hex');
}

/** keccak256 over 8 × 32-byte big-endian words, field order per /build. */
export function publicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, action, amount }) {
  const buf = Buffer.concat([
    word(BigInt(commitment)),
    word(matchIdToBigInt(matchId)),
    word(BigInt(turn)),
    word(BigInt(selfBalance)),
    word(BigInt(opponentBalance)),
    word(ACTION_CODE[action]),
    word(BigInt(amount ?? 0)),
    word(CIRCUIT_VERSION_NUM),
  ]);
  return '0x' + Buffer.from(keccak_256(buf)).toString('hex');
}

export function idempotencyKeyFor(matchId, turn) {
  const h = crypto.createHash('sha256').update(`steal-the-vfy:${matchId}:${turn}`).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${((parseInt(h[16], 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

export function isTurnEnvelope(msg) {
  if (!msg || typeof msg !== 'object') return false;
  if (msg.eventId === 'steal-the-vfy') return true;
  if (typeof msg.type === 'string' && /steal|vfy/i.test(msg.type)) return true;
  return msg.matchId != null && msg.turn != null && msg.state != null;
}

/**
 * Build the full turn response. Returns { body, proved }.
 * placement: 'both' | 'top' | 'nested' — where proof/public_signals are attached.
 */
export async function handleTurn(env, { params, salt, placement = 'both', now = () => new Date() }) {
  const st = env.state ?? {};
  const matchId = env.matchId;
  const turn = env.turn;
  const base = {
    matchId,
    turn,
    agentTimestamp: now().toISOString(),
    idempotencyKey: idempotencyKeyFor(matchId, turn),
  };

  const commitment = await commitmentOf(params, salt);
  const given = env.strategyCommitment?.hash;
  if (given != null && BigInt(given) !== commitment) {
    // Our committed strategy is not the one the platform froze: we cannot prove anything.
    return { body: { ...base, action: { type: 'HOLD' }, policyProof: { circuitVersion: CIRCUIT_VERSION } }, proved: false, error: 'commitment mismatch' };
  }

  const action = policy(st, params);
  const amount = action.type === 'EXTRACT' ? BigInt(action.amount) : 0n;
  const input = {
    commitment: commitment.toString(),
    matchId: matchIdToBigInt(matchId).toString(),
    turnNumber: BigInt(turn).toString(),
    selfBalance: BigInt(st.selfBalance).toString(),
    opponentBalance: BigInt(st.opponentBalance).toString(),
    action: ACTION_CODE[action.type].toString(),
    amount: amount.toString(),
    circuitVersion: CIRCUIT_VERSION_NUM.toString(),
    strategyParams: params.map(String),
    salt: salt.toString(),
  };
  const { proof, publicSignals } = await groth16.fullProve(input, VFY_WASM, VFY_ZKEY);
  const cleanProof = { pi_a: proof.pi_a, pi_b: proof.pi_b, pi_c: proof.pi_c, protocol: proof.protocol, curve: proof.curve };
  const pih = publicInputsHash({
    commitment, matchId, turn, selfBalance: st.selfBalance, opponentBalance: st.opponentBalance, action: action.type, amount,
  });
  const policyProof = { circuitVersion: CIRCUIT_VERSION, publicInputsHash: pih };
  if (placement === 'both' || placement === 'nested') {
    policyProof.proof = cleanProof;
    policyProof.public_signals = publicSignals;
  }
  const body = { ...base, action, policyProof };
  if (placement === 'both' || placement === 'top') {
    body.proof = cleanProof;
    body.public_signals = publicSignals;
  }
  return { body, proved: true };
}
