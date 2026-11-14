import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { decodeSecret, hmacHex, verifyHmac, secretCandidates, SIGNATURE_HEADER } from './hmac.js';
import { decide } from './decide.js';
import { proveDecision } from './prove.js';
import { SeenSet } from './seen.js';
import { isTurnEnvelope, handleTurn, parseParams, parseSalt, idempotencyKeyFor, CIRCUIT_VERSION } from './vfy.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
loadEnv(path.join(root, '.env'));

const PORT = Number(process.env.PORT || 8787);
const SEEN_PATH = path.resolve(root, process.env.SEEN_PATH || './data/seen.json');
const SALT = BigInt(process.env.AGENT_GAMES_SALT || '0');

let secret = decodeSecret(requiredEnv('AGENT_GAMES_HMAC_SECRET'));
const SECRET_CANDIDATES = secretCandidates(requiredEnv('AGENT_GAMES_HMAC_SECRET'));
const seen = new SeenSet(SEEN_PATH);
const TASK_LOG = path.resolve(root, process.env.TASK_LOG || './data/tasks.log');
const VFY_PLACEMENT = process.env.VFY_PROOF_PLACEMENT || 'both';
let VFY_PARAMS = null;
let VFY_SALT = null;
try {
  VFY_PARAMS = parseParams(process.env.STRATEGY_PARAMS);
  VFY_SALT = parseSalt(process.env.STRATEGY_SALT);
} catch (e) {
  console.log('Steal the VFY strategy not configured:', e.message);
}
const turnCache = new Map();

function logTask(entry) {
  // Public task data and our public answer only. Never secrets, params or salt.
  try {
    fs.mkdirSync(path.dirname(TASK_LOG), { recursive: true });
    fs.appendFileSync(TASK_LOG, JSON.stringify({ at: new Date().toISOString(), ...entry }) + '\n');
  } catch {}
}

const app = express();
app.disable('x-powered-by');
app.use(
  express.raw({
    type: () => true,
    limit: '2mb',
  }),
);

app.get('/health', (_req, res) => {
  res.json({ ok: true, protocolVersion: 'v1' });
});

app.post(['/agent', '/'], async (req, res) => {
  const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body ?? '');
  const sig = req.headers[SIGNATURE_HEADER];
  const match = SECRET_CANDIDATES.find((k) => verifyHmac(k, raw, sig));
  if (match) secret = match;
  if (!match) {
    const hdr = sig == null ? 'missing' : `len=${String(sig).length} prefix=${String(sig).slice(0, 7).replace(/[0-9a-f]/gi, 'h')}`;
    console.log(new Date().toISOString(), '401 bad signature', hdr, 'bodylen', raw.length, 'headers', Object.keys(req.headers).filter((h) => h.includes('sig') || h.includes('agent')).join(','));
    res.status(401).json({ error: 'invalid signature' });
    return;
  }

  let task;
  try {
    task = JSON.parse(raw.toString('utf8'));
  } catch {
    signedJson(res, 400, { error: 'invalid json' });
    return;
  }

  try {
    if (task?.type === 'agent-games.preflight.v1' || (typeof task?.type === 'string' && task.type.includes('preflight'))) {
      logTask({ kind: 'preflight', type: task.type });
      signedJson(res, 200, { ok: true, protocolVersion: 'v1' });
      return;
    }

    if (isTurnEnvelope(task)) {
      await handleTurnRequest(task, res);
      return;
    }

    if (task?.type !== 'agent-games.proof-gatekeeper.v1') {
      signedJson(res, 400, { error: 'unsupported type', type: task?.type ?? null });
      return;
    }

    if (task.task_id && seen.getTask(task.task_id)) {
      const cached = seen.getTask(task.task_id);
      signedJson(res, 200, cached);
      return;
    }

    const input = task.input;
    if (!input) {
      signedJson(res, 400, { error: 'missing input' });
      return;
    }

    const already = seen.hasProofTx(input.proof_tx);
    const verdict = decide(input, { seenProofTx: already });
    const body = {
      decision: verdict.decision,
      reason_code: verdict.reason_code,
    };
    if (input.proof_tx) body.proof_tx = input.proof_tx;

    if (verdict.includeProof) {
      const proved = await proveDecision(task, {
        circuitDecision: verdict.circuitDecision,
        salt: SALT,
      });
      body.proof = proved.proof;
      body.public_signals = proved.public_signals;
    }

    logTask({ kind: 'gatekeeper', task_id: task.task_id, mode: task.mode, input, decision: body.decision, reason_code: body.reason_code, proved: !!body.proof });
    if (task.task_id) seen.rememberTask(task.task_id, body);
    if (verdict.decision === 'APPROVE') seen.rememberApproval(input.proof_tx);

    signedJson(res, 200, body);
  } catch (err) {
    console.error('task failed', err?.message || err);
    // Fail closed: never approve on error. Reason only, no potentially-invalid proof.
    signedJson(res, 200, {
      decision: 'REJECT',
      reason_code: 'MISSING_VERIFICATION',
      error: 'internal',
    });
  }
});

async function handleTurnRequest(env, res) {
  const key = `${env.matchId}:${env.turn}`;
  if (turnCache.has(key)) {
    signedJson(res, 200, turnCache.get(key));
    return;
  }
  let body;
  let info = {};
  try {
    if (!VFY_PARAMS || !VFY_SALT) throw new Error('strategy not configured');
    const r = await handleTurn(env, { params: VFY_PARAMS, salt: VFY_SALT, placement: VFY_PLACEMENT });
    body = r.body;
    info = { proved: r.proved, error: r.error };
  } catch (err) {
    console.error('turn failed', err?.message || err);
    // Fail closed: HOLD (amount omitted), no invalid proof.
    body = {
      matchId: env.matchId,
      turn: env.turn,
      action: { type: 'HOLD' },
      policyProof: { circuitVersion: CIRCUIT_VERSION },
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: idempotencyKeyFor(env.matchId, env.turn),
    };
    info = { proved: false, error: String(err?.message || err).slice(0, 200) };
  }
  if (info.proved) turnCache.set(key, body);
  logTask({ kind: 'vfy-turn', matchId: env.matchId, turn: env.turn, mode: env.mode, state: env.state, commitment: env.strategyCommitment?.hash, action: body.action, publicInputsHash: body.policyProof?.publicInputsHash, ...info });
  signedJson(res, 200, body);
}

function signedJson(res, status, obj) {
  const body = JSON.stringify(obj);
  const signature = hmacHex(secret, body);
  res.status(status);
  res.setHeader('content-type', 'application/json');
  res.setHeader(SIGNATURE_HEADER, signature);
  res.send(body);
}

function requiredEnv(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`Missing ${name}. Copy .env.example to .env and fill it in.`);
    process.exit(1);
  }
  return v;
}

function loadEnv(file) {
  try {
    const text = fs.readFileSync(file, 'utf8');
    for (const line of text.split('\n')) {
      const t = line.trim();
      if (!t || t.startsWith('#')) continue;
      const eq = t.indexOf('=');
      if (eq <= 0) continue;
      const key = t.slice(0, eq).trim();
      let val = t.slice(eq + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (process.env[key] == null) process.env[key] = val;
    }
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
}

if (process.env.AGENT_GAMES_BIND !== 'false') {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Agent Games agent listening on :${PORT}  POST /agent`);
  });
}

export { app };
