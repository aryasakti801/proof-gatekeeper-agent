import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { decodeSecret, hmacHex, verifyHmac, SIGNATURE_HEADER } from './hmac.js';
import { decide } from './decide.js';
import { proveDecision } from './prove.js';
import { SeenSet } from './seen.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
loadEnv(path.join(root, '.env'));

const PORT = Number(process.env.PORT || 8787);
const SEEN_PATH = path.resolve(root, process.env.SEEN_PATH || './data/seen.json');
const SALT = BigInt(process.env.AGENT_GAMES_SALT || '0');

const secret = decodeSecret(requiredEnv('AGENT_GAMES_HMAC_SECRET'));
const seen = new SeenSet(SEEN_PATH);

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
  if (!verifyHmac(secret, raw, sig)) {
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
    if (task?.type === 'agent-games.preflight.v1') {
      signedJson(res, 200, { ok: true, protocolVersion: 'v1' });
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
    console.log(`Proof Gatekeeper listening on :${PORT}  POST /agent`);
  });
}

export { app };
