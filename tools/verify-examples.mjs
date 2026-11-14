// Anyone can run: node tools/verify-examples.mjs  -> re-verifies the committed example proofs with snarkjs.
import fs from 'node:fs';
import { groth16 } from 'snarkjs';
const r = (p) => JSON.parse(fs.readFileSync(new URL(p, import.meta.url), 'utf8'));
const g = r('../examples/gatekeeper-response.json');
const v = r('../examples/vfy-response.json');
const gOk = await groth16.verify(r('../circuits/verification_key.json'), g.public_signals, g.proof);
const vOk = await groth16.verify(r('../circuits/vfy_verification_key.json'), v.public_signals, v.proof);
console.log('gatekeeper proof:', gOk ? 'VALID' : 'INVALID');
console.log('steal-the-vfy policy proof:', vOk ? 'VALID' : 'INVALID');
process.exit(gOk && vOk ? 0 : 1);
