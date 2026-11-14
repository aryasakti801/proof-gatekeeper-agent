// Prints ONLY the strategy commitment hash (never the params or salt).
// Usage: node tools/commitment.mjs            -> reads STRATEGY_PARAMS / STRATEGY_SALT from .env
//        node tools/commitment.mjs --init     -> if STRATEGY_SALT is missing, generates one into .env
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseParams, parseSalt, commitmentOf, toHex32 } from '../src/vfy.js';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envPath = path.join(root, '.env');
let text = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
const get = (k) => (text.match(new RegExp(`^${k}=(.*)$`, 'm')) || [])[1]?.trim();
if (process.argv.includes('--init') && !get('STRATEGY_SALT')) {
  const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const salt = (BigInt('0x' + crypto.randomBytes(32).toString('hex')) % (FIELD - 1n)) + 1n;
  text = text.replace(/^STRATEGY_SALT=.*\n?/m, '');
  text += (text.endsWith('\n') || !text ? '' : '\n') + `STRATEGY_SALT=${salt}\n`;
  fs.writeFileSync(envPath, text, { mode: 0o600 });
}
const params = parseParams(get('STRATEGY_PARAMS'));
const salt = parseSalt(get('STRATEGY_SALT'));
console.log(toHex32(await commitmentOf(params, salt)));
process.exit(0);
