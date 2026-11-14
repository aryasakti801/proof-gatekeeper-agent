import { createHmac, timingSafeEqual } from 'node:crypto';

export const SIGNATURE_HEADER = 'x-agent-games-signature';

/** Decode the dashboard secret: 32-byte hex (optional 0x) or raw plaintext. */
export function decodeSecret(secret) {
  if (secret == null) throw new Error('AGENT_GAMES_HMAC_SECRET is not set');
  const s = String(secret).trim();
  if (!s) throw new Error('AGENT_GAMES_HMAC_SECRET is empty');
  const hex = s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s;
  if (/^[0-9a-fA-F]+$/.test(hex) && hex.length === 64) {
    return Buffer.from(hex, 'hex');
  }
  return Buffer.from(s, 'utf8');
}

export function hmacHex(secretBytes, body) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
  return createHmac('sha256', secretBytes).update(buf).digest('hex');
}

export function verifyHmac(secretBytes, body, signatureHeader) {
  if (signatureHeader == null || signatureHeader === '') return false;
  const expected = hmacHex(secretBytes, body);
  const got = String(signatureHeader).trim().toLowerCase().replace(/^0x/, '');
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(got, 'hex');
  if (a.length !== b.length || a.length === 0) return false;
  return timingSafeEqual(a, b);
}
