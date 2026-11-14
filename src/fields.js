/** BN254 / bn128 scalar field prime. */
export const FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function hexToField(value) {
  if (value == null) throw new Error('missing hex field');
  if (typeof value === 'bigint') return value % FIELD;
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || !Number.isInteger(value) || value < 0) {
      throw new Error(`invalid numeric field: ${value}`);
    }
    return BigInt(value) % FIELD;
  }
  let s = String(value).trim();
  if (!s) throw new Error('empty hex field');
  if (s.startsWith('0x') || s.startsWith('0X')) s = s.slice(2);
  if (!/^[0-9a-fA-F]+$/.test(s)) throw new Error(`invalid hex: ${value}`);
  return BigInt('0x' + s) % FIELD;
}

/** Pack a utf8 string as a big-endian integer (mod p). */
export function utf8ToField(value) {
  if (value == null) throw new Error('missing string field');
  if (typeof value === 'bigint' || typeof value === 'number') {
    return hexToField(value);
  }
  const s = String(value);
  if (/^0x[0-9a-fA-F]+$/i.test(s)) return hexToField(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s) % FIELD;
  const bytes = Buffer.from(s, 'utf8');
  let x = 0n;
  for (const b of bytes) x = (x * 256n + BigInt(b)) % FIELD;
  return x;
}

export function intToField(value) {
  if (value == null || value === '') throw new Error('missing int field');
  if (typeof value === 'bigint') return value % FIELD;
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || !Number.isInteger(value) || value < 0) {
      throw new Error(`invalid int: ${value}`);
    }
    return BigInt(value) % FIELD;
  }
  const s = String(value).trim();
  if (/^0x[0-9a-fA-F]+$/i.test(s)) return hexToField(s);
  if (!/^[0-9]+$/.test(s)) throw new Error(`invalid int: ${value}`);
  return BigInt(s) % FIELD;
}

export function fieldToString(x) {
  return (typeof x === 'bigint' ? x : BigInt(x)).toString();
}
