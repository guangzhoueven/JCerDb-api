const ITER = 10000;
const enc = new TextEncoder();

export function randomHex(bytes) {
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function bytesToHex(buf) {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: ITER, hash: 'SHA-256' },
    key,
    256
  );
  return bytesToHex(bits);
}

export async function verifyPassword(password, saltHex, expectedHex) {
  const actual = await hashPassword(password, saltHex);
  if (actual.length !== expectedHex.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual.charCodeAt(i) ^ expectedHex.charCodeAt(i);
  return diff === 0;
}

export function parseCookies(request) {
  const header = request.headers.get('Cookie') || '';
  const jar = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) jar[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return jar;
}

export const ROLE_RANK = { user: 0, admin: 1, super: 2 };

export async function getAuth(request, env) {
  const token = parseCookies(request).session;
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT u.uid, u.username, u.role, u.status
     FROM sessions s JOIN users u ON u.uid = s.uid
     WHERE s.token = ? AND s.expires_at > ?`
  )
    .bind(token, Math.floor(Date.now() / 1000))
    .first();
  if (!row) return null;
  if (row.status !== 'active') return null;
  return row;
}

export function hasRole(user, required) {
  if (!user) return false;
  return ROLE_RANK[user.role] >= ROLE_RANK[required];
}
