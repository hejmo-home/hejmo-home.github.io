// Target validation of the Hejmo OAuth relay page (ADR 0013, hejmo-home/hejmo).
// No DOM, no network: it only turns the address of this page into "forward there",
// "refuse" or "opened directly", so it can be tested with `node --test`.
//
// The box (internal/googleauth State) sends Google a state of the form
//   hj1.<base64url, no padding, of the box's origin>.<token>
// and Google hands it back unchanged. The origin in it is where the browser goes back to.

export const CALLBACK_PATH = '/connections/google/callback';
// Google's answer: the relay passes these on, byte for byte, and nothing else.
const FORWARDED = ['code', 'state', 'error', 'scope'];

// isPrivateHost says whether a host name is an address in the home network (or this
// machine): 127.0.0.1, localhost, 10/8, 172.16/12, 192.168/16, *.local, IPv6 ULA
// (fc00::/7) and link-local (fe80::/10). Brackets around IPv6 are accepted.
export function isPrivateHost(host) {
  let h = String(host).toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (h.endsWith('.')) h = h.slice(0, -1);
  if (h === 'localhost') return true;
  if (h.endsWith('.local') && h.length > '.local'.length) return true;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (v4) {
    const [a, b, c, d] = v4.slice(1).map(Number);
    if ([a, b, c, d].some((n) => n > 255)) return false;
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  if (h.includes(':')) {
    const first = h.split(':')[0];
    if (!/^[0-9a-f]{1,4}$/.test(first)) return false;
    const n = parseInt(first, 16);
    return (n & 0xfe00) === 0xfc00 || (n & 0xffc0) === 0xfe80;
  }
  return false;
}

// decodeState returns the box's origin carried by a state, or null.
function decodeState(state) {
  const parts = state.split('.');
  if (parts.length !== 3 || parts[0] !== 'hj1' || parts[1] === '' || parts[2] === '') return null;
  if (!/^[A-Za-z0-9_-]+$/.test(parts[1])) return null;
  try {
    const bin = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

// resolveRelay takes this page's query string (location.search) and says what to do:
//   { kind: 'direct' }                       opened without Google's answer: explain
//   { kind: 'forward', target }              go to target (https://<box>/connections/google/callback?...)
//   { kind: 'refused', reason, shown? }      refuse; shown is the address that was asked for, if it is one
// reasons: 'no_box' (no usable box address in the state), 'bad_origin' (not a plain
// http(s) origin: other path, credentials, query ...), 'public_http' (http to a public address).
export function resolveRelay(search) {
  let q = String(search ?? '');
  const hash = q.indexOf('#');
  if (hash >= 0) q = q.slice(0, hash);
  if (q.startsWith('?')) q = q.slice(1);

  const kept = [];
  const states = [];
  for (const seg of q.split('&')) {
    const key = seg.split('=')[0];
    if (!FORWARDED.includes(key)) continue;
    kept.push(seg);
    if (key === 'state') states.push(seg.slice('state='.length));
  }
  if (kept.length === 0) return { kind: 'direct' };

  if (states.length !== 1) return { kind: 'refused', reason: 'no_box' };
  let state;
  try {
    state = decodeURIComponent(states[0]);
  } catch {
    return { kind: 'refused', reason: 'no_box' };
  }
  const origin = decodeState(state);
  if (origin === null) return { kind: 'refused', reason: 'no_box' };

  // A plain origin only: scheme://host[:port], nothing after it, no credentials.
  if (!/^https?:\/\/[^/?#@\\\s]+$/i.test(origin)) return { kind: 'refused', reason: 'bad_origin' };
  let u;
  try {
    u = new URL(origin);
  } catch {
    return { kind: 'refused', reason: 'bad_origin' };
  }
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || u.username || u.password || u.pathname !== '/' || u.search || u.hash) {
    return { kind: 'refused', reason: 'bad_origin' };
  }
  const base = u.origin + CALLBACK_PATH;
  if (u.protocol === 'http:' && !isPrivateHost(u.hostname)) {
    return { kind: 'refused', reason: 'public_http', shown: base };
  }
  return { kind: 'forward', target: base + '?' + kept.join('&') };
}
