import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveRelay, isPrivateHost } from '../oauth/relay.js';

// The state is what the box makes (internal/googleauth State): "hj1." + base64url (no padding)
// of the box's origin + "." + a sealed token.
const b64 = (s) => Buffer.from(s, 'utf8').toString('base64url');
const state = (origin, token = 'Zm9vYmFy_-x') => `hj1.${b64(origin)}.${token}`;
const search = (origin, extra = 'code=4%2F0AbC-d_e') => `?${extra}&state=${state(origin)}`;
const CB = '/connections/google/callback';

test('opened directly, with no parameters, it only explains itself', () => {
  for (const s of ['', '?', '#', '?foo=bar', '?prompt=consent']) {
    assert.deepEqual(resolveRelay(s), { kind: 'direct' }, JSON.stringify(s));
  }
});

test('forwards over https to any host, to the callback path only', () => {
  for (const origin of ['https://box.example.com', 'https://hejmo.fritz.box', 'https://203.0.113.9', 'https://box.example.com:8443', 'https://[2001:db8::1]']) {
    const r = resolveRelay(search(origin));
    assert.equal(r.kind, 'forward', origin);
    assert.ok(r.target.startsWith(origin + CB + '?'), r.target);
    assert.equal(new URL(r.target).pathname, CB);
  }
});

test('code and state are passed on exactly as received', () => {
  const rawCode = '4%2F0AbC-d_e%2Bx+y';
  const st = state('https://box.example.com');
  const r = resolveRelay(`?state=${st}&code=${rawCode}`);
  assert.equal(r.kind, 'forward');
  assert.equal(r.target, `https://box.example.com${CB}?state=${st}&code=${rawCode}`);
  const u = new URL(r.target);
  assert.equal(u.searchParams.get('state'), st);
  assert.equal(u.searchParams.get('code'), '4/0AbC-d_e+x y');
});

test('error and scope are forwarded too; anything else is dropped', () => {
  const st = state('https://box.example.com');
  const r = resolveRelay(`?error=access_denied&state=${st}&scope=a%20b&authuser=0&prompt=none&evil=1#frag`);
  assert.equal(r.kind, 'forward');
  assert.equal(r.target, `https://box.example.com${CB}?error=access_denied&state=${st}&scope=a%20b`);
});

test('http is allowed only for private addresses', () => {
  const ok = ['http://127.0.0.1:8099', 'http://127.1.2.3', 'http://[::1]:8099', 'http://10.0.0.5', 'http://10.255.255.255', 'http://172.16.0.1', 'http://172.31.255.255',
    'http://192.168.178.20', 'http://192.168.0.1:8080', 'http://[fd12:3456::1]', 'http://[fc00::1]:8080', 'http://[fdff::1]'];
  for (const origin of ok) {
    const r = resolveRelay(search(origin));
    assert.equal(r.kind, 'forward', origin);
    assert.ok(r.target.startsWith(origin + CB), r.target);
  }
});

test('public http targets are refused in plain words, nothing is forwarded', () => {
  const bad = ['http://hejmo.example.com', 'http://8.8.8.8', 'http://172.15.255.255', 'http://172.32.0.1', 'http://11.0.0.1', 'http://192.169.0.1',
    'http://10.0.0.5.evil.com', 'http://127.0.0.1.evil.com', 'http://evil.local.com', 'http://localhost.evil.com', 'http://notlocal', 'http://[2001:db8::1]',
    'http://[fec0::1]',
    // names are never "private", not even localhost or *.local (a router or office DNS may answer .local)
    'http://localhost', 'http://localhost:8099', 'http://hejmo.local', 'http://my-box.local:8080', 'http://x.localhost',
    // link-local and carrier-grade NAT are not home-network addresses
    'http://[fe80::1]', 'http://[febf::1]', 'http://169.254.1.1', 'http://100.64.0.1', 'http://100.127.255.255',
    // IPv4-mapped IPv6 (the box's relayUsable unmaps these; the relay refuses them, the safe side)
    'http://[::ffff:192.168.1.1]', 'http://[::ffff:c0a8:101]', 'http://[::ffff:8.8.8.8]', 'http://[64:ff9b::808:808]', 'http://[::fc00:1]', 'http://0.0.0.0', 'http://[::]'];
  for (const origin of bad) {
    const r = resolveRelay(search(origin));
    assert.equal(r.kind, 'refused', origin);
    assert.equal(r.target, undefined, 'no forward target for ' + origin);
    assert.ok(r.reason, origin);
  }
});

test('a refusal because of a public http target still shows the target', () => {
  const r = resolveRelay(search('http://hejmo.example.com'));
  assert.equal(r.kind, 'refused');
  assert.equal(r.reason, 'public_http');
  assert.equal(r.shown, `http://hejmo.example.com${CB}`);
});

test('any other path, credentials, query, fragment or scheme in the box address is refused', () => {
  const bad = ['https://box.example.com/other', 'https://box.example.com/connections/google/callback', 'https://box.example.com/..%2Fx',
    'https://user@box.example.com', 'https://user:pw@box.example.com', 'https://box.example.com?x=1', 'https://box.example.com#x',
    'ftp://box.example.com', 'javascript:alert(1)', 'https://box.example.com\\evil.com', 'https://evil.com%40good.example', 'https://a%2fb.example.com', 'https://10.0.0.1%2F.evil.com', 'http://10.0.0.1%2F.evil.com', 'https://box.example.com\tx', 'https://box\t.example.com', 'http://[fe80::1%25eth0]', 'http://[fe80::1%eth0]', 'https://box.example.com:99999', 'https://box.example.com:abc', 'javascript:alert(1)', 'data:text/html,x', 'file:///etc/passwd', '//box.example.com', 'box.example.com', '', 'https://', 'https:///x'];
  for (const origin of bad) {
    const r = resolveRelay(search(origin));
    assert.equal(r.kind, 'refused', JSON.stringify(origin));
    assert.equal(r.target, undefined);
  }
});

test('a state that carries no usable box address is refused', () => {
  const tok = 'abc';
  const bad = ['x', 'abc.def.ghi', `hj2.${b64('https://box.example.com')}.${tok}`, `hj1.${b64('https://box.example.com')}`, `hj1..${tok}`,
    `hj1.${b64('https://box.example.com')}.`, `hj1.${b64('https://box.example.com')}.${tok}.extra`, 'hj1.***.abc', `hj1.${b64('https://box.example.com')}=.${tok}`, 'hj1.%FF.abc'];
  for (const st of bad) {
    const r = resolveRelay(`?code=abc&state=${st}`);
    assert.equal(r.kind, 'refused', st);
    assert.equal(r.reason, 'no_box', st);
  }
  assert.equal(resolveRelay('?code=abc').reason, 'no_box');
  assert.equal(resolveRelay('?code=abc').kind, 'refused');
});

test('isPrivateHost: IP literals only', () => {
  for (const h of ['127.0.0.1', '127.9.9.9', '[::1]', '::1', '10.1.2.3', '172.20.0.1', '192.168.1.1', 'fd00::1', '[fc12::1]']) assert.equal(isPrivateHost(h), true, h);
  for (const h of ['example.com', '8.8.8.8', '172.32.0.1', '192.167.0.1', '2001:db8::1', 'local', 'x.localhost', 'localhost', 'a.local', 'fe80::abcd', '169.254.1.1', '100.64.0.1', '::ffff:192.168.1.1', '::', '0.0.0.0', '10.0.0.1.evil.com']) assert.equal(isPrivateHost(h), false, h);
});

test('the address checked is the address visited: odd spellings are normalised first', () => {
  // WHATWG URL turns hex, octal and integer IPv4 into dotted form; the allow-list sees that form.
  for (const [origin, expected] of [
    ['http://0x7f.1', 'http://127.0.0.1'], ['http://0300.0250.0.1', 'http://192.168.0.1'], ['http://2130706433', 'http://127.0.0.1'],
    ['http://0xC0A80001', 'http://192.168.0.1'], ['HTTP://192.168.1.1', 'http://192.168.1.1'],
  ]) {
    const r = resolveRelay(search(origin));
    assert.equal(r.kind, 'forward', origin);
    assert.equal(r.target.split('?')[0], expected + CB, origin);
  }
  for (const origin of ['http://010.0.0.1', 'http://0x08.8.8.8', 'http://134744072']) assert.equal(resolveRelay(search(origin)).kind, 'refused', origin);
});

test('upper case, default ports, trailing dot and IDN are normalised, never widened', () => {
  const base = (o) => resolveRelay(search(o)).target.split('?')[0];
  assert.equal(base('HTTPS://Box.Example.COM'), 'https://box.example.com' + CB);
  assert.equal(base('https://box.example.com:443'), 'https://box.example.com' + CB);
  assert.equal(base('https://box.example.com.'), 'https://box.example.com.' + CB);
  assert.equal(base('https://bücher.example'), 'https://xn--bcher-kva.example' + CB);
  assert.equal(resolveRelay(search('http://hejmo.local.')).kind, 'refused');
  assert.equal(resolveRelay(search('http://hejmo.example.com.')).kind, 'refused');
  assert.equal(base('http://192.168.1.1.'), 'http://192.168.1.1' + CB);
});

test('duplicate code, error or scope are refused, like a duplicate state', () => {
  const st = state('https://box.example.com');
  for (const q of [`?code=a&code=b&state=${st}`, `?error=a&error=b&state=${st}`, `?code=a&scope=x&scope=y&state=${st}`, `?code=a&state=${st}&state=${st}`]) {
    const r = resolveRelay(q);
    assert.equal(r.kind, 'refused', q);
    assert.equal(r.target, undefined);
  }
});
