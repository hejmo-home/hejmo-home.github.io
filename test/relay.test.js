"use strict";
// Tests of the relay page (ADR 0013, ticket 18 of hejmo-home/hejmo): where it
// may send the browser, and what it passes on. Run: node --test test/

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const relay = require("../oauth/relay.js");

// The state a Hejmo box makes: hj1.<box address, base64url>.<signed token>.
function stateFor(origin) {
  return "hj1." + Buffer.from(origin, "utf8").toString("base64url") + ".dG9rZW4";
}

function go(origin, extra) {
  const q = new URLSearchParams(Object.assign({ code: "4/0AVMB", state: stateFor(origin), scope: "https://www.googleapis.com/auth/calendar" }, extra || {}));
  return relay.route("?" + q.toString());
}

test("forwards to https://<any host>/connections/google/callback", () => {
  for (const origin of ["https://hejmo.fritz.box", "https://192.168.178.20", "https://hejmo.example.com:8443", "https://[fd00::1]", "https://box.local"]) {
    const r = go(origin);
    assert.equal(r.action, "forward", origin);
    assert.equal(r.target, origin + "/connections/google/callback");
    const u = new URL(r.url);
    assert.equal(u.origin, origin);
    assert.equal(u.pathname, "/connections/google/callback");
    assert.equal(u.searchParams.get("code"), "4/0AVMB");
    assert.equal(u.searchParams.get("state"), stateFor(origin));
    assert.equal(u.searchParams.get("scope"), "https://www.googleapis.com/auth/calendar");
  }
});

test("forwards over http only to an IP address of a home network", () => {
  for (const origin of ["http://192.168.178.20", "http://10.0.0.5:8080", "http://172.16.0.1", "http://172.31.255.254", "http://[fd12:3456::7]"]) {
    assert.equal(go(origin).action, "forward", origin);
  }
  for (const origin of [
    "http://hejmo.local", "http://hejmo.example.com", "http://8.8.8.8", "http://172.32.0.1", "http://172.15.0.1", "http://192.169.1.1",
    "http://127.0.0.1", "http://169.254.1.1", "http://[2001:db8::1]", "http://300.1.1.1", "http://192.168.1.1.evil.example",
  ]) {
    const r = go(origin);
    assert.equal(r.action, "refused", origin);
    assert.equal(r.url, undefined, "nothing is passed on to " + origin);
  }
});

test("refuses every other path, scheme and address with more than an origin", () => {
  for (const origin of [
    "https://hejmo.fritz.box/other", "https://hejmo.fritz.box/connections/google/callback", "https://hejmo.fritz.box/?x=1", "https://hejmo.fritz.box#x",
    "https://user@hejmo.fritz.box", "https://user:pw@hejmo.fritz.box", "javascript:alert(1)", "data:text/html,x", "ftp://192.168.1.1", "file:///etc/passwd",
    "//evil.example", "evil.example", "", "https://", "https:///x",
  ]) {
    assert.equal(go(origin).action, "refused", JSON.stringify(origin));
  }
});

test("a state that is not one of a Hejmo box is refused", () => {
  for (const state of ["hj1.!!.tok", "hj2." + Buffer.from("https://a.example").toString("base64url") + ".tok", "hj1." + Buffer.from("https://a.example").toString("base64url"), "plain", "hj1..tok"]) {
    assert.equal(relay.route("?code=c&state=" + encodeURIComponent(state)).action, "refused", state);
  }
});

test("passes on an error such as access_denied, and nothing else", () => {
  const origin = "https://hejmo.fritz.box";
  const r = relay.route("?" + new URLSearchParams({ error: "access_denied", state: stateFor(origin), authuser: "0", prompt: "consent", hd: "x", code_challenge: "leak" }).toString());
  assert.equal(r.action, "forward");
  const u = new URL(r.url);
  assert.deepEqual([...u.searchParams.keys()].sort(), ["error", "state"]);
  assert.equal(u.searchParams.get("error"), "access_denied");
});

test("opened without a sign-in it only explains itself", () => {
  for (const search of ["", "?", "?state=" + stateFor("https://a.example"), "?code=c", "?foo=bar"]) {
    assert.equal(relay.route(search).action, "direct", search);
  }
});

test("a decoded origin keeps unusual characters out of the target", () => {
  const r = go("https://hejmo.fritz.box\r\nLocation: https://evil.example");
  assert.equal(r.action, "refused");
});

test("the page is self-contained: no third-party code, a strict policy, no referrer", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "oauth", "index.html"), "utf8");
  assert.match(html, /Content-Security-Policy[^>]*default-src 'none'/);
  assert.match(html, /name="referrer" content="no-referrer"/);
  for (const m of html.matchAll(/(?:src|href)="([^"]*)"/g)) {
    assert.ok(!/^(https?:)?\/\//.test(m[1]) || m[1].startsWith("https://github.com/hejmo-home/hejmo"), "loads or links " + m[1]);
  }
  for (const m of html.matchAll(/<(?:script|link)\b[^>]*>/g)) {
    assert.ok(!/(?:src|href)="(?:https?:)?\/\//.test(m[0]), "loads from outside: " + m[0]);
  }
  const css = fs.readFileSync(path.join(__dirname, "..", "oauth", "relay.css"), "utf8");
  assert.ok(!/url\(|@import/.test(css), "the stylesheet loads something");
});
