// The relay page of the Google connection (ADR 0013, ticket 18 of
// hejmo-home/hejmo). Google sends the browser here after the sign-in, because
// Google only accepts redirect addresses on a public domain. The state Google
// hands back names the Hejmo box the sign-in was started on ("hj1.<box address
// as base64url>.<signed token>"); this page forwards code, state, error and
// scope to /connections/google/callback of that box, and nothing else.
//
// No third-party code, nothing stored, no request of its own. The box does not
// trust this page: it accepts a code only with a state it made itself, and PKCE
// keeps the code useless to anyone but the box.
(function (root) {
  "use strict";

  var CALLBACK = "/connections/google/callback";
  var FORWARDED = ["code", "state", "error", "scope"];

  // decodeOrigin reads the box address out of the state; null if the state has
  // not the shape of one made by a Hejmo box.
  function decodeOrigin(state) {
    var parts = String(state || "").split(".");
    if (parts.length !== 3 || parts[0] !== "hj1" || !parts[1] || !parts[2]) return null;
    if (!/^[A-Za-z0-9_-]+$/.test(parts[1])) return null;
    try {
      var b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
      while (b64.length % 4) b64 += "=";
      var bin = typeof atob === "function" ? atob(b64) : Buffer.from(b64, "base64").toString("binary");
      return decodeURIComponent(Array.prototype.map.call(bin, function (c) {
        return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
      }).join(""));
    } catch (e) {
      return null;
    }
  }

  // isPrivateIP says whether a host is an IP address of a home network:
  // 10/8, 172.16/12, 192.168/16, or an IPv6 unique local address (fc00::/7).
  function isPrivateIP(host) {
    var v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
    if (v4) {
      var o = v4.slice(1).map(Number);
      if (o.some(function (n) { return n > 255; })) return false;
      return o[0] === 10 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168);
    }
    if (host.charAt(0) === "[" && host.charAt(host.length - 1) === "]") {
      var v6 = host.slice(1, -1).toLowerCase();
      return /^f[cd][0-9a-f]{2}:/.test(v6) && /^[0-9a-f:]+$/.test(v6);
    }
    return false;
  }

  // targetFor is the callback address on the box at origin, or null when this
  // page must not go there: over https any host is fine; over http only an IP
  // address of a home network; no other scheme, no user name, no path.
  function targetFor(origin) {
    var u;
    try {
      u = new URL(origin);
    } catch (e) {
      return null;
    }
    if (u.origin !== origin || u.username || u.password || u.search || u.hash || !u.hostname) return null;
    if (u.protocol === "https:") return origin + CALLBACK;
    if (u.protocol === "http:" && isPrivateIP(u.hostname.charAt(0) === "[" ? u.hostname : u.hostname)) return origin + CALLBACK;
    return null;
  }

  // route decides what the page does with the address it was opened with:
  // "forward" (to url), "refused" (the target is not allowed; target says which)
  // or "direct" (opened without a sign-in: explain what the page is for).
  function route(search) {
    var q = new URLSearchParams(search || "");
    var state = q.get("state");
    if (!state || (!q.get("code") && !q.get("error"))) return { action: "direct" };
    var origin = decodeOrigin(state);
    var target = origin === null ? null : targetFor(origin);
    if (target === null) return { action: "refused", target: origin === null ? "" : origin + CALLBACK };
    var out = new URLSearchParams();
    FORWARDED.forEach(function (k) { if (q.has(k)) out.set(k, q.get(k)); });
    return { action: "forward", target: target, url: target + "?" + out.toString() };
  }

  var api = { route: route, targetFor: targetFor, decodeOrigin: decodeOrigin, isPrivateIP: isPrivateIP, CALLBACK: CALLBACK };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
    return;
  }

  // In the browser: the page speaks German to a German browser, else English; it shows the right card and, for a forward, goes.
  root.document.documentElement.lang = /^de\b/i.test(root.navigator.language || "") ? "de" : "en";
  var result = route(root.location.search);
  var card = root.document.querySelector('[data-state="' + result.action + '"]');
  root.document.querySelectorAll("[data-state]").forEach(function (el) { el.hidden = el !== card; });
  root.document.querySelectorAll("[data-target]").forEach(function (el) { el.textContent = result.target || ""; });
  root.document.querySelectorAll("[data-go]").forEach(function (el) { if (result.url) el.setAttribute("href", result.url); });
  if (result.action === "forward") root.location.replace(result.url);
})(typeof window !== "undefined" ? window : this);
