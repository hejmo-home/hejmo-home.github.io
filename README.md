# hejmo-home.github.io

Static pages for [Hejmo](https://github.com/hejmo-home/hejmo), served by GitHub Pages. This repository runs no server of its own.

- `/oauth/`: the Google OAuth relay page (ADR 0013 in the main repository). After a Google sign-in, Google sends the browser here, because Google only accepts redirect addresses on a public domain. The page forwards `code`, `state`, `error` and `scope` to `/connections/google/callback` of the Hejmo box named in the `state`, and stores nothing. **Every Hejmo installation may use it** as an authorised redirect URI of its own Google OAuth client.

## What the relay page does and does not do

- It goes back to `https://<any host>/connections/google/callback`, and over `http://` only to an IP address of a home network (10/8, 172.16/12, 192.168/16, IPv6 unique local). Any other scheme, host, path, user name or query is refused in plain words; nothing is passed on.
- It passes on nothing but `code`, `state`, `error` and `scope`.
- It has no third-party code, loads nothing from other sites (a strict `Content-Security-Policy`), sends no referrer and sets no cookie or storage.
- It does not have to be trusted: the box accepts a code only with a `state` it made itself (signed, valid 15 minutes, used once), and PKCE keeps the code useless to anyone else.

## Changing it

Changes need the same review as the main repository. `node --test test/` checks where the page may go and that it stays self-contained.

License: AGPL-3.0, like Hejmo.
