# hejmo-home.github.io

Static pages for [Hejmo](https://github.com/hejmo-home/hejmo), served by GitHub Pages.

- `/oauth/`: the Google OAuth relay page (ADR 0013 in the main repository). It forwards `code`, `state`, `error` and `scope` to the callback of your own Hejmo box and stores nothing. The box's address comes from the `state` the box made (`hj1.<base64url origin>.<token>`); only `https://<host>/connections/google/callback`, or `http://` to a private address, is allowed. The check lives in `oauth/relay.js`; run the tests with `npm test`. **Every Hejmo installation may use it** as an authorised redirect URI of its own Google OAuth client.

The relay page is reviewed like code in the main repository.

License: AGPL-3.0, like Hejmo.
