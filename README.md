# hejmo-home.github.io

Static pages for [Hejmo](https://github.com/hejmo-home/hejmo), served by GitHub Pages.

- `/oauth/`: the Google OAuth relay page (ADR 0013 in the main repository). It forwards `code`, `state` and `error` to the callback of your own Hejmo box and stores nothing. **Every Hejmo installation may use it** as an authorised redirect URI of its own Google OAuth client.

The relay page is added with the Google Calendar connection ticket of the main repository and reviewed like code there.

License: AGPL-3.0, like Hejmo.
