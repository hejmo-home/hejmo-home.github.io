// Glue of the relay page: reads this page's address, shows what resolveRelay says and,
// if allowed, goes on to the box. Stores nothing (no cookies, no storage) and sends nothing.
import { resolveRelay } from './relay.js';

const show = (id) => { document.getElementById(id).hidden = false; };
const r = resolveRelay(location.search);

if (r.kind === 'forward') {
  document.getElementById('forward-target').textContent = r.target.split('?')[0];
  document.getElementById('forward-button').href = r.target;
  show('forward');
  location.replace(r.target);
} else if (r.kind === 'refused') {
  if (r.reason === 'public_http') {
    document.getElementById('refused-target').textContent = r.shown;
    show('refused-http');
  } else {
    show('refused-other');
  }
} else {
  show('direct');
}
