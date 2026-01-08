export default {
  async fetch(req, env) {

    /* ============ CONFIG ============ */
    const SECRET = '1234567890';  // SAME AS index.html
    const TARGET_HTML = 'https://original-action-744073.framer.app/'; // <-- CHANGE
    const ALLOWED_ORIGIN = 'https://original-action-744073.framer.app/';
    /* ================================= */

    const url = new URL(req.url);
    const ua = req.headers.get('user-agent') || '';

    // Basic bot filter
    if (!ua || ua.length < 20) {
      return new Response('Blocked', { status: 403 });
    }

    const token = url.searchParams.get('t');
    const emailHash = url.searchParams.get('h');
    if (!token || !emailHash) {
      return new Response('Bad request', { status: 400 });
    }

    let decoded;
    try { decoded = atob(token); }
    catch { return new Response('Bad token', { status: 403 }); }

    const [ts, hash, sig] = decoded.split('|');
    if (!ts || !hash || !sig) {
      return new Response('Malformed token', { status: 403 });
    }

    // Expiry: 30 seconds
    if (Date.now() - Number(ts) > 30000) {
      return new Response('Expired', { status: 403 });
    }

    const expectedSig = await sha256(ts + '|' + hash + '|' + SECRET);
    if (sig !== expectedSig || hash !== emailHash) {
      return new Response('Invalid', { status: 403 });
    }

    // Fetch real HTML
    const resp = await fetch(TARGET_HTML, {
      headers: { 'User-Agent': ua }
    });

    const html = await resp.text();

    return new Response(html, {
      headers: {
        'Content-Type': 'text/html',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': ALLOWED_ORIGIN
      }
    });
  }
};

async function sha256(input) {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(input)
  );
  return [...new Uint8Array(buf)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

