export default {
    async fetch(req, env) {
  
      /* ===== CONFIG (EDIT THESE 3 ONLY) ===== */
      const SECRET = '1234567890'; // must match index.html
      const TARGET_HTML = 'https://original-action-744073.framer.app/'; // full URL
      const ALLOWED_ORIGIN = 'https://original-action-744073.framer.app/';
      /* ===================================== */
  
      const url = new URL(req.url);
      const ua = req.headers.get('user-agent') || '';
  
      /* ---- Bot / junk filter ---- */
      if (!ua || ua.length < 25 || /bot|crawl|spider|wget|curl/i.test(ua)) {
        return new Response('Blocked', { status: 403 });
      }
  
      /* ---- Token params ---- */
      const token = url.searchParams.get('t');
      const emailHash = url.searchParams.get('h');
  
      if (!token || !emailHash) {
        return new Response('Bad request', { status: 400 });
      }
  
      let decoded;
      try {
        decoded = atob(token);
      } catch {
        return new Response('Invalid token', { status: 403 });
      }
  
      const parts = decoded.split('|');
      if (parts.length !== 3) {
        return new Response('Malformed token', { status: 403 });
      }
  
      const [ts, hash, sig] = parts;
  
      /* ---- Token expiry (30s) ---- */
      if (Date.now() - Number(ts) > 30000) {
        return new Response('Expired', { status: 403 });
      }
  
      /* ---- Signature check ---- */
      const expectedSig = await sha256(ts + '|' + hash + '|' + SECRET);
      if (sig !== expectedSig || hash !== emailHash) {
        return new Response('Invalid signature', { status: 403 });
      }
  
      /* ---- Fetch protected HTML ---- */
      const upstream = await fetch(TARGET_HTML, {
        headers: { 'User-Agent': ua }
      });
  
      const html = await upstream.text();
  
      return new Response(html, {
        headers: {
          'Content-Type': 'text/html; charset=UTF-8',
          'Cache-Control': 'no-store, no-cache, must-revalidate',
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
  
