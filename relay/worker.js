// Police Scanner key relay (Cloudflare Worker)
// Holds the Groq API key as a secret (GROQ_KEY) and forwards only the two requests the site needs.
// The key never reaches anyone's browser.
const ALLOWED_ORIGINS = ['https://mr-albenberg.github.io'];
const ROUTES = { '/openai/v1/audio/transcriptions': 25e6, '/openai/v1/chat/completions': 200e3 }; // path -> max body bytes
const MODELS = ['whisper-large-v3', 'whisper-large-v3-turbo', 'openai/gpt-oss-120b', 'openai/gpt-oss-20b', 'qwen/qwen3.8-27b'];

function cors(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Expose-Headers': 'retry-after, x-ratelimit-remaining-requests, x-ratelimit-reset-requests',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const okOrigin = ALLOWED_ORIGINS.includes(origin) || /^http:\/\/localhost(:\d+)?$/.test(origin);
    if (!okOrigin) return new Response('Forbidden', { status: 403 });
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(origin) });
    const url = new URL(request.url);
    const max = ROUTES[url.pathname];
    if (request.method !== 'POST' || !max) return new Response('Not found', { status: 404, headers: cors(origin) });
    if (!env.GROQ_KEY) return new Response(JSON.stringify({ error: { message: 'Relay has no GROQ_KEY secret set' } }), { status: 500, headers: cors(origin) });
    const len = +request.headers.get('Content-Length') || 0;
    if (len > max) return new Response('Too large', { status: 413, headers: cors(origin) });

    const body = await request.arrayBuffer();
    if (body.byteLength > max) return new Response('Too large', { status: 413, headers: cors(origin) });
    // only the models this site uses
    if (url.pathname.endsWith('/chat/completions')) {
      try { const j = JSON.parse(new TextDecoder().decode(body)); if (!MODELS.includes(j.model)) return new Response('Model not allowed', { status: 400, headers: cors(origin) }); }
      catch { return new Response('Bad request', { status: 400, headers: cors(origin) }); }
    } else {
      const m = new TextDecoder().decode(body.slice(0, Math.min(body.byteLength, 4096)) ).match(/name="model"\r?\n\r?\n([^\r\n]+)/);
      const tail = new TextDecoder().decode(body.slice(Math.max(0, body.byteLength - 4096)));
      const m2 = m || tail.match(/name="model"\r?\n\r?\n([^\r\n]+)/);
      if (m2 && !MODELS.includes(m2[1].trim())) return new Response('Model not allowed', { status: 400, headers: cors(origin) });
    }
    const upstream = await fetch('https://api.groq.com' + url.pathname, {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + env.GROQ_KEY, 'Content-Type': request.headers.get('Content-Type') || 'application/json' },
      body,
    });
    const headers = new Headers(cors(origin));
    for (const h of ['content-type', 'retry-after', 'x-ratelimit-remaining-requests', 'x-ratelimit-reset-requests']) {
      const v = upstream.headers.get(h); if (v) headers.set(h, v);
    }
    return new Response(upstream.body, { status: upstream.status, headers });
  },
};
