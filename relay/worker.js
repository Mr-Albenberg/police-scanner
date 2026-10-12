// Police Scanner key relay (Cloudflare Worker)
// Holds the Groq API key as a secret (GROQ_KEY) and forwards only the two requests the site needs.
// The key never reaches anyone's browser.
const ALLOWED_ORIGINS = ['https://mr-albenberg.github.io'];
const ROUTES = { '/openai/v1/audio/transcriptions': 25e6, '/openai/v1/chat/completions': 200e3 }; // path -> max body bytes
const MODELS = ['whisper-large-v3', 'whisper-large-v3-turbo', 'openai/gpt-oss-120b', 'openai/gpt-oss-20b', 'qwen/qwen3.8-27b'];

// --- Broadcastify stream minting --------------------------------------------
// Holds one authorized Broadcastify login and returns a fresh signed HLS URL.
// The browser then reads the playlist + segments straight from Broadcastify's
// CDN (which sends Access-Control-Allow-Origin: *), so no audio flows through
// this Worker — only the occasional, tiny mint call does. Secrets: BCFY_USERNAME,
// BCFY_PASSWORD. Lock to the feeds you're authorized to relay.
const BCFY_FEEDS = ['44069'];
let BCFY_COOKIE = ''; // cached on warm isolates; re-login happens on a 401

async function bcfyLogin(env) {
  const body = new URLSearchParams({ username: env.BCFY_USERNAME, password: env.BCFY_PASSWORD, action: 'auth', redirect: '/account/' });
  const r = await fetch('https://www.broadcastify.com/login/', {
    method: 'POST', redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Referer: 'https://www.broadcastify.com/listen/feed/popout.php' },
    body: body.toString(),
  });
  const set = (r.headers.getSetCookie && r.headers.getSetCookie()) || [];
  const jar = {};
  for (const sc of set) { const m = sc.match(/^([^=]+)=([^;]*)/); if (m) jar[m[1]] = m[2]; }
  BCFY_COOKIE = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
  return BCFY_COOKIE;
}

async function bcfyMint(env, feedId) {
  const hit = () => fetch(`https://www.broadcastify.com/listen/session/?feedId=${feedId}`, {
    method: 'POST', headers: { Cookie: BCFY_COOKIE, Referer: 'https://www.broadcastify.com/listen/feed/popout.php', Accept: 'application/json' },
  });
  if (!BCFY_COOKIE) await bcfyLogin(env);
  let r = await hit();
  if (r.status === 401) { await bcfyLogin(env); r = await hit(); } // expired session -> re-login once
  if (!r.ok) throw new Error('mint ' + r.status);
  const j = await r.json();
  if (!j || typeof j.url !== 'string' || !j.url.startsWith('https://')) throw new Error('bad mint response');
  return j.url;
}

function cors(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Expose-Headers': 'retry-after, x-ratelimit-remaining-requests, x-ratelimit-reset-requests',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

// --- Accounts: KV storage, PBKDF2 passwords, AES-GCM key encryption ---------
// KV binding: USERS.  Secret: ENC_KEY (base64 of 32 random bytes).
//   user:<lower>  -> { username, email, salt, hash, keysEnc, createdAt }
//   sess:<token>  -> <lower>   (30-day TTL)
// Passwords are PBKDF2-hashed with a per-user salt. Stored API keys are
// AES-GCM encrypted, so a KV dump alone can't read them. On login the Worker
// returns the decrypted keys to the user's own browser, which uses them to call
// Groq/Gemini directly — no audio proxied through the Worker, so it stays free.
const te = new TextEncoder(), td = new TextDecoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const randToken = (n = 32) => b64(crypto.getRandomValues(new Uint8Array(n))).replace(/[+/=]/g, '');

async function pbkdf2(password, saltBytes) {
  const km = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' }, km, 256);
  return b64(bits);
}
async function aesKey(env) {
  // ENC_KEY is any secret string; derive a stable 32-byte AES key from it via
  // SHA-256 (no base64 parsing, tolerant of how the secret was set). trim() so a
  // stray trailing newline from `wrangler secret put` doesn't change the key.
  const hash = await crypto.subtle.digest('SHA-256', te.encode(String(env.ENC_KEY || '').trim()));
  return crypto.subtle.importKey('raw', hash, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function encrypt(env, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(env), te.encode(JSON.stringify(obj)));
  return b64(iv) + '.' + b64(ct);
}
async function decrypt(env, blob) {
  const [ivb, ctb] = blob.split('.');
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(ivb) }, await aesKey(env), unb64(ctb));
  return JSON.parse(td.decode(pt));
}
const normKeys = (k = {}) => ({
  groq: String(k.groq || ''), gemini: String(k.gemini || ''),
  deepgram: String(k.deepgram || ''), openai: String(k.openai || ''),
});

async function sessionUser(env, request) {
  const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  if (!token) return null;
  const uname = await env.USERS.get('sess:' + token);
  return uname || null;
}

async function handleAuth(request, env, url, origin) {
  const H = { ...cors(origin), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
  const ok = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: H });
  const err = (status, error) => ok({ error }, status);
  if (!env.USERS || !env.ENC_KEY) return err(500, 'accounts are not configured on this relay');

  if (url.pathname === '/auth/signup' && request.method === 'POST') {
    let b; try { b = await request.json(); } catch { return err(400, 'bad request'); }
    const username = String(b.username || '').trim();
    const email = String(b.email || '').trim();
    const password = String(b.password || '');
    const keys = normKeys(b.keys);
    if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) return err(400, 'Username must be 3–32 characters: letters, numbers, . _ -');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return err(400, 'Enter a valid email address');
    if (password.length < 8) return err(400, 'Password must be at least 8 characters');
    if (!keys.groq) return err(400, 'A Groq API key is required');
    if (!keys.gemini) return err(400, 'A Gemini API key is required');
    const ukey = 'user:' + username.toLowerCase();
    if (await env.USERS.get(ukey)) return err(409, 'That username is already taken');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await pbkdf2(password, salt);
    const keysEnc = await encrypt(env, keys);
    await env.USERS.put(ukey, JSON.stringify({ username, email, salt: b64(salt), hash, keysEnc, createdAt: Date.now() }));
    const token = randToken();
    await env.USERS.put('sess:' + token, username.toLowerCase(), { expirationTtl: 60 * 60 * 24 * 30 });
    return ok({ token, username, keys });
  }

  if (url.pathname === '/auth/login' && request.method === 'POST') {
    let b; try { b = await request.json(); } catch { return err(400, 'bad request'); }
    const username = String(b.username || '').trim();
    const password = String(b.password || '');
    const rec = await env.USERS.get('user:' + username.toLowerCase());
    if (!rec) return err(401, 'Wrong username or password');
    const u = JSON.parse(rec);
    const hash = await pbkdf2(password, unb64(u.salt));
    if (hash !== u.hash) return err(401, 'Wrong username or password');
    const token = randToken();
    await env.USERS.put('sess:' + token, username.toLowerCase(), { expirationTtl: 60 * 60 * 24 * 30 });
    return ok({ token, username: u.username, keys: await decrypt(env, u.keysEnc) });
  }

  if (url.pathname === '/auth/me' && request.method === 'GET') {
    const uname = await sessionUser(env, request);
    if (!uname) return err(401, 'not signed in');
    const rec = await env.USERS.get('user:' + uname);
    if (!rec) return err(401, 'not signed in');
    const u = JSON.parse(rec);
    return ok({ username: u.username, email: u.email, keys: await decrypt(env, u.keysEnc) });
  }

  if (url.pathname === '/auth/keys' && request.method === 'POST') {
    const uname = await sessionUser(env, request);
    if (!uname) return err(401, 'not signed in');
    let b; try { b = await request.json(); } catch { return err(400, 'bad request'); }
    const keys = normKeys(b.keys);
    if (!keys.groq) return err(400, 'A Groq API key is required');
    if (!keys.gemini) return err(400, 'A Gemini API key is required');
    const rec = await env.USERS.get('user:' + uname);
    if (!rec) return err(401, 'not signed in');
    const u = JSON.parse(rec);
    u.keysEnc = await encrypt(env, keys);
    await env.USERS.put('user:' + uname, JSON.stringify(u));
    return ok({ ok: true, keys });
  }

  if (url.pathname === '/auth/logout' && request.method === 'POST') {
    const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
    if (token) await env.USERS.delete('sess:' + token);
    return ok({ ok: true });
  }

  return err(404, 'unknown auth route');
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const okOrigin = ALLOWED_ORIGINS.includes(origin) || /^http:\/\/localhost(:\d+)?$/.test(origin);
    if (!okOrigin) return new Response('Forbidden', { status: 403 });
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(origin) });
    const url = new URL(request.url);

    // Account endpoints (signup / login / me / keys / logout).
    if (url.pathname.startsWith('/auth/')) {
      try { return await handleAuth(request, env, url, origin); }
      catch (e) {
        return new Response(JSON.stringify({ error: 'auth error: ' + String((e && e.message) || e) }),
          { status: 500, headers: { ...cors(origin), 'Content-Type': 'application/json' } });
      }
    }

    // Mint a fresh signed stream URL (GET /mint?feedId=44069).
    if (url.pathname === '/mint') {
      const jsonHeaders = { ...cors(origin), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
      const feedId = url.searchParams.get('feedId') || '';
      if (!BCFY_FEEDS.includes(feedId)) return new Response(JSON.stringify({ error: 'feed not allowed' }), { status: 403, headers: jsonHeaders });
      if (!env.BCFY_USERNAME || !env.BCFY_PASSWORD) return new Response(JSON.stringify({ error: 'relay missing BCFY credentials' }), { status: 500, headers: jsonHeaders });
      try {
        const u = await bcfyMint(env, feedId);
        return new Response(JSON.stringify({ url: u }), { headers: jsonHeaders });
      } catch (e) {
        return new Response(JSON.stringify({ error: String((e && e.message) || e) }), { status: 502, headers: jsonHeaders });
      }
    }

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
