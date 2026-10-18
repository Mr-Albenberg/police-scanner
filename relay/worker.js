// Police Scanner key relay (Cloudflare Worker)
// Holds the Groq API key as a secret (GROQ_KEY) and forwards only the two requests the site needs.
// The key never reaches anyone's browser.
const ALLOWED_ORIGINS = ['https://mr-albenberg.github.io', 'https://jackalbenbergforwebmaster.vercel.app'];
// Vercel preview deploys for this project get rotating subdomains; allow them too.
const ALLOWED_ORIGIN_RE = [/^http:\/\/localhost(:\d+)?$/, /^https:\/\/jackalbenbergforwebmaster[a-z0-9-]*\.vercel\.app$/];
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
    'Access-Control-Allow-Origin': origin || '*',
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
const b64url = (buf) => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = (s) => unb64(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(s.length + ((4 - (s.length % 4)) % 4), '='));
function concatU8(...arrs) { let n = 0; for (const a of arrs) n += a.length; const o = new Uint8Array(n); let i = 0; for (const a of arrs) { o.set(a, i); i += a.length; } return o; }
async function sha256Id(s) { return b64url(await crypto.subtle.digest('SHA-256', te.encode(s))).slice(0, 24); }
// Great-circle distance in metres between two lat/lon points.
function distM(aLat, aLon, bLat, bLon) {
  const R = 6371000, t = Math.PI / 180, dLa = (bLat - aLat) * t, dLo = (bLon - aLon) * t;
  const h = Math.sin(dLa / 2) ** 2 + Math.cos(aLat * t) * Math.cos(bLat * t) * Math.sin(dLo / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

// --- Web Push (VAPID + RFC 8291 aes128gcm) ---------------------------------
// Free browser push notifications. VAPID keypair: public key below (also in the
// client), private key in the VAPID_PRIVATE_JWK secret. No third-party service.
const VAPID_PUBLIC = 'BH9ZOWE2XozHXPfoU2Tnm5yKuz4wRN4ymuK1fAMETfJ640rreOanElDoj78RL2TR_tfdIrSjcoADhzTO8wXtFNw';
const VAPID_SUBJECT = 'mailto:admin@platescan.org';
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
async function vapidJwt(env, endpoint) {
  const seg = (o) => b64url(te.encode(JSON.stringify(o)));
  const data = seg({ typ: 'JWT', alg: 'ES256' }) + '.' + seg({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: VAPID_SUBJECT });
  const key = await crypto.subtle.importKey('jwk', JSON.parse(env.VAPID_PRIVATE_JWK), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, te.encode(data));
  return data + '.' + b64url(sig);
}
async function pushEncrypt(sub, plaintext) {
  const uaPub = unb64url(sub.keys.p256dh), auth = unb64url(sub.keys.auth);
  const as = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', as.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, as.privateKey, 256));
  const ikm = await hkdf(auth, shared, concatU8(te.encode('WebPush: info\0'), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, te.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, te.encode('Content-Encoding: nonce\0'), 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const rec = concatU8(te.encode(plaintext), new Uint8Array([2])); // 0x02 = last record, no padding
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, rec));
  return concatU8(salt, new Uint8Array([0, 0, 0x10, 0x00]), new Uint8Array([asPub.length]), asPub, ct); // rs=4096
}
async function sendPush(env, sub, payload) {
  const body = await pushEncrypt(sub, JSON.stringify(payload));
  const jwt = await vapidJwt(env, sub.endpoint);
  const r = await fetch(sub.endpoint, {
    method: 'POST',
    headers: { Authorization: 'vapid t=' + jwt + ', k=' + VAPID_PUBLIC, 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '600', Urgency: 'high' },
    body,
  });
  return r.status; // 201 ok; 404/410 => subscription gone
}

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

// Send a password-reset code by email via Resend. Needs RESEND_API_KEY and,
// to reach arbitrary recipients, RESET_FROM on a domain verified in Resend.
async function sendResetEmail(env, to, username, code) {
  const from = String(env.RESET_FROM || 'Police Scanner <onboarding@resend.dev>').replace(/^﻿/, '').trim();
  const html = `<div style="font-family:system-ui,-apple-system,sans-serif;background:#0a1824;color:#eaf6fb;padding:26px;border-radius:14px;max-width:440px;margin:auto">
    <div style="color:#8fe9ff;font-weight:800;letter-spacing:.12em;font-size:13px">SLO // POLICE SCANNER</div>
    <p style="color:#9db8c7;margin:10px 0 18px">Password reset for <b style="color:#eaf6fb">${username}</b></p>
    <p style="margin:0 0 10px">Your reset code:</p>
    <div style="font-size:32px;font-weight:800;letter-spacing:8px;color:#8fe9ff;background:#071522;padding:16px;border-radius:12px;text-align:center">${code}</div>
    <p style="color:#9db8c7;font-size:13px;line-height:1.5;margin:18px 0 0">Enter it in the app to set a new password. It expires in 15 minutes. If you didn't request this, you can safely ignore this email.</p>
  </div>`;
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + String(env.RESEND_API_KEY).replace(/^﻿/, '').trim(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ from, to, subject: 'Your Police Scanner reset code: ' + code, html, text: `Police Scanner password reset for ${username}\n\nYour reset code is: ${code}\n\nEnter it in the app to set a new password. It expires in 15 minutes. If you didn't request this, you can ignore this email.` }),
  });
  if (!r.ok) throw new Error('resend ' + r.status + ' ' + (await r.text()).slice(0, 200));
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
    if (username.toLowerCase() !== 'admin' && password.length < 8) return err(400, 'Password must be at least 8 characters');
    if (!keys.groq) return err(400, 'A Groq API key is required');
    if (!keys.gemini) return err(400, 'A Gemini API key is required');
    const ukey = 'user:' + username.toLowerCase();
    if (await env.USERS.get(ukey)) return err(409, 'That username is already taken');
    if (await env.USERS.get('email:' + email.toLowerCase())) return err(409, 'An account already uses that email');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await pbkdf2(password, salt);
    const keysEnc = await encrypt(env, keys);
    await env.USERS.put(ukey, JSON.stringify({ username, email, salt: b64(salt), hash, keysEnc, createdAt: Date.now() }));
    await env.USERS.put('email:' + email.toLowerCase(), username.toLowerCase());
    const token = randToken();
    await env.USERS.put('sess:' + token, username.toLowerCase(), { expirationTtl: 60 * 60 * 24 * 30 });
    return ok({ token, username, keys, avatar: '' });
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
    return ok({ token, username: u.username, keys: await decrypt(env, u.keysEnc), avatar: u.avatar || '' });
  }

  if (url.pathname === '/auth/me' && request.method === 'GET') {
    const uname = await sessionUser(env, request);
    if (!uname) return err(401, 'not signed in');
    const rec = await env.USERS.get('user:' + uname);
    if (!rec) return err(401, 'not signed in');
    const u = JSON.parse(rec);
    return ok({ username: u.username, email: u.email, keys: await decrypt(env, u.keysEnc), avatar: u.avatar || '' });
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

  if (url.pathname === '/auth/profile' && request.method === 'POST') {
    const uname = await sessionUser(env, request);
    if (!uname) return err(401, 'not signed in');
    let b; try { b = await request.json(); } catch { return err(400, 'bad request'); }
    const rec = await env.USERS.get('user:' + uname);
    if (!rec) return err(401, 'not signed in');
    const u = JSON.parse(rec);
    if ('avatar' in b) {
      const a = String(b.avatar || '');
      if (a && !/^data:image\/(png|jpeg|jpg|webp);base64,/.test(a)) return err(400, 'Image must be a PNG, JPEG or WebP');
      if (a.length > 200000) return err(400, 'Image is too large — pick a smaller one');
      u.avatar = a;
    }
    await env.USERS.put('user:' + uname, JSON.stringify(u));
    return ok({ ok: true, avatar: u.avatar || '' });
  }

  if (url.pathname === '/auth/username' && request.method === 'POST') {
    const uname = await sessionUser(env, request);
    if (!uname) return err(401, 'not signed in');
    let b; try { b = await request.json(); } catch { return err(400, 'bad request'); }
    const newName = String(b.username || '').trim();
    const password = String(b.password || '');
    if (!/^[A-Za-z0-9_.-]{3,32}$/.test(newName)) return err(400, 'Username must be 3–32 characters: letters, numbers, . _ -');
    const lowNew = newName.toLowerCase();
    const rec = await env.USERS.get('user:' + uname);
    if (!rec) return err(401, 'not signed in');
    const u = JSON.parse(rec);
    if ((await pbkdf2(password, unb64(u.salt))) !== u.hash) return err(403, 'Password is wrong');
    if (lowNew !== uname && await env.USERS.get('user:' + lowNew)) return err(409, 'That username is taken');
    u.username = newName;
    await env.USERS.put('user:' + lowNew, JSON.stringify(u));
    if (lowNew !== uname) {
      await env.USERS.delete('user:' + uname);
      if (u.email) await env.USERS.put('email:' + String(u.email).toLowerCase(), lowNew);
      const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
      if (token) await env.USERS.put('sess:' + token, lowNew, { expirationTtl: 60 * 60 * 24 * 30 });
      const h = await env.USERS.get('host:' + uname);
      if (h) { await env.USERS.put('host:' + lowNew, h, { expirationTtl: 60 }); await env.USERS.delete('host:' + uname); }
    }
    return ok({ username: newName });
  }

  if (url.pathname === '/auth/password' && request.method === 'POST') {
    const uname = await sessionUser(env, request);
    if (!uname) return err(401, 'not signed in');
    let b; try { b = await request.json(); } catch { return err(400, 'bad request'); }
    const current = String(b.current || ''), next = String(b.next || '');
    if (uname !== 'admin' && next.length < 8) return err(400, 'New password must be at least 8 characters');
    const rec = await env.USERS.get('user:' + uname);
    if (!rec) return err(401, 'not signed in');
    const u = JSON.parse(rec);
    if ((await pbkdf2(current, unb64(u.salt))) !== u.hash) return err(403, 'Current password is wrong');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    u.salt = b64(salt); u.hash = await pbkdf2(next, salt);
    await env.USERS.put('user:' + uname, JSON.stringify(u));
    return ok({ ok: true });
  }

  // Resolve an email or username to the stored (lowercase) username key.
  async function resolveAccount(input) {
    const s = String(input || '').trim().toLowerCase();
    if (!s) return null;
    if (s.includes('@')) return (await env.USERS.get('email:' + s)) || null;
    return (await env.USERS.get('user:' + s)) ? s : null;
  }

  if (url.pathname === '/auth/forgot' && request.method === 'POST') {
    return err(503, 'Password reset is disabled right now.'); // temporarily off
    if (!env.RESEND_API_KEY) return err(503, 'Password-reset email is not set up on this relay yet.');
    let b; try { b = await request.json(); } catch { return err(400, 'bad request'); }
    // Always respond the same way so the form can't probe which emails have accounts.
    const generic = ok({ ok: true });
    const uname = await resolveAccount(b.account);
    if (!uname) return generic;
    const rec = await env.USERS.get('user:' + uname);
    if (!rec) return generic;
    const u = JSON.parse(rec);
    const existing = await env.USERS.get('reset:' + uname);
    if (existing) { try { if (Date.now() - JSON.parse(existing).at < 60000) return generic; } catch {} } // 60s cooldown
    const code = String(Math.floor(100000 + Math.random() * 900000));
    await env.USERS.put('reset:' + uname, JSON.stringify({ code, at: Date.now(), tries: 0 }), { expirationTtl: 900 });
    try { await sendResetEmail(env, u.email, u.username, code); } catch {}
    return generic;
  }

  if (url.pathname === '/auth/reset' && request.method === 'POST') {
    return err(503, 'Password reset is disabled right now.'); // temporarily off
    let b; try { b = await request.json(); } catch { return err(400, 'bad request'); }
    const uname = await resolveAccount(b.account);
    const code = String(b.code || '').trim();
    const next = String(b.password || '');
    const badCode = () => err(400, 'Wrong code, or it has expired. Request a new one.');
    if (!uname) return badCode();
    const recRaw = await env.USERS.get('reset:' + uname);
    if (!recRaw) return badCode();
    let rst; try { rst = JSON.parse(recRaw); } catch { return badCode(); }
    if (rst.tries >= 5) { await env.USERS.delete('reset:' + uname); return err(429, 'Too many attempts. Request a new code.'); }
    if (code !== rst.code) { rst.tries++; await env.USERS.put('reset:' + uname, JSON.stringify(rst), { expirationTtl: 900 }); return err(400, 'Wrong code. Check your email and try again.'); }
    if (uname !== 'admin' && next.length < 8) return err(400, 'New password must be at least 8 characters');
    const rec = await env.USERS.get('user:' + uname);
    if (!rec) return badCode();
    const u = JSON.parse(rec);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    u.salt = b64(salt); u.hash = await pbkdf2(next, salt);
    await env.USERS.put('user:' + uname, JSON.stringify(u));
    await env.USERS.delete('reset:' + uname);
    return ok({ ok: true });
  }

  if (url.pathname === '/auth/logout' && request.method === 'POST') {
    const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
    if (token) await env.USERS.delete('sess:' + token);
    return ok({ ok: true });
  }

  return err(404, 'unknown auth route');
}

// --- Zone push alerts -------------------------------------------------------
//  /push/subscribe   POST {subscription, zone:{lat,lon,r}}  save/update a device
//  /push/unsubscribe POST {endpoint}                        remove a device
//  /push/test        POST {}                                send a test to my devices
//  /alert/call       POST {lat,lon,text,title}              a running device reports
//        a located call; the relay pushes every subscriber whose zone contains it.
//  KV:  psub:<user>:<id> -> {endpoint, keys, zone, at}
//       aseen:<callKey>  -> 1   (300s, global de-dup across reporters)
//       prate:<subName>  -> ts  (per-device throttle, 300s)
async function handlePush(request, env, url, origin) {
  const H = { ...cors(origin), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
  const ok = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: H });
  const err = (s, e) => ok({ error: e }, s);
  if (!env.USERS || !env.VAPID_PRIVATE_JWK) return err(503, 'Push alerts are not set up on this relay yet.');
  const uname = await sessionUser(env, request);
  if (!uname) return err(401, 'not signed in');
  if (request.method !== 'POST') return err(405, 'method');
  let b; try { b = await request.json(); } catch { return err(400, 'bad request'); }

  if (url.pathname === '/push/subscribe') {
    const sub = b.subscription || {};
    if (!sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) return err(400, 'bad subscription');
    const z = b.zone || {};
    const lat = +z.lat, lon = +z.lon, r = +z.r;
    if (!isFinite(lat) || !isFinite(lon) || !isFinite(r)) return err(400, 'a zone is required — set your spot first');
    const id = await sha256Id(sub.endpoint);
    await env.USERS.put('psub:' + uname + ':' + id, JSON.stringify({ endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth }, zone: { lat, lon, r }, at: Date.now() }));
    return ok({ ok: true });
  }

  if (url.pathname === '/push/unsubscribe') {
    if (!b.endpoint) return err(400, 'endpoint required');
    await env.USERS.delete('psub:' + uname + ':' + (await sha256Id(b.endpoint)));
    return ok({ ok: true });
  }

  if (url.pathname === '/push/test') {
    const list = await env.USERS.list({ prefix: 'psub:' + uname + ':' });
    let sent = 0;
    for (const k of list.keys) {
      const raw = await env.USERS.get(k.name); if (!raw) continue;
      const sub = JSON.parse(raw);
      try { const st = await sendPush(env, sub, { title: 'Police Scanner', body: 'Test alert — zone notifications are on.', tag: 'test' }); if (st === 201 || st === 200) sent++; else if (st === 404 || st === 410) await env.USERS.delete(k.name); } catch {}
    }
    return ok({ ok: true, sent });
  }

  if (url.pathname === '/alert/call') {
    const lat = +b.lat, lon = +b.lon;
    if (!isFinite(lat) || !isFinite(lon)) return err(400, 'lat/lon required');
    const text = String(b.text || '').slice(0, 300);
    const title = String(b.title || 'Call in your zone').slice(0, 80);
    const href = String(b.href || origin).slice(0, 300); // app URL to open on click
    const callKey = await sha256Id(lat.toFixed(3) + ',' + lon.toFixed(3) + '|' + text.slice(0, 40));
    if (await env.USERS.get('aseen:' + callKey)) return ok({ ok: true, dedup: true });
    await env.USERS.put('aseen:' + callKey, '1', { expirationTtl: 300 });
    const list = await env.USERS.list({ prefix: 'psub:' });
    const now = Date.now();
    let sent = 0;
    await Promise.all(list.keys.map(async (k) => {
      const raw = await env.USERS.get(k.name); if (!raw) return;
      const sub = JSON.parse(raw);
      if (!sub.zone || distM(lat, lon, sub.zone.lat, sub.zone.lon) > sub.zone.r) return;
      const last = await env.USERS.get('prate:' + k.name);
      if (last && now - (+last) < 12000) return; // at most one push / 12s / device
      try {
        const st = await sendPush(env, sub, { title, body: text || 'A call just dropped in your zone.', tag: callKey, url: href, call: { lat, lon } });
        if (st === 201 || st === 200) { sent++; await env.USERS.put('prate:' + k.name, String(now), { expirationTtl: 300 }); }
        else if (st === 404 || st === 410) await env.USERS.delete(k.name);
      } catch {}
    }));
    return ok({ ok: true, sent });
  }

  return err(404, 'unknown push route');
}

export default {
  async fetch(request, env) {
    // Accept any origin so the app works from any URL, device or installed PWA
    // (that's what caused "failed to fetch" on sign-in from other URLs). Auth
    // needs real credentials and uses bearer tokens, not cookies, so echoing the
    // request's origin back is safe here.
    const origin = request.headers.get('Origin') || '';
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

    // Zone push-alert endpoints (subscribe / unsubscribe / test / alert fan-out).
    if (url.pathname.startsWith('/push/') || url.pathname === '/alert/call') {
      try { return await handlePush(request, env, url, origin); }
      catch (e) {
        return new Response(JSON.stringify({ error: 'push error: ' + String((e && e.message) || e) }),
          { status: 500, headers: { ...cors(origin), 'Content-Type': 'application/json' } });
      }
    }

    // (Call/event sync is peer-to-peer now; the KV feed was removed.)

    // --- Device coordination for same-account P2P (WebRTC via PeerJS) ---------
    //  /host  POST {peerId}  register this device as the account's host (60s TTL)
    //         POST {stop:1}  stop hosting
    //         GET            get the account's current host peer id (or null)
    //  /ice   GET            ICE servers (Cloudflare STUN always; TURN if the
    //                        TURN_TOKEN_ID + TURN_API_TOKEN secrets are set)
    if (url.pathname === '/host' || url.pathname === '/ice') {
      const H = { ...cors(origin), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
      const uname = await sessionUser(env, request);
      if (!uname) return new Response(JSON.stringify({ error: 'not signed in' }), { status: 401, headers: H });

      if (url.pathname === '/host') {
        if (request.method === 'GET') {
          const rec = await env.USERS.get('host:' + uname);
          const h = rec ? JSON.parse(rec) : null;
          return new Response(JSON.stringify({ peerId: h ? h.peerId : null }), { headers: H });
        }
        if (request.method === 'POST') {
          let b; try { b = await request.json(); } catch { b = {}; }
          if (b.stop) { await env.USERS.delete('host:' + uname); return new Response(JSON.stringify({ ok: true }), { headers: H }); }
          const peerId = String(b.peerId || '');
          if (!peerId) return new Response(JSON.stringify({ error: 'peerId required' }), { status: 400, headers: H });
          await env.USERS.put('host:' + uname, JSON.stringify({ peerId, at: Date.now() }), { expirationTtl: 150 });
          return new Response(JSON.stringify({ ok: true }), { headers: H });
        }
        return new Response(JSON.stringify({ error: 'method' }), { status: 405, headers: H });
      }

      // /ice
      const iceServers = [{ urls: 'stun:stun.cloudflare.com:3478' }];
      const turnId = String(env.TURN_TOKEN_ID || '').trim(), turnKey = String(env.TURN_API_TOKEN || '').trim();
      if (turnId && turnKey) {
        try {
          const r = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${turnId}/credentials/generate`, {
            method: 'POST', headers: { Authorization: 'Bearer ' + turnKey, 'Content-Type': 'application/json' },
            body: JSON.stringify({ ttl: 86400 }),
          });
          if (r.ok) { const j = await r.json(); if (j.iceServers) iceServers.push(j.iceServers); }
        } catch { /* fall back to STUN only */ }
      }
      return new Response(JSON.stringify({ iceServers }), { headers: H });
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
