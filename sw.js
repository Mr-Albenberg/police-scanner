// Police Scanner service worker — offline app shell + zone push alerts.
// Bump CACHE to force old caches out on the next visit after a shape change.
const CACHE = 'ps-shell-v1';
const SHELL = [
  './', './index.html', './logo.png', './favicon-32.png', './manifest.webmanifest', './streets.json',
  'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css',
  'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js',
];

self.addEventListener('install', (e) => {
  // Precache each file on its own so one blocked URL doesn't abort the rest.
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    await Promise.all(SHELL.map((u) => c.add(u).catch(() => {})));
    self.skipWaiting();
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)));
    await self.clients.claim();
  })());
});

// Only touch our own files + the Leaflet CDN. The relay API, map tiles and the
// audio stream are always left to the network (never cached/stale).
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  let url; try { url = new URL(req.url); } catch { return; }
  const sameOrigin = url.origin === self.location.origin;
  const isLeaflet = url.href.indexOf('cdnjs.cloudflare.com/ajax/libs/leaflet') >= 0;
  if (!sameOrigin && !isLeaflet) return;

  // Navigations (the app HTML): network-first so a deploy is picked up when
  // online; fall back to the cached shell when offline.
  if (req.mode === 'navigate') {
    e.respondWith((async () => {
      try {
        const net = await fetch(req);
        caches.open(CACHE).then((c) => c.put('./', net.clone())).catch(() => {});
        return net;
      } catch {
        return (await caches.match('./')) || (await caches.match('./index.html')) || Response.error();
      }
    })());
    return;
  }

  // Static assets (logo, streets.json, Leaflet): cache-first, refreshed in the
  // background so the next load has the newest copy.
  e.respondWith((async () => {
    const cached = await caches.match(req);
    const net = fetch(req).then((r) => {
      if (r && r.ok) caches.open(CACHE).then((c) => c.put(req, r.clone())).catch(() => {});
      return r;
    }).catch(() => null);
    return cached || (await net) || Response.error();
  })());
});

self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = {}; }
  const title = d.title || 'Police Scanner';
  const opts = {
    body: d.body || 'A call just dropped in your zone.',
    tag: d.tag || 'zone-alert',
    renotify: true,
    icon: './logo.png',
    badge: './favicon-32.png',
    vibrate: [120, 60, 120],
    data: { url: d.url || './', call: d.call || null }, // call = {lat, lon} to open on click
  };
  e.waitUntil(self.registration.showNotification(title, opts));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const data = e.notification.data || {};
  let target = data.url || './';
  if (data.call && typeof data.call.lat === 'number') {
    target += (target.indexOf('?') >= 0 ? '&' : '?') + 'call=' + data.call.lat + ',' + data.call.lon;
  }
  e.waitUntil((async () => {
    const cl = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of cl) {
      if ('focus' in c) {
        await c.focus();
        if (data.call) { try { c.postMessage({ type: 'focusCall', call: data.call }); } catch {} }
        return;
      }
    }
    if (self.clients.openWindow) return self.clients.openWindow(target);
  })());
});
