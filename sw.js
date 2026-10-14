// Police Scanner service worker — handles zone push alerts.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

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
    // carry the call location so the page can jump straight to it
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
