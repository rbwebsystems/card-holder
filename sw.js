// Service worker: əvvəlcə şəbəkə (həmişə ən son versiya), internet yoxdursa — keş.
// Fayllar dəyişəndə VERSION-u və app.js-dəki APP_VERSION-u artır.
const VERSION = 'v9';
const CACHE = `card-holder-${VERSION}`;
const ASSETS = [
  './',
  './index.html',
  './styles.css',
  './app.js',
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/apple-touch-icon.png'
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(ASSETS.map((u) => new Request(u, { cache: 'reload' }))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

const fromCache = async (req) =>
  (await caches.match(req, { ignoreSearch: true })) ||
  (req.mode === 'navigate' ? caches.match('./index.html') : undefined);

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  if (new URL(req.url).origin !== location.origin) return;

  e.respondWith((async () => {
    // HTTP keşindən yan keçib serverdən yoxla (ETag ilə — dəyişməyibsə sürətlidir)
    const fresh = req.mode === 'navigate'
      ? new Request(req.url, { cache: 'no-cache', credentials: 'same-origin' })
      : new Request(req, { cache: 'no-cache' });
    const network = fetch(fresh).then(async (res) => {
      if (res.ok) (await caches.open(CACHE)).put(req, res.clone());
      return res;
    });
    // Zəif internetdə 4 saniyədən sonra keşdən aç
    const timeout = new Promise((resolve) => setTimeout(async () => resolve(await fromCache(req)), 4000));
    try {
      return (await Promise.race([network, timeout])) || (await network);
    } catch {
      return (await fromCache(req)) || Response.error();
    }
  })());
});
