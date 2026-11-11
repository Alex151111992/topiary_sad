import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';

const VK_ORIGIN = 'https://id.vk.ru';
const CALLBACK_PATHS = new Set(['/api/auth/vk/callback', '/auth/vkid']);
const ATTEMPT_SECONDS = 600;
const SESSION_SECONDS = 3600;
const STORE_LIMIT = 2048;

const assets = new Map([
  ['/', ['index.html', 'text/html']],
  ['/index.html', ['index.html', 'text/html']],
  ['/style.css', ['style.css', 'text/css']],
  ['/script.js', ['script.js', 'text/javascript']],
  ['/auth.js', ['auth.js', 'text/javascript']],
]);

function readVkConfig(clientId, redirectUri) {
  if (!clientId && !redirectUri) return null;
  if (!/^[1-9]\d*$/.test(clientId ?? '') || !redirectUri) {
    throw new Error('Укажите VK_CLIENT_ID и VK_REDIRECT_URI.');
  }

  const callback = new URL(redirectUri);
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(callback.hostname);
  const validScheme = callback.protocol === 'https:' || (callback.protocol === 'http:' && loopback);
  if (!validScheme || !CALLBACK_PATHS.has(callback.pathname) || callback.username || callback.password || /[?#]/.test(redirectUri)) {
    throw new Error('VK_REDIRECT_URI должен вести на /auth/vkid или /api/auth/vk/callback по HTTPS. HTTP допустим только для локального адреса.');
  }
  return {
    clientId,
    redirectUri,
    callbackPath: callback.pathname,
    origin: callback.origin,
    host: callback.host,
    secure: callback.protocol === 'https:',
  };
}

function randomId() {
  return randomBytes(32).toString('base64url');
}

function readCookie(request, name) {
  const entry = request.headers.cookie?.split(';').map(cookie => cookie.trim())
    .find(cookie => cookie.startsWith(`${name}=`));
  const value = entry?.slice(name.length + 1);
  return value && /^[A-Za-z0-9_-]{43}$/.test(value) ? value : undefined;
}

function writeCookie(response, name, id, seconds, secure) {
  response.setHeader('Set-Cookie', `${name}=${id}; Path=/; Max-Age=${seconds}; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`);
}

function redirect(response, location) {
  response.writeHead(303, { Location: location }).end();
}

function singleParam(params, key) {
  const values = params.getAll(key);
  return values.length === 1 ? values[0] : null;
}

export function createSiteServer({ clientId, redirectUri } = {}, { fetchVk = fetch, now = Date.now } = {}) {
  const vk = readVkConfig(clientId, redirectUri);
  const prefix = vk?.secure ? '__Host-' : '';
  const attemptCookie = `${prefix}topiary_vk_attempt`;
  const sessionCookie = `${prefix}topiary_session`;
  const attempts = new Map();
  const sessions = new Map();

  function pruneExpired() {
    const time = now();
    for (const store of [attempts, sessions]) {
      for (const [key, item] of store) {
        if (item.expiresAt <= time) store.delete(key);
      }
    }
  }

  function startVk(request, response) {
    if (!vk) return redirect(response, '/?login=unconfigured#login');

    pruneExpired();
    attempts.delete(readCookie(request, attemptCookie));
    if (attempts.size >= STORE_LIMIT) return redirect(response, '/?login=error#login');

    const attemptId = randomId();
    const state = randomId();
    const verifier = randomId();
    attempts.set(attemptId, { state, verifier, expiresAt: now() + ATTEMPT_SECONDS * 1000 });
    writeCookie(response, attemptCookie, attemptId, ATTEMPT_SECONDS, vk.secure);

    const authorize = new URL('/authorize', VK_ORIGIN);
    authorize.search = new URLSearchParams({
      response_type: 'code',
      client_id: vk.clientId,
      redirect_uri: vk.redirectUri,
      state,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 's256',
    });
    redirect(response, authorize.href);
  }

  async function finishVk(request, response, params) {
    const failed = '/?login=error#login';
    if (!vk) return redirect(response, '/?login=unconfigured#login');

    pruneExpired();
    const attemptId = readCookie(request, attemptCookie);
    const attempt = attempts.get(attemptId);
    if (!attempt || singleParam(params, 'state') !== attempt.state) return redirect(response, failed);
    attempts.delete(attemptId);

    if (params.has('error')) {
      const cancelled = singleParam(params, 'error') === 'access_denied' && !params.has('code');
      return redirect(response, cancelled ? '/?login=cancelled#login' : failed);
    }

    const code = singleParam(params, 'code');
    const deviceId = singleParam(params, 'device_id');
    if (!code || code.length > 4096 || !deviceId || deviceId.length > 512) return redirect(response, failed);

    try {
      const exchangeUrl = new URL('/oauth2/auth', VK_ORIGIN);
      exchangeUrl.search = new URLSearchParams({
        grant_type: 'authorization_code',
        redirect_uri: vk.redirectUri,
        client_id: vk.clientId,
        code_verifier: attempt.verifier,
        state: attempt.state,
        device_id: deviceId,
      });
      const exchange = await fetchVk(exchangeUrl, {
        method: 'POST',
        body: new URLSearchParams({ code }),
        redirect: 'error',
        signal: AbortSignal.timeout(8000),
      });
      if (!exchange.ok) return redirect(response, failed);

      const token = await exchange.json();
      if (!token || token.error || token.state !== attempt.state ||
          typeof token.access_token !== 'string' || !token.access_token.trim() ||
          !Number.isSafeInteger(token.user_id) || token.user_id <= 0) {
        return redirect(response, failed);
      }

      pruneExpired();
      sessions.delete(readCookie(request, sessionCookie));
      if (sessions.size >= STORE_LIMIT) return redirect(response, failed);

      const sessionId = randomId();
      sessions.set(sessionId, { userId: token.user_id, expiresAt: now() + SESSION_SECONDS * 1000 });
      writeCookie(response, sessionCookie, sessionId, SESSION_SECONDS, vk.secure);
      return redirect(response, '/#login');
    } catch {
      return redirect(response, failed);
    }
  }

  const server = createServer(async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Content-Type-Options', 'nosniff');

    if (request.method !== 'GET') return response.writeHead(405, { Allow: 'GET' }).end();

    try {
      const url = new URL(request.url, 'http://site.invalid');
      if (url.origin !== 'http://site.invalid') return response.writeHead(400).end();

      if (vk && request.headers.host?.toLowerCase() !== vk.host) {
        const canonical = new URL(vk.origin);
        canonical.pathname = url.pathname;
        canonical.search = url.search;
        return redirect(response, canonical.href);
      }

      if (CALLBACK_PATHS.has(url.pathname)) {
        if (vk && url.pathname !== vk.callbackPath) return response.writeHead(404).end();
        return await finishVk(request, response, url.searchParams);
      }

      switch (url.pathname) {
        case '/api/auth/session': {
          const session = sessions.get(readCookie(request, sessionCookie));
          const authenticated = Boolean(session && session.expiresAt > now());
          response.writeHead(200, { 'Content-Type': 'application/json' });
          return response.end(JSON.stringify({ authenticated, providers: vk ? ['vk'] : [] }));
        }
        case '/api/auth/vk/start':
          return startVk(request, response);
        default: {
          const asset = assets.get(url.pathname);
          if (!asset) return response.writeHead(404).end();
          const [filename, type] = asset;
          const body = readFileSync(new URL(filename, import.meta.url));
          return response.writeHead(200, { 'Content-Type': `${type}; charset=utf-8` }).end(body);
        }
      }
    } catch {
      return response.writeHead(500).end();
    }
  });

  const cleanup = setInterval(pruneExpired, 60000).unref();
  server.once('close', () => clearInterval(cleanup));
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT ?? 8080);
  const site = createSiteServer({
    clientId: process.env.VK_CLIENT_ID,
    redirectUri: process.env.VK_REDIRECT_URI,
  });
  site.listen(port, '127.0.0.1', () => {
    console.log(`Топиарий Сад: http://127.0.0.1:${site.address().port}/#login`);
  });
}
