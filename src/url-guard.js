import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

export const DEFAULT_TIMEOUT_MS = 5000;
export const DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
export const DEFAULT_MAX_REDIRECTS = 5;

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * Error thrown when a URL or a redirect target violates the outbound fetch policy.
 * `statusCode` lets the HTTP layer answer with 400 instead of treating it as a probe failure.
 */
export class SsrfError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SsrfError';
    this.code = 'SSRF_BLOCKED';
    this.statusCode = 400;
  }
}

// Reserved, loopback, link-local, and cloud-metadata ranges. Anything here is unreachable
// for the outbound probe unless the host is explicitly allowlisted by the operator.
const BLOCKED_ADDRESSES = new net.BlockList();
BLOCKED_ADDRESSES.addSubnet('0.0.0.0', 8, 'ipv4');
BLOCKED_ADDRESSES.addSubnet('10.0.0.0', 8, 'ipv4');
BLOCKED_ADDRESSES.addSubnet('100.64.0.0', 10, 'ipv4'); // CGNAT
BLOCKED_ADDRESSES.addSubnet('127.0.0.0', 8, 'ipv4');
BLOCKED_ADDRESSES.addSubnet('169.254.0.0', 16, 'ipv4'); // link-local + 169.254.169.254 metadata
BLOCKED_ADDRESSES.addSubnet('172.16.0.0', 12, 'ipv4');
BLOCKED_ADDRESSES.addSubnet('192.0.0.0', 24, 'ipv4');
BLOCKED_ADDRESSES.addSubnet('192.0.2.0', 24, 'ipv4');
BLOCKED_ADDRESSES.addSubnet('192.168.0.0', 16, 'ipv4');
BLOCKED_ADDRESSES.addSubnet('198.18.0.0', 15, 'ipv4');
BLOCKED_ADDRESSES.addSubnet('198.51.100.0', 24, 'ipv4');
BLOCKED_ADDRESSES.addSubnet('203.0.113.0', 24, 'ipv4');
BLOCKED_ADDRESSES.addSubnet('224.0.0.0', 4, 'ipv4'); // multicast
BLOCKED_ADDRESSES.addSubnet('240.0.0.0', 4, 'ipv4'); // reserved + broadcast
BLOCKED_ADDRESSES.addSubnet('::', 128, 'ipv6');
BLOCKED_ADDRESSES.addSubnet('::1', 128, 'ipv6');
BLOCKED_ADDRESSES.addSubnet('fc00::', 7, 'ipv6');
BLOCKED_ADDRESSES.addSubnet('fe80::', 10, 'ipv6');

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata',
  'metadata.google.internal',
  'metadata.goog',
]);

const BLOCKED_HOST_SUFFIXES = ['.localhost', '.local', '.internal'];

/**
 * Normalizes a URL hostname: strips IPv6 brackets, the trailing root dot, and lowercases it.
 * @param {string} hostname
 * @returns {string}
 */
export function normalizeHostname(hostname) {
  return String(hostname || '')
    .trim()
    .toLowerCase()
    .replace(/^\[/, '')
    .replace(/\]$/, '')
    .replace(/\.$/, '');
}

/**
 * Extracts an embedded IPv4 address from IPv4-mapped / NAT64 IPv6 literals.
 * @param {string} address
 * @returns {string | null}
 */
function extractEmbeddedIpv4(address) {
  const dottedMapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(address);
  if (dottedMapped) return dottedMapped[1];

  const nat64 = /^64:ff9b::(\d{1,3}(?:\.\d{1,3}){3})$/.exec(address);
  if (nat64) return nat64[1];

  const nat64Hex = /^64:ff9b::([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(address);
  if (nat64Hex) {
    const high = parseInt(nat64Hex[1], 16);
    const low = parseInt(nat64Hex[2], 16);
    return [high >> 8, high & 0xff, low >> 8, low & 0xff].join('.');
  }

  const hexMapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(address);
  if (hexMapped) {
    const high = parseInt(hexMapped[1], 16);
    const low = parseInt(hexMapped[2], 16);
    return [high >> 8, high & 0xff, low >> 8, low & 0xff].join('.');
  }

  return null;
}

/**
 * Returns true when an IP literal points at a loopback, private, link-local, metadata,
 * multicast, or otherwise reserved address.
 * @param {string} address
 * @returns {boolean}
 */
export function isBlockedAddress(address) {
  const normalized = normalizeHostname(address);
  if (!normalized) return true;

  const withoutZone = normalized.split('%')[0];

  if (net.isIPv4(withoutZone)) {
    return BLOCKED_ADDRESSES.check(withoutZone, 'ipv4');
  }

  if (net.isIPv6(withoutZone)) {
    const embedded = extractEmbeddedIpv4(withoutZone);
    if (embedded && net.isIPv4(embedded)) {
      return BLOCKED_ADDRESSES.check(embedded, 'ipv4');
    }
    return BLOCKED_ADDRESSES.check(withoutZone, 'ipv6');
  }

  // Unknown literal => fail closed.
  return true;
}

/**
 * Returns true for hostnames that always resolve locally or to cloud metadata.
 * @param {string} hostname
 * @returns {boolean}
 */
export function isBlockedHostname(hostname) {
  const host = normalizeHostname(hostname);
  if (!host) return true;
  // Zone-scoped or percent-encoded IPv6 literals must never reach DNS.
  if (host.includes('%')) return true;
  if (BLOCKED_HOSTNAMES.has(host)) return true;
  return BLOCKED_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

/**
 * Parses SWAGGER_FETCH_ALLOWLIST (comma-separated hostnames, `*.example.com` wildcards allowed).
 * @param {string | undefined} [raw]
 * @returns {string[]}
 */
export function parseAllowlist(raw = process.env.SWAGGER_FETCH_ALLOWLIST) {
  if (!raw || typeof raw !== 'string') return [];
  return raw
    .split(',')
    .map((entry) => normalizeHostname(entry))
    .filter(Boolean);
}

/**
 * @param {string} hostname
 * @param {string[]} allowlist
 * @returns {boolean}
 */
export function isAllowlisted(hostname, allowlist = []) {
  const host = normalizeHostname(hostname);
  if (!host) return false;

  return allowlist.some((entry) => {
    if (entry.startsWith('*.')) {
      const suffix = entry.slice(2);
      return Boolean(suffix) && (host === suffix || host.endsWith(`.${suffix}`));
    }
    return host === entry;
  });
}

/**
 * Synchronous URL policy check: scheme, hostname, and IP literals.
 * @param {string} rawUrl
 * @param {{ allowlist?: string[] }} [options]
 * @returns {{ url: URL, host: string, allowlisted: boolean }}
 */
export function assertSafeUrl(rawUrl, options = {}) {
  const allowlist = options.allowlist ?? parseAllowlist();

  let parsed;
  try {
    parsed = new URL(String(rawUrl));
  } catch {
    throw new SsrfError('Invalid URL: a valid absolute http(s) URL is required');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new SsrfError(`Blocked URL scheme "${parsed.protocol}" — only http and https are allowed`);
  }

  const host = normalizeHostname(parsed.hostname);
  if (!host) {
    throw new SsrfError('Blocked URL without a hostname');
  }

  const allowlisted = isAllowlisted(host, allowlist);
  if (allowlist.length > 0 && !allowlisted) {
    throw new SsrfError(`Blocked request to ${host}: host is not in SWAGGER_FETCH_ALLOWLIST`);
  }
  if (allowlisted) {
    return { url: parsed, host, allowlisted };
  }

  if (net.isIP(host)) {
    if (isBlockedAddress(host)) {
      throw new SsrfError(`Blocked request to private or reserved address ${host}`);
    }
    return { url: parsed, host, allowlisted };
  }

  if (isBlockedHostname(host)) {
    throw new SsrfError(`Blocked request to local or internal hostname ${host}`);
  }

  return { url: parsed, host, allowlisted };
}

/**
 * Resolves a hostname and rejects when any resolved address is private/reserved
 * (DNS-rebinding protection). Returns the vetted addresses for connection pinning.
 * @param {string} hostname
 * @param {{ allowlist?: string[], lookupImpl?: Function }} [options]
 * @returns {Promise<Array<{ address: string, family: number }>>}
 */
export async function resolveAndValidate(hostname, options = {}) {
  const host = normalizeHostname(hostname);
  const allowlist = options.allowlist ?? parseAllowlist();
  const allowlisted = isAllowlisted(host, allowlist);

  if (allowlist.length > 0 && !allowlisted) {
    throw new SsrfError(`Blocked request to ${host}: host is not in SWAGGER_FETCH_ALLOWLIST`);
  }

  if (net.isIP(host)) {
    if (!allowlisted && isBlockedAddress(host)) {
      throw new SsrfError(`Blocked request to private or reserved address ${host}`);
    }
    return [{ address: host, family: net.isIPv6(host) ? 6 : 4 }];
  }

  const lookup = options.lookupImpl || ((name) => dns.lookup(name, { all: true, verbatim: true }));

  let records;
  try {
    records = await lookup(host);
  } catch {
    throw Object.assign(new Error(`DNS resolution failed for ${host}`), {
      code: 'ENOTFOUND',
      statusCode: 502,
    });
  }

  if (!Array.isArray(records)) {
    records = records ? [records] : [];
  }

  const addresses = [];
  const seen = new Set();

  for (const record of records) {
    const address = normalizeHostname(
      typeof record === 'string' ? record : record?.address
    );
    if (!address || seen.has(address)) continue;
    seen.add(address);

    if (!allowlisted && isBlockedAddress(address)) {
      throw new SsrfError(
        `Blocked request: ${host} resolves to private or reserved address ${address}`
      );
    }

    const family = record?.family === 6 || net.isIPv6(address) ? 6 : 4;
    addresses.push({ address, family });
  }

  if (addresses.length === 0) {
    throw Object.assign(new Error(`DNS resolution returned no addresses for ${host}`), {
      code: 'ENOTFOUND',
      statusCode: 502,
    });
  }

  return addresses;
}

function getHeader(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()];
}

function responseTooLarge(host, maxBytes) {
  return Object.assign(new Error(`Response from ${host} exceeds the ${maxBytes} byte limit`), {
    code: 'RESPONSE_TOO_LARGE',
    statusCode: 413,
  });
}

function timeoutError(host, timeoutMs) {
  return Object.assign(new Error(`Request to ${host} timed out after ${timeoutMs}ms`), {
    name: 'TimeoutError',
    code: 'ETIMEDOUT',
    statusCode: 504,
  });
}

function createResponse({ status, statusText, headers, url, buffer }) {
  return {
    status,
    statusText: statusText || '',
    headers,
    url,
    body: buffer,
    bytes: buffer.length,
    text: () => buffer.toString('utf8'),
    json: () => JSON.parse(buffer.toString('utf8')),
  };
}

/**
 * Minimal HTTP(S) client pinned to a pre-validated IP address so a second DNS answer
 * cannot redirect the socket to a private address (DNS rebinding).
 */
function httpRequestPinned(url, { method, headers, body, address, family, timeoutMs, maxBytes, signal }) {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === 'https:';
    const transport = isHttps ? https : http;
    const hostname = normalizeHostname(url.hostname);
    const requestHeaders = { ...headers };
    const hasContentLength = Object.keys(requestHeaders).some(
      (key) => key.toLowerCase() === 'content-length'
    );

    if (body !== undefined && body !== null && !hasContentLength) {
      requestHeaders['Content-Length'] = Buffer.byteLength(body);
    }

    let settled = false;
    let absoluteTimer;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(absoluteTimer);
      reject(err);
    };
    const succeed = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(absoluteTimer);
      resolve(value);
    };

    let req;
    try {
      req = transport.request(
        {
          protocol: url.protocol,
          hostname,
          port: url.port || (isHttps ? 443 : 80),
          path: `${url.pathname}${url.search}`,
          method,
          headers: requestHeaders,
          servername: net.isIP(hostname) ? undefined : hostname,
          lookup: (lookupHostname, lookupOptions, callback) => {
            if (lookupOptions && lookupOptions.all) {
              callback(null, [{ address, family }]);
              return;
            }
            callback(null, address, family);
          },
          signal,
        },
        (res) => {
          const chunks = [];
          let total = 0;

          res.on('data', (chunk) => {
            total += chunk.length;
            if (total > maxBytes) {
              res.destroy();
              req.destroy();
              fail(responseTooLarge(hostname, maxBytes));
              return;
            }
            chunks.push(chunk);
          });

          res.on('end', () => {
            if (settled) return;
            succeed(
              createResponse({
                status: res.statusCode || 0,
                statusText: res.statusMessage,
                headers: res.headers,
                url: url.toString(),
                buffer: Buffer.concat(chunks),
              })
            );
          });

          res.on('error', (err) => fail(err));
        }
      );
    } catch (err) {
      fail(err);
      return;
    }

    req.setTimeout(timeoutMs, () => {
      req.destroy(timeoutError(hostname, timeoutMs));
    });

    // Absolute per-hop deadline: a trickling response must not extend the timeout.
    absoluteTimer = setTimeout(() => {
      req.destroy(timeoutError(hostname, timeoutMs));
    }, timeoutMs);

    req.on('error', (err) => {
      if (err?.name === 'AbortError') {
        fail(Object.assign(new Error(`Request to ${hostname} was aborted`), { name: 'AbortError' }));
        return;
      }
      fail(err);
    });

    if (body !== undefined && body !== null) {
      req.write(body);
    }
    req.end();
  });
}

async function injectedFetch(fetchImpl, url, { method, headers, body, timeoutMs, maxBytes, signal }) {
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener('abort', onAbort, { once: true });
  }

  const hostname = normalizeHostname(url.hostname);
  let timer;

  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => {
        // Settle the race with the timeout first, then abort the in-flight mock/fetch.
        reject(timeoutError(hostname, timeoutMs));
        controller.abort();
      }, timeoutMs);
    });

    const res = await Promise.race([
      fetchImpl(url.toString(), {
        method,
        headers,
        body,
        redirect: 'manual',
        signal: controller.signal,
      }),
      timeout,
    ]);

    const declaredLength = Number(getHeader(res.headers, 'content-length'));
    if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
      throw responseTooLarge(hostname, maxBytes);
    }

    const buffer = Buffer.from(await Promise.race([res.arrayBuffer(), timeout]));
    if (buffer.length > maxBytes) {
      throw responseTooLarge(hostname, maxBytes);
    }

    return createResponse({
      status: res.status,
      statusText: res.statusText,
      headers: res.headers,
      url: res.url || url.toString(),
      buffer,
    });
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

/**
 * Fetches an http(s) URL under a strict SSRF policy:
 * - only http/https, loopback/private/link-local/metadata hosts blocked;
 * - DNS resolved and every address re-checked before connecting (and the socket pinned to it);
 * - redirects followed manually, each hop re-validated;
 * - overall timeout and response-size cap;
 * - SWAGGER_FETCH_ALLOWLIST optionally restricts fetching to explicit hosts.
 *
 * @param {string} rawUrl
 * @param {object} [options]
 * @param {string} [options.method='GET']
 * @param {Record<string, string>} [options.headers]
 * @param {string | Buffer} [options.body]
 * @param {number} [options.timeoutMs]
 * @param {number} [options.maxResponseBytes]
 * @param {number} [options.maxRedirects]
 * @param {string[]} [options.allowlist]
 * @param {Function} [options.fetchImpl] - test seam, must behave like fetch with redirect: 'manual'
 * @param {Function} [options.lookupImpl] - test seam for DNS resolution
 * @param {AbortSignal} [options.signal]
 * @returns {Promise<{ status: number, headers: object, url: string, body: Buffer, bytes: number, text: Function, json: Function }>}
 */
export async function safeFetch(rawUrl, options = {}) {
  const method = String(options.method || 'GET').toUpperCase();
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const allowlist = options.allowlist ?? parseAllowlist();
  const deadline = Date.now() + timeoutMs;

  let currentUrl = String(rawUrl);
  let currentMethod = method;
  let currentBody = options.body;

  for (let redirects = 0; ; redirects += 1) {
    const { url, host } = assertSafeUrl(currentUrl, { allowlist });
    const addresses = await resolveAndValidate(host, { allowlist, lookupImpl: options.lookupImpl });

    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw timeoutError(host, timeoutMs);
    }

    const res = options.fetchImpl
      ? await injectedFetch(options.fetchImpl, url, {
          method: currentMethod,
          headers: options.headers || {},
          body: currentBody,
          timeoutMs: remaining,
          maxBytes: maxResponseBytes,
          signal: options.signal,
        })
      : await httpRequestPinned(url, {
          method: currentMethod,
          headers: options.headers || {},
          body: currentBody,
          address: addresses[0].address,
          family: addresses[0].family,
          timeoutMs: remaining,
          maxBytes: maxResponseBytes,
          signal: options.signal,
        });

    if (!REDIRECT_STATUSES.has(res.status)) {
      return res;
    }

    const location = getHeader(res.headers, 'location');
    if (!location) {
      return res;
    }

    if (redirects >= maxRedirects) {
      throw new SsrfError(`Blocked request: more than ${maxRedirects} redirects`);
    }

    currentUrl = new URL(String(location), url).toString();
    if (res.status === 303 || ((res.status === 301 || res.status === 302) && currentMethod === 'POST')) {
      currentMethod = 'GET';
      currentBody = undefined;
    }
  }
}
