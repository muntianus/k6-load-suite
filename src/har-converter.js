import { THRESHOLD_PROFILES } from '../lib/thresholds.js';

const SENSITIVE_HEADER_NAMES = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-csrf-token',
  'x-xsrf-token',
  'x-session-id',
]);

const SENSITIVE_PARAM_PATTERN =
  /^(token|access_token|refresh_token|api_key|apikey|secret|password|passwd|session|sig|signature)$/i;

/**
 * Redacts PII / sensitive query parameters from a URL string.
 * @param {string} rawUrl
 * @returns {string}
 */
export function sanitizeUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    for (const key of Array.from(parsed.searchParams.keys())) {
      if (SENSITIVE_PARAM_PATTERN.test(key)) {
        parsed.searchParams.set(key, 'REDACTED');
      }
    }
    return parsed.toString();
  } catch {
    return String(rawUrl || '');
  }
}

/**
 * Filters and redacts sensitive HTTP headers (Authorization, Cookie, API keys) and pseudo-headers.
 * @param {Array<{name: string, value: string}>} [headers]
 * @returns {{ cleanHeaders: Record<string, string>, redactedCount: number }}
 */
export function sanitizeHeaders(headers = []) {
  const cleanHeaders = {};
  let redactedCount = 0;

  if (!Array.isArray(headers)) {
    return { cleanHeaders, redactedCount };
  }

  for (const h of headers) {
    if (!h || typeof h.name !== 'string') continue;
    const rawName = h.name.trim();
    const lower = rawName.toLowerCase();

    // Skip HTTP/2 pseudo-headers and host/content-length managed by k6
    if (lower.startsWith(':') || lower === 'host' || lower === 'content-length') {
      continue;
    }

    if (SENSITIVE_HEADER_NAMES.has(lower) || lower.includes('secret') || lower.includes('token')) {
      redactedCount += 1;
      continue;
    }

    cleanHeaders[rawName] = String(h.value ?? '');
  }

  return { cleanHeaders, redactedCount };
}

/**
 * Redacts sensitive fields from JSON request bodies if applicable.
 * @param {string | undefined} text
 * @returns {string | null}
 */
export function sanitizePostBody(text) {
  if (!text || typeof text !== 'string') return null;
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const clone = { ...parsed };
      for (const key of Object.keys(clone)) {
        if (SENSITIVE_PARAM_PATTERN.test(key)) {
          clone[key] = 'REDACTED';
        }
      }
      return JSON.stringify(clone);
    }
    return text;
  } catch {
    return text;
  }
}

/**
 * Converts a HAR (HTTP Archive) JSON object into a deterministic ES-module k6 script.
 * - Filters out PII headers/cookies (`Authorization`, `Cookie`, `X-API-Key`, etc.)
 * - Groups entries by `pageref` or hostname
 * - Adds `check(res, { 'status 200': (r) => r.status === 200 })`
 *
 * @param {object} har - Parsed HAR object containing `log.entries`
 * @param {object} [options]
 * @param {string} [options.profile='smoke'] - Threshold profile name
 * @param {boolean} [options.includeStaticAssets=false] - Whether to keep images/fonts/css
 * @returns {{ script: string, stats: { totalEntries: number, convertedRequests: number, redactedHeaders: number, groups: string[] } }}
 */
export function convertHarToK6(har, options = {}) {
  const entries = har?.log?.entries;
  if (!Array.isArray(entries)) {
    throw new TypeError('Invalid HAR payload: expected har.log.entries array');
  }

  const profileName = options.profile && THRESHOLD_PROFILES[options.profile] ? options.profile : 'smoke';
  const profileConfig = THRESHOLD_PROFILES[profileName];
  const includeStatic = Boolean(options.includeStaticAssets);

  const pagesMap = new Map();
  if (Array.isArray(har?.log?.pages)) {
    for (const p of har.log.pages) {
      if (p && p.id) {
        pagesMap.set(p.id, p.title || p.id);
      }
    }
  }

  const grouped = new Map();
  let redactedHeadersTotal = 0;
  let convertedRequests = 0;

  for (const entry of entries) {
    const req = entry?.request;
    if (!req || typeof req.url !== 'string' || !req.url.startsWith('http')) {
      continue;
    }

    const cleanUrl = sanitizeUrl(req.url);
    if (!includeStatic && /\.(png|jpe?g|gif|webp|svg|woff2?|ttf|eot|ico|css)(\?|$)/i.test(cleanUrl)) {
      continue;
    }

    const method = String(req.method || 'GET').toUpperCase();
    const { cleanHeaders, redactedCount } = sanitizeHeaders(req.headers);
    redactedHeadersTotal += redactedCount;

    if (Array.isArray(req.cookies) && req.cookies.length > 0) {
      redactedHeadersTotal += req.cookies.length;
    }

    let groupName = 'default-group';
    if (entry.pageref && pagesMap.has(entry.pageref)) {
      groupName = String(pagesMap.get(entry.pageref));
    } else if (entry.pageref) {
      groupName = String(entry.pageref);
    } else {
      try {
        groupName = new URL(cleanUrl).hostname || 'default-group';
      } catch {
        groupName = 'default-group';
      }
    }

    const bodyText = sanitizePostBody(req.postData?.text);

    if (!grouped.has(groupName)) {
      grouped.set(groupName, []);
    }

    grouped.get(groupName).push({
      method,
      url: cleanUrl,
      headers: cleanHeaders,
      body: bodyText,
    });
    convertedRequests += 1;
  }

  const lines = [
    "import http from 'k6/http';",
    "import { check, group, sleep } from 'k6';",
    '',
    `export const options = ${JSON.stringify(profileConfig, null, 2)};`,
    '',
    'export default function () {',
  ];

  for (const [groupName, requests] of grouped.entries()) {
    const safeGroupName = groupName.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    lines.push(`  group('${safeGroupName}', () => {`);
    lines.push('    let res;');

    for (const r of requests) {
      const safeUrl = r.url.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
      const hasHeaders = Object.keys(r.headers).length > 0;
      const paramsStr = hasHeaders ? `, { headers: ${JSON.stringify(r.headers)} }` : '';

      if (r.method === 'GET' || r.method === 'HEAD') {
        const fn = r.method.toLowerCase();
        lines.push(`    res = http.${fn}('${safeUrl}'${paramsStr});`);
      } else if (r.method === 'POST' || r.method === 'PUT' || r.method === 'PATCH' || r.method === 'DEL' || r.method === 'DELETE') {
        const fn = r.method === 'DELETE' ? 'del' : r.method.toLowerCase();
        const bodyArg = r.body !== null ? JSON.stringify(r.body) : 'null';
        lines.push(`    res = http.${fn}('${safeUrl}', ${bodyArg}${paramsStr});`);
      } else {
        const bodyArg = r.body !== null ? JSON.stringify(r.body) : 'null';
        lines.push(`    res = http.request('${r.method}', '${safeUrl}', ${bodyArg}${paramsStr});`);
      }

      lines.push("    check(res, { 'status 200': (r) => r.status === 200 });");
    }

    lines.push('  });');
    lines.push('');
  }

  lines.push('  sleep(1);');
  lines.push('}');
  lines.push('');

  return {
    script: lines.join('\n'),
    stats: {
      totalEntries: entries.length,
      convertedRequests,
      redactedHeaders: redactedHeadersTotal,
      groups: Array.from(grouped.keys()),
    },
  };
}
