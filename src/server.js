import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { THRESHOLD_PROFILES, buildOptions } from '../lib/thresholds.js';
import { convertHarToK6, sanitizeHeaders, sanitizeUrl } from './har-converter.js';
import {
  DEFAULT_MAX_RESPONSE_BYTES,
  DEFAULT_TIMEOUT_MS,
  SsrfError,
  assertSafeUrl,
  parseAllowlist,
  safeFetch,
} from './url-guard.js';

export const SCENARIO_CATALOG = Object.freeze([
  {
    id: 'globlex-enterprise-slo',
    path: 'scenarios/globlex-enterprise-slo.js',
    description:
      'Multi-group SLO scenario covering globlex.shop, globlex.pro, globlex.online, api.globlex.pro/health, /enterprise/overview, and /quote-parse/',
    defaultProfile: 'baseline',
    surfaces: [
      'globlex.shop',
      'globlex.pro',
      'globlex.online',
      'api.globlex.pro/health',
      'api.globlex.pro/enterprise/overview',
      'api.globlex.pro/quote-parse/',
    ],
  },
  {
    id: 'perfops-gateway-slo',
    path: 'scenarios/perfops-gateway-slo.js',
    description: 'Edge & control-plane SLO scenario for perfops.tech, perfops.shop, and aco.perfops.shop/health',
    defaultProfile: 'smoke',
    surfaces: ['perfops.tech', 'perfops.shop', 'aco.perfops.shop/health'],
  },
]);

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function readJsonBody(req, maxBytes = 2 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;

    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(Object.assign(new Error('Payload too large'), { statusCode: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(Object.assign(new Error('Invalid JSON payload'), { statusCode: 400 }));
      }
    });

    req.on('error', reject);
  });
}

/**
 * Normalizes headers object or array, redacting sensitive auth/token headers.
 * @param {Record<string, string> | Array<{name: string, value: string}>} [rawHeaders]
 * @returns {Record<string, string>}
 */
export function normalizeAndSanitizeHeaders(rawHeaders) {
  if (!rawHeaders) return { Accept: 'application/json' };
  const headersArray = Array.isArray(rawHeaders)
    ? rawHeaders
    : Object.entries(rawHeaders).map(([name, value]) => ({ name, value }));
  const { cleanHeaders } = sanitizeHeaders(headersArray);
  if (!cleanHeaders.Accept && !cleanHeaders.accept) {
    cleanHeaders.Accept = 'application/json';
  }
  return cleanHeaders;
}

/**
 * Parses an OpenAPI/Swagger spec object or an endpoint list into structured endpoint definitions.
 * @param {object | Array} input - OpenAPI 3.x, Swagger 2.0, or endpoint list payload
 * @param {string} [defaultBaseUrl='http://127.0.0.1:4040']
 * @returns {{ baseUrl: string, endpoints: Array<{ method: string, url: string, path: string, group: string, summary?: string, headers: Record<string, string>, body: any }> }}
 */
export function parseSwaggerEndpoints(input, defaultBaseUrl = 'http://127.0.0.1:4040') {
  if (!input) {
    throw Object.assign(new Error('Missing OpenAPI/Swagger or endpoint payload'), { statusCode: 400 });
  }

  let spec = input;
  let explicitBaseUrl = input.baseUrl || input.host;

  if (input.spec && typeof input.spec === 'object') {
    spec = input.spec;
    explicitBaseUrl = explicitBaseUrl || spec.baseUrl || spec.host;
  } else if (input.swagger && typeof input.swagger === 'object') {
    spec = input.swagger;
    explicitBaseUrl = explicitBaseUrl || spec.baseUrl || spec.host;
  } else if (input.openapi && typeof input.openapi === 'object') {
    spec = input.openapi;
    explicitBaseUrl = explicitBaseUrl || spec.baseUrl || spec.host;
  }

  let resolvedBaseUrl = explicitBaseUrl;
  if (!resolvedBaseUrl) {
    if (Array.isArray(spec.servers) && spec.servers.length > 0 && spec.servers[0]?.url) {
      resolvedBaseUrl = spec.servers[0].url;
    } else if (spec.host) {
      const scheme = Array.isArray(spec.schemes) && spec.schemes[0] ? spec.schemes[0] : 'http';
      const basePath = spec.basePath || '';
      resolvedBaseUrl = `${scheme}://${spec.host}${basePath}`;
    }
  }
  if (!resolvedBaseUrl) {
    resolvedBaseUrl = defaultBaseUrl;
  }
  if (!/^https?:\/\//i.test(resolvedBaseUrl)) {
    resolvedBaseUrl = `http://${resolvedBaseUrl}`;
  }

  const endpoints = [];

  const rawList = Array.isArray(input)
    ? input
    : Array.isArray(input.endpoints)
      ? input.endpoints
      : null;

  if (rawList) {
    for (const item of rawList) {
      if (typeof item === 'string') {
        const fullUrl = item.startsWith('http')
          ? sanitizeUrl(item)
          : sanitizeUrl(
              new URL(
                item.replace(/^\//, ''),
                resolvedBaseUrl.endsWith('/') ? resolvedBaseUrl : `${resolvedBaseUrl}/`
              ).toString()
            );
        const parsedUrl = new URL(fullUrl);
        endpoints.push({
          method: 'GET',
          url: fullUrl,
          path: parsedUrl.pathname,
          group: parsedUrl.pathname.replace(/^\//, '') || 'root',
          headers: { Accept: 'application/json' },
          body: null,
        });
      } else if (item && typeof item === 'object') {
        const rawPath = item.path || item.url || '/';
        const method = String(item.method || 'GET').toUpperCase();
        const fullUrl = rawPath.startsWith('http')
          ? sanitizeUrl(rawPath)
          : sanitizeUrl(
              new URL(
                rawPath.replace(/^\//, ''),
                resolvedBaseUrl.endsWith('/') ? resolvedBaseUrl : `${resolvedBaseUrl}/`
              ).toString()
            );
        const parsedUrl = new URL(fullUrl);
        const headers = normalizeAndSanitizeHeaders(item.headers);
        endpoints.push({
          method,
          url: fullUrl,
          path: parsedUrl.pathname,
          group:
            item.group ||
            item.name ||
            parsedUrl.pathname.replace(/^\//, '') ||
            'root',
          headers,
          body: item.body ?? null,
        });
      }
    }
    return { baseUrl: resolvedBaseUrl, endpoints };
  }

  const pathsObj = spec.paths;
  if (!pathsObj || typeof pathsObj !== 'object') {
    throw Object.assign(
      new Error('Invalid OpenAPI/Swagger spec: missing paths object or endpoints array'),
      { statusCode: 400 }
    );
  }

  const HTTP_METHODS = new Set(['get', 'post', 'put', 'delete', 'patch', 'head', 'options']);

  for (const [pathStr, pathItem] of Object.entries(pathsObj)) {
    if (!pathItem || typeof pathItem !== 'object') continue;

    for (const [methodKey, op] of Object.entries(pathItem)) {
      const lowerMethod = methodKey.toLowerCase();
      if (!HTTP_METHODS.has(lowerMethod)) continue;

      const method = lowerMethod.toUpperCase();
      const concretePath = pathStr
        .replace(/\{([^}]+)\}/g, '1')
        .replace(/:([a-zA-Z0-9_]+)/g, '1');
      const fullUrl = sanitizeUrl(
        new URL(
          concretePath.replace(/^\//, ''),
          resolvedBaseUrl.endsWith('/') ? resolvedBaseUrl : `${resolvedBaseUrl}/`
        ).toString()
      );

      let groupName = 'default';
      if (Array.isArray(op.tags) && op.tags.length > 0 && op.tags[0]) {
        groupName = String(op.tags[0]);
      } else if (op.operationId) {
        groupName = String(op.operationId);
      } else {
        groupName = pathStr.replace(/^\//, '') || 'root';
      }

      const headers = normalizeAndSanitizeHeaders(op.headers);
      if (['POST', 'PUT', 'PATCH'].includes(method) && !headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
      }

      let body = null;
      if (['POST', 'PUT', 'PATCH'].includes(method)) {
        if (op.requestBody?.content?.['application/json']?.example) {
          body = op.requestBody.content['application/json'].example;
        } else if (op.example) {
          body = op.example;
        } else {
          body = {};
        }
      }

      endpoints.push({
        method,
        url: fullUrl,
        path: pathStr,
        group: groupName,
        summary: op.summary || op.operationId || `${method} ${pathStr}`,
        headers,
        body,
      });
    }
  }

  if (endpoints.length === 0) {
    throw Object.assign(
      new Error('No valid HTTP operations found in OpenAPI/Swagger spec'),
      { statusCode: 400 }
    );
  }

  return { baseUrl: resolvedBaseUrl, endpoints };
}

/**
 * Generates a deterministic ES-module k6 script from structured endpoint descriptors.
 * @param {Array<object>} endpoints
 * @param {object} [options]
 * @param {string} [options.profile='smoke']
 * @returns {string}
 */
export function generateK6ScriptFromSwagger(endpoints, options = {}) {
  const profileName =
    options.profile && THRESHOLD_PROFILES[options.profile] ? options.profile : 'smoke';
  const profileConfig = THRESHOLD_PROFILES[profileName];

  const grouped = new Map();
  for (const ep of endpoints) {
    const groupName = ep.group || 'default';
    if (!grouped.has(groupName)) {
      grouped.set(groupName, []);
    }
    grouped.get(groupName).push(ep);
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
      const hasHeaders = r.headers && Object.keys(r.headers).length > 0;
      const paramsStr = hasHeaders ? `, { headers: ${JSON.stringify(r.headers)} }` : '';

      if (r.method === 'GET' || r.method === 'HEAD') {
        const fn = r.method.toLowerCase();
        lines.push(`    res = http.${fn}('${safeUrl}'${paramsStr});`);
      } else if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(r.method)) {
        const fn = r.method === 'DELETE' ? 'del' : r.method.toLowerCase();
        const bodyArg =
          r.body !== null && r.body !== undefined ? JSON.stringify(r.body) : 'null';
        lines.push(`    res = http.${fn}('${safeUrl}', ${bodyArg}${paramsStr});`);
      } else {
        const bodyArg =
          r.body !== null && r.body !== undefined ? JSON.stringify(r.body) : 'null';
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

  return lines.join('\n');
}

/**
 * Executes a fast smoke probe against the extracted endpoints and computes latency & SLO metrics.
 * Outbound requests go through safeFetch: private/metadata targets and redirects to them are
 * rejected with SsrfError (HTTP 400) instead of being recorded as a probe failure.
 * @param {Array<object>} endpoints
 * @param {object} [options]
 * @returns {Promise<{ smoke_metrics: object, verdict: 'GO' | 'NO-GO', results: Array<object> }>}
 */
export async function executeSmokeProbe(endpoints, options = {}) {
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const maxResponseBytes = options.maxResponseBytes || DEFAULT_MAX_RESPONSE_BYTES;
  const allowlist = options.allowlist ?? parseAllowlist();
  const results = [];
  const startTotal = performance.now();

  for (const ep of endpoints) {
    const startReq = performance.now();
    try {
      if (options.mockProbe) {
        const latency = options.mockLatencyMs ?? 15;
        const status = options.mockStatus ?? 200;
        results.push({
          url: ep.url,
          method: ep.method,
          status,
          duration_ms: latency,
          ok: status >= 200 && status < 400,
        });
        continue;
      }

      const fetchOptions = {
        method: ep.method,
        headers: ep.headers || {},
        timeoutMs,
        maxResponseBytes,
        allowlist,
        signal: options.signal,
      };

      if (ep.body && ['POST', 'PUT', 'PATCH'].includes(ep.method)) {
        fetchOptions.body =
          typeof ep.body === 'string' ? ep.body : JSON.stringify(ep.body);
      }

      const res = await safeFetch(ep.url, fetchOptions);
      const duration = Math.round((performance.now() - startReq) * 100) / 100;

      results.push({
        url: ep.url,
        method: ep.method,
        status: res.status,
        duration_ms: duration,
        ok: res.status >= 200 && res.status < 400,
      });
    } catch (err) {
      // A policy violation must fail the whole request, never be downgraded to a NO-GO probe.
      if (err instanceof SsrfError) {
        throw err;
      }
      const duration = Math.round((performance.now() - startReq) * 100) / 100;
      results.push({
        url: ep.url,
        method: ep.method,
        status: 0,
        error: err.name === 'AbortError' ? 'timeout' : err.message,
        duration_ms: duration,
        ok: false,
      });
    }
  }

  const totalDuration = Math.round((performance.now() - startTotal) * 100) / 100;
  const total = results.length;
  const passed = results.filter((r) => r.ok).length;
  const failed = total - passed;
  const durations = results.map((r) => r.duration_ms).sort((a, b) => a - b);

  const avgDuration =
    total > 0 ? Math.round((durations.reduce((a, b) => a + b, 0) / total) * 100) / 100 : 0;
  const minDuration = total > 0 ? durations[0] : 0;
  const maxDuration = total > 0 ? durations[durations.length - 1] : 0;
  const p95Index = Math.min(Math.floor(total * 0.95), total - 1);
  const p95Duration = total > 0 ? durations[p95Index] : 0;
  const checksRate = total > 0 ? Number((passed / total).toFixed(4)) : 1.0;
  const failRate = total > 0 ? Number((failed / total).toFixed(4)) : 0.0;

  const smoke_metrics = {
    http_reqs: total,
    successful_probes: passed,
    failed_probes: failed,
    checks_rate: checksRate,
    http_req_failed_rate: failRate,
    http_req_duration_p95: p95Duration,
    http_req_duration_avg: avgDuration,
    http_req_duration_min: minDuration,
    http_req_duration_max: maxDuration,
    status_codes: results.map((r) => r.status),
    duration_ms: totalDuration,
  };

  const verdict = total === 0 || (failed === 0 && checksRate >= 0.99) ? 'GO' : 'NO-GO';

  return { smoke_metrics, verdict, results };
}

/**
 * High-level processor for OpenAPI/Swagger conversion and smoke probing.
 * @param {object} body
 * @returns {Promise<{ status: string, k6_script: string, smoke_metrics: object, verdict: string }>}
 */
export async function processSwaggerToK6(body = {}) {
  const { baseUrl, endpoints } = parseSwaggerEndpoints(body);
  const profile = body.profile || 'smoke';
  const k6_script = generateK6ScriptFromSwagger(endpoints, { profile });
  const mockProbe = Boolean(body.mockProbe);
  const allowlist = parseAllowlist();

  // Fail fast on private/metadata targets before touching the network. Mock probes never fetch,
  // so offline conversion of specs pointing at local services keeps working.
  if (!mockProbe) {
    for (const ep of endpoints) {
      assertSafeUrl(ep.url, { allowlist });
    }
  }

  const probeOptions = {
    timeoutMs: Math.min(Number(body.timeoutMs) || DEFAULT_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
    maxResponseBytes: DEFAULT_MAX_RESPONSE_BYTES,
    allowlist,
    mockProbe,
    mockStatus: body.mockStatus,
    mockLatencyMs: body.mockLatencyMs,
  };

  const { smoke_metrics, verdict } = await executeSmokeProbe(endpoints, probeOptions);

  return {
    status: 'ok',
    k6_script,
    smoke_metrics,
    verdict,
    endpoints_count: endpoints.length,
    baseUrl,
    profile,
  };
}

/**
 * Creates the k6-load-suite HTTP server instance.
 * @returns {import('node:http').Server}
 */
export function createServer() {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

    if (req.method === 'GET' && url.pathname === '/health') {
      return sendJson(res, 200, {
        status: 'ok',
        service: 'k6-load-suite',
        version: '1.0.0',
        scenarios: SCENARIO_CATALOG.length,
        profiles: Object.keys(THRESHOLD_PROFILES),
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/v1/scenarios') {
      const requestedProfile = url.searchParams.get('profile');
      return sendJson(res, 200, {
        scenarios: SCENARIO_CATALOG,
        thresholdProfiles: THRESHOLD_PROFILES,
        resolvedOptions: requestedProfile ? buildOptions(requestedProfile) : undefined,
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/har-to-k6') {
      try {
        const body = await readJsonBody(req);
        const harPayload = body.har ? body.har : body;
        const result = convertHarToK6(harPayload, {
          profile: body.profile || 'smoke',
          includeStaticAssets: Boolean(body.includeStaticAssets),
        });

        return sendJson(res, 200, {
          status: 'converted',
          profile: body.profile || 'smoke',
          script: result.script,
          stats: result.stats,
        });
      } catch (err) {
        const status = err.statusCode || (err instanceof TypeError ? 422 : 400);
        return sendJson(res, status, {
          error: err.message || 'Failed to convert HAR payload',
        });
      }
    }

    if (
      req.method === 'POST' &&
      (url.pathname === '/api/swagger-to-k6' || url.pathname === '/api/v1/swagger-to-k6')
    ) {
      try {
        const body = await readJsonBody(req);
        const result = await processSwaggerToK6(body);
        return sendJson(res, 200, result);
      } catch (err) {
        const status = err.statusCode || (err instanceof TypeError ? 422 : 400);
        return sendJson(res, status, {
          error: err.message || 'Failed to process OpenAPI/Swagger spec',
        });
      }
    }

    return sendJson(res, 404, { error: 'Not Found', path: url.pathname });
  });
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const port = Number(process.env.PORT || 4040);
  const server = createServer();
  server.listen(port, () => {
    console.log(`[k6-load-suite] listening on http://0.0.0.0:${port}`);
  });
}
