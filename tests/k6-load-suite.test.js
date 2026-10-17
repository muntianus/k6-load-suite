import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  THRESHOLD_PROFILES,
  buildOptions,
  createStandardChecks,
  verifyResponse,
} from '../lib/thresholds.js';
import { convertHarToK6, sanitizeHeaders, sanitizeUrl } from '../src/har-converter.js';
import {
  createServer,
  parseSwaggerEndpoints,
  generateK6ScriptFromSwagger,
  executeSmokeProbe,
  processSwaggerToK6,
} from '../src/server.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');

test('lib/thresholds: exposes smoke, baseline, stress, and spike profiles', () => {
  assert.ok(THRESHOLD_PROFILES.smoke);
  assert.ok(THRESHOLD_PROFILES.baseline);
  assert.ok(THRESHOLD_PROFILES.stress);
  assert.ok(THRESHOLD_PROFILES.spike);

  const custom = buildOptions('baseline', {
    vus: 15,
    thresholds: { 'http_req_duration{group:::api}': ['p(95)<200'] },
    tags: { env: 'staging' },
  });

  assert.equal(custom.vus, 15);
  assert.deepEqual(custom.thresholds['http_req_duration{group:::api}'], ['p(95)<200']);
  assert.equal(custom.tags.env, 'staging');
});

test('lib/thresholds: verifyResponse validates HTTP 200 and latency thresholds', () => {
  const okRes = { status: 200, timings: { duration: 120 }, body: '{"ok":true}' };
  const slowRes = { status: 200, timings: { duration: 950 }, body: '{"ok":true}' };

  assert.equal(verifyResponse(okRes, null, 300), true);
  assert.equal(verifyResponse(slowRes, null, 300), false);

  const checks = createStandardChecks(250);
  assert.equal(checks['status 200'](okRes), true);
  assert.equal(checks['latency < 250ms'](okRes), true);
});

test('src/har-converter: redacts PII headers, cookies, and query tokens while generating ES-module k6 code', () => {
  const sampleHar = {
    log: {
      pages: [{ id: 'page_1', title: 'globlex-rfq-flow' }],
      entries: [
        {
          pageref: 'page_1',
          request: {
            method: 'GET',
            url: 'https://api.globlex.pro/enterprise/overview?access_token=sec-12345&region=eu',
            headers: [
              { name: 'Accept', value: 'application/json' },
              { name: 'Authorization', value: 'Bearer secret-jwt-token' },
              { name: 'Cookie', value: 'session_id=xyz987' },
              { name: 'X-API-Key', value: 'glx_live_secret' },
            ],
            cookies: [{ name: 'session_id', value: 'xyz987' }],
          },
        },
        {
          pageref: 'page_1',
          request: {
            method: 'POST',
            url: 'https://api.globlex.pro/quote-parse/',
            headers: [{ name: 'Content-Type', value: 'application/json' }],
            postData: {
              text: JSON.stringify({
                rfqText: '10x Juniper EX4300',
                api_key: 'should-be-redacted',
              }),
            },
          },
        },
        {
          pageref: 'page_1',
          request: {
            method: 'GET',
            url: 'https://globlex.shop/assets/logo.png',
            headers: [],
          },
        },
      ],
    },
  };

  const { script, stats } = convertHarToK6(sampleHar, { profile: 'smoke' });

  assert.equal(stats.totalEntries, 3);
  assert.equal(stats.convertedRequests, 2); // static png filtered out
  assert.ok(stats.redactedHeaders >= 3);
  assert.deepEqual(stats.groups, ['globlex-rfq-flow']);

  assert.match(script, /import http from 'k6\/http';/);
  assert.match(script, /group\('globlex-rfq-flow'/);
  assert.match(script, /check\(res, \{ 'status 200': \(r\) => r\.status === 200 \}\);/);
  assert.match(script, /access_token=REDACTED/);
  assert.ok(!script.includes('secret-jwt-token'));
  assert.ok(!script.includes('xyz987'));
  assert.ok(!script.includes('glx_live_secret'));
  assert.ok(!script.includes('should-be-redacted'));
});

test('scenarios: globlex-enterprise-slo.js and perfops-gateway-slo.js contain required target surfaces', async () => {
  const globlexCode = await fs.readFile(
    path.join(repoRoot, 'scenarios/globlex-enterprise-slo.js'),
    'utf8'
  );
  for (const target of [
    'globlex.shop',
    'globlex.pro',
    'globlex.online',
    '/health',
    '/enterprise/overview',
    '/quote-parse/',
  ]) {
    assert.ok(globlexCode.includes(target), `Expected ${target} in globlex-enterprise-slo.js`);
  }

  const perfopsCode = await fs.readFile(
    path.join(repoRoot, 'scenarios/perfops-gateway-slo.js'),
    'utf8'
  );
  for (const target of ['perfops.tech', 'perfops.shop', 'aco.perfops.shop']) {
    assert.ok(perfopsCode.includes(target), `Expected ${target} in perfops-gateway-slo.js`);
  }
});

test('src/server.js: HTTP endpoints /health, /api/v1/scenarios, and /api/v1/har-to-k6 work end-to-end', async () => {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const healthRes = await fetch(`${baseUrl}/health`);
    assert.equal(healthRes.status, 200);
    const healthData = await healthRes.json();
    assert.equal(healthData.status, 'ok');
    assert.equal(healthData.service, 'k6-load-suite');

    const scenariosRes = await fetch(`${baseUrl}/api/v1/scenarios?profile=stress`);
    assert.equal(scenariosRes.status, 200);
    const scenariosData = await scenariosRes.json();
    assert.equal(scenariosData.scenarios.length, 2);
    assert.ok(scenariosData.thresholdProfiles.stress);
    assert.ok(scenariosData.resolvedOptions.thresholds);

    const convertRes = await fetch(`${baseUrl}/api/v1/har-to-k6`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        profile: 'smoke',
        har: {
          log: {
            entries: [
              {
                request: {
                  method: 'GET',
                  url: 'https://perfops.tech/api/health',
                  headers: [{ name: 'Authorization', value: 'Bearer secret123' }],
                },
              },
            ],
          },
        },
      }),
    });
    assert.equal(convertRes.status, 200);
    const convertData = await convertRes.json();
    assert.equal(convertData.status, 'converted');
    assert.equal(convertData.stats.convertedRequests, 1);
    assert.equal(convertData.stats.redactedHeaders, 1);
    assert.ok(convertData.script.includes("http.get('https://perfops.tech/api/health')"));
    assert.ok(!convertData.script.includes('secret123'));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('sanitizeUrl and sanitizeHeaders handle edge cases cleanly', () => {
  assert.equal(
    sanitizeUrl('https://perfops.tech/callback?token=abc&ok=1'),
    'https://perfops.tech/callback?token=REDACTED&ok=1'
  );
  const { cleanHeaders, redactedCount } = sanitizeHeaders([
    { name: ':authority', value: 'perfops.tech' },
    { name: 'X-Auth-Token', value: 'sensitive' },
    { name: 'Accept-Language', value: 'en-US' },
  ]);
  assert.equal(redactedCount, 1);
  assert.deepEqual(cleanHeaders, { 'Accept-Language': 'en-US' });
});

test('src/server.js: parseSwaggerEndpoints and generateK6ScriptFromSwagger parse OpenAPI 3, Swagger 2, and endpoint lists', () => {
  const openapiSpec = {
    openapi: '3.0.0',
    servers: [{ url: 'https://api.globlex.pro/v1' }],
    paths: {
      '/orders/{orderId}': {
        get: {
          summary: 'Get Order',
          tags: ['Orders'],
          headers: [{ name: 'Authorization', value: 'Bearer secret_token' }],
        },
        post: {
          summary: 'Create Order',
          tags: ['Orders'],
          requestBody: {
            content: {
              'application/json': {
                example: { sku: 'EX4300', qty: 5 },
              },
            },
          },
        },
      },
    },
  };

  const { baseUrl, endpoints } = parseSwaggerEndpoints(openapiSpec);
  assert.equal(baseUrl, 'https://api.globlex.pro/v1');
  assert.equal(endpoints.length, 2);
  assert.equal(endpoints[0].method, 'GET');
  assert.equal(endpoints[0].url, 'https://api.globlex.pro/v1/orders/1');
  assert.equal(endpoints[0].group, 'Orders');
  assert.ok(!JSON.stringify(endpoints[0].headers).includes('secret_token'));

  assert.equal(endpoints[1].method, 'POST');
  assert.deepEqual(endpoints[1].body, { sku: 'EX4300', qty: 5 });

  const script = generateK6ScriptFromSwagger(endpoints, { profile: 'baseline' });
  assert.match(script, /import http from 'k6\/http';/);
  assert.match(script, /import \{ check, group, sleep \} from 'k6';/);
  assert.match(script, /group\('Orders'/);
  assert.match(script, /http\.get\('https:\/\/api\.globlex\.pro\/v1\/orders\/1'/);
  assert.match(script, /http\.post\('https:\/\/api\.globlex\.pro\/v1\/orders\/1'/);
  assert.match(script, /check\(res, \{ 'status 200': \(r\) => r\.status === 200 \}\);/);
});

test('src/server.js: POST /api/swagger-to-k6 generates deterministic script and executes fast smoke probe with verdict GO', async () => {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. OpenAPI 3.0 spec probing /health and /api/v1/scenarios
    const openapiPayload = {
      openapi: '3.0.0',
      servers: [{ url: baseUrl }],
      paths: {
        '/health': {
          get: {
            summary: 'Service Health',
            tags: ['health-check'],
          },
        },
        '/api/v1/scenarios': {
          get: {
            summary: 'Scenario Catalog',
            tags: ['scenarios-catalog'],
          },
        },
      },
    };

    const res = await fetch(`${baseUrl}/api/swagger-to-k6`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(openapiPayload),
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'ok');
    assert.equal(data.verdict, 'GO');
    assert.equal(data.endpoints_count, 2);

    // Verify k6 script structure
    assert.ok(data.k6_script, 'Expected k6_script in response');
    assert.match(data.k6_script, /import http from 'k6\/http';/);
    assert.match(data.k6_script, /import \{ check, group, sleep \} from 'k6';/);
    assert.match(data.k6_script, /group\('health-check'/);
    assert.match(data.k6_script, /group\('scenarios-catalog'/);
    assert.match(data.k6_script, /check\(res, \{ 'status 200': \(r\) => r\.status === 200 \}\);/);

    // Verify smoke metrics
    assert.ok(data.smoke_metrics, 'Expected smoke_metrics in response');
    assert.equal(data.smoke_metrics.http_reqs, 2);
    assert.equal(data.smoke_metrics.successful_probes, 2);
    assert.equal(data.smoke_metrics.failed_probes, 0);
    assert.equal(data.smoke_metrics.checks_rate, 1.0);
    assert.equal(data.smoke_metrics.http_req_failed_rate, 0.0);
    assert.deepEqual(data.smoke_metrics.status_codes, [200, 200]);
    assert.ok(typeof data.smoke_metrics.duration_ms === 'number');
    assert.ok(typeof data.smoke_metrics.http_req_duration_p95 === 'number');

    // 2. Endpoint list payload
    const listRes = await fetch(`${baseUrl}/api/swagger-to-k6`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl,
        endpoints: [{ path: '/health', method: 'GET' }],
      }),
    });
    assert.equal(listRes.status, 200);
    const listData = await listRes.json();
    assert.equal(listData.status, 'ok');
    assert.equal(listData.verdict, 'GO');
    assert.equal(listData.smoke_metrics.http_reqs, 1);
    assert.equal(listData.smoke_metrics.successful_probes, 1);

    // 3. Failing endpoint results in verdict NO-GO
    const failRes = await fetch(`${baseUrl}/api/swagger-to-k6`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl,
        endpoints: [{ path: '/non-existent-probe-route', method: 'GET' }],
      }),
    });
    assert.equal(failRes.status, 200);
    const failData = await failRes.json();
    assert.equal(failData.verdict, 'NO-GO');
    assert.equal(failData.smoke_metrics.failed_probes, 1);
    assert.deepEqual(failData.smoke_metrics.status_codes, [404]);

    // 4. Invalid spec returns 400
    const badRes = await fetch(`${baseUrl}/api/swagger-to-k6`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ invalid: true }),
    });
    assert.equal(badRes.status, 400);
    const badData = await badRes.json();
    assert.ok(badData.error);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

