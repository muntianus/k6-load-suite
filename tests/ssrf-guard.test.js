import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_MAX_RESPONSE_BYTES,
  SsrfError,
  assertSafeUrl,
  isAllowlisted,
  isBlockedAddress,
  isBlockedHostname,
  parseAllowlist,
  resolveAndValidate,
  safeFetch,
} from '../src/url-guard.js';
import { createServer } from '../src/server.js';

const PUBLIC_LOOKUP = async () => [{ address: '93.184.216.34', family: 4 }];

function jsonResponse(payload, init = {}) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
}

test('url-guard: blocks loopback, private, link-local, metadata, and IPv6 local ranges', () => {
  const blocked = [
    '127.0.0.1',
    '127.10.20.30',
    '0.0.0.0',
    '10.0.0.5',
    '10.255.255.255',
    '172.16.0.1',
    '172.31.255.254',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '::1',
    '::',
    'fc00::1',
    'fd12:3456::1',
    'fe80::1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    '64:ff9b::a9fe:a9fe',
  ];

  for (const address of blocked) {
    assert.equal(isBlockedAddress(address), true, `expected ${address} to be blocked`);
  }

  for (const address of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111']) {
    assert.equal(isBlockedAddress(address), false, `expected ${address} to be allowed`);
  }
});

test('url-guard: blocks localhost, .local, .internal, and metadata hostnames', () => {
  for (const host of ['localhost', 'LOCALHOST.', 'api.localhost', 'printer.local', 'metadata.google.internal']) {
    assert.equal(isBlockedHostname(host), true, `expected ${host} to be blocked`);
  }
  assert.equal(isBlockedHostname('api.globlex.pro'), false);
});

test('url-guard: assertSafeUrl rejects file://, non-http schemes, private IPs, and local hosts', () => {
  const rejected = [
    ['file:///etc/passwd', /scheme/i],
    ['ftp://example.com/spec.json', /scheme/i],
    ['gopher://example.com/', /scheme/i],
    ['http://169.254.169.254/latest/meta-data/', /private or reserved/i],
    ['http://127.0.0.1:4040/health', /private or reserved/i],
    ['http://[::1]:4040/health', /private or reserved/i],
    ['http://10.1.2.3/openapi.json', /private or reserved/i],
    ['http://localhost:4040/health', /local or internal/i],
    ['http://metadata.google.internal/computeMetadata/v1/', /local or internal/i],
    ['http://specs.local/openapi.json', /local or internal/i],
    ['not-a-url', /invalid url/i],
  ];

  for (const [url, pattern] of rejected) {
    assert.throws(
      () => assertSafeUrl(url, { allowlist: [] }),
      (err) => err instanceof SsrfError && err.statusCode === 400 && pattern.test(err.message),
      `expected ${url} to be rejected`
    );
  }

  const { host } = assertSafeUrl('https://api.globlex.pro/v1/openapi.json', { allowlist: [] });
  assert.equal(host, 'api.globlex.pro');
});

test('url-guard: SWAGGER_FETCH_ALLOWLIST restricts hosts and can explicitly opt in loopback', () => {
  assert.deepEqual(parseAllowlist(' Example.com, *.globlex.pro , '), ['example.com', '*.globlex.pro']);
  assert.deepEqual(parseAllowlist(''), []);
  assert.deepEqual(parseAllowlist(undefined), []);

  const allowlist = ['example.com', '*.globlex.pro', '127.0.0.1'];
  assert.equal(isAllowlisted('example.com', allowlist), true);
  assert.equal(isAllowlisted('api.globlex.pro', allowlist), true);
  assert.equal(isAllowlisted('globlex.pro.evil.test', allowlist), false);

  assert.throws(() => assertSafeUrl('https://other.test/spec', { allowlist: ['example.com'] }), SsrfError);
  assert.doesNotThrow(() => assertSafeUrl('https://api.globlex.pro/spec', { allowlist }));
  // Explicit operator opt-in is the only way loopback stays reachable (used by local tests).
  assert.doesNotThrow(() => assertSafeUrl('http://127.0.0.1:4040/health', { allowlist: ['127.0.0.1'] }));
});

test('url-guard: DNS answers pointing at private ranges are rejected (rebinding protection)', async () => {
  await assert.rejects(
    resolveAndValidate('rebind.example.com', {
      allowlist: [],
      lookupImpl: async () => [
        { address: '93.184.216.34', family: 4 },
        { address: '10.0.0.7', family: 4 },
      ],
    }),
    (err) => err instanceof SsrfError && /resolves to private or reserved address 10\.0\.0\.7/.test(err.message)
  );

  await assert.rejects(
    resolveAndValidate('v6.example.com', {
      allowlist: [],
      lookupImpl: async () => [{ address: 'fd00::1', family: 6 }],
    }),
    SsrfError
  );

  const ok = await resolveAndValidate('api.example.com', { allowlist: [], lookupImpl: PUBLIC_LOOKUP });
  assert.deepEqual(ok, [{ address: '93.184.216.34', family: 4 }]);

  await assert.rejects(
    resolveAndValidate('missing.example.com', {
      allowlist: [],
      lookupImpl: async () => {
        throw new Error('ENOTFOUND');
      },
    }),
    (err) => err.code === 'ENOTFOUND'
  );
});

test('url-guard: safeFetch performs a successful mocked request without touching the network', async () => {
  let calledWith;
  const fetchImpl = async (url, init) => {
    calledWith = { url, init };
    return jsonResponse({ ok: true });
  };

  const res = await safeFetch('https://api.example.com/v1/spec.json', {
    fetchImpl,
    lookupImpl: PUBLIC_LOOKUP,
    allowlist: [],
    headers: { Accept: 'application/json' },
    timeoutMs: 1000,
  });

  assert.equal(res.status, 200);
  assert.deepEqual(res.json(), { ok: true });
  assert.equal(calledWith.url, 'https://api.example.com/v1/spec.json');
  assert.equal(calledWith.init.redirect, 'manual');
});

test('url-guard: safeFetch blocks private/metadata targets before calling fetch', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return jsonResponse({});
  };

  for (const url of ['http://169.254.169.254/latest/meta-data/', 'http://127.0.0.1/', 'file:///etc/passwd']) {
    await assert.rejects(
      safeFetch(url, { fetchImpl, lookupImpl: PUBLIC_LOOKUP, allowlist: [] }),
      SsrfError,
      `expected ${url} to be blocked`
    );
  }
  assert.equal(calls, 0, 'no outbound request should be made');
});

test('url-guard: safeFetch rejects redirects to private addresses and allows public redirects', async () => {
  let calls = 0;
  const redirectToMetadata = async () => {
    calls += 1;
    return new Response(null, {
      status: 302,
      headers: { Location: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' },
    });
  };

  await assert.rejects(
    safeFetch('https://example.com/spec.json', {
      fetchImpl: redirectToMetadata,
      lookupImpl: PUBLIC_LOOKUP,
      allowlist: [],
    }),
    (err) => err instanceof SsrfError && /private or reserved/i.test(err.message) && /169\.254\.169\.254/.test(err.message)
  );
  assert.equal(calls, 1);

  const responses = [
    new Response(null, { status: 302, headers: { Location: '/v2/spec.json' } }),
    jsonResponse({ redirected: true }),
  ];
  const res = await safeFetch('https://example.com/spec.json', {
    fetchImpl: async () => responses.shift(),
    lookupImpl: PUBLIC_LOOKUP,
    allowlist: [],
  });
  assert.equal(res.status, 200);
  assert.deepEqual(res.json(), { redirected: true });
  assert.equal(res.url, 'https://example.com/v2/spec.json');
});

test('url-guard: safeFetch enforces the response size cap', async () => {
  const oversized = new Response(Buffer.alloc(DEFAULT_MAX_RESPONSE_BYTES + 1024, 0x61), {
    status: 200,
  });

  await assert.rejects(
    safeFetch('https://api.example.com/big', {
      fetchImpl: async () => oversized,
      lookupImpl: PUBLIC_LOOKUP,
      allowlist: [],
    }),
    (err) => err.code === 'RESPONSE_TOO_LARGE' && err.statusCode === 413
  );
});

test('url-guard: safeFetch enforces the timeout', async () => {
  const hangingFetch = (_url, init) =>
    new Promise((_, reject) => {
      init.signal.addEventListener('abort', () =>
        reject(Object.assign(new Error('aborted'), { name: 'AbortError' }))
      );
    });

  await assert.rejects(
    safeFetch('https://api.example.com/slow', {
      fetchImpl: hangingFetch,
      lookupImpl: PUBLIC_LOOKUP,
      allowlist: [],
      timeoutMs: 50,
    }),
    (err) => err.code === 'ETIMEDOUT' && err.name === 'TimeoutError'
  );
});

test('src/server.js: POST /api/v1/swagger-to-k6 returns 400 for metadata/private baseUrl without fetching', async () => {
  const previousAllowlist = process.env.SWAGGER_FETCH_ALLOWLIST;
  delete process.env.SWAGGER_FETCH_ALLOWLIST;

  const server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const serviceUrl = `http://127.0.0.1:${port}`;

  try {
    for (const baseUrl of ['http://169.254.169.254', 'http://10.0.0.10:8080', 'http://localhost:4040']) {
      const res = await fetch(`${serviceUrl}/api/v1/swagger-to-k6`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ baseUrl, endpoints: [{ path: '/latest/meta-data/', method: 'GET' }] }),
      });
      assert.equal(res.status, 400, `expected 400 for ${baseUrl}`);
      const data = await res.json();
      assert.match(data.error, /blocked/i);
    }

    // Absolute endpoint URLs are validated too, not only baseUrl.
    const absoluteRes = await fetch(`${serviceUrl}/api/v1/swagger-to-k6`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://api.example.com',
        endpoints: [{ url: 'http://127.0.0.1:22/', method: 'GET' }],
      }),
    });
    assert.equal(absoluteRes.status, 400);
    assert.match((await absoluteRes.json()).error, /private or reserved/i);

    // Mock probe performs no outbound request, so offline conversion stays usable.
    const mockRes = await fetch(`${serviceUrl}/api/v1/swagger-to-k6`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'http://127.0.0.1:4040',
        endpoints: [{ path: '/health', method: 'GET' }],
        mockProbe: true,
      }),
    });
    assert.equal(mockRes.status, 200);
    const mockData = await mockRes.json();
    assert.equal(mockData.verdict, 'GO');
    assert.equal(mockData.smoke_metrics.http_reqs, 1);
  } finally {
    if (previousAllowlist === undefined) {
      delete process.env.SWAGGER_FETCH_ALLOWLIST;
    } else {
      process.env.SWAGGER_FETCH_ALLOWLIST = previousAllowlist;
    }
    await new Promise((resolve) => server.close(resolve));
  }
});
