import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { buildOptions, createStandardChecks } from '../lib/thresholds.js';

const PROFILE = typeof __ENV !== 'undefined' && __ENV.K6_PROFILE ? __ENV.K6_PROFILE : 'baseline';
const BASE_SHOP_URL =
  typeof __ENV !== 'undefined' && __ENV.GLOBLEX_SHOP_URL
    ? __ENV.GLOBLEX_SHOP_URL
    : 'https://globlex.shop';
const BASE_PRO_URL =
  typeof __ENV !== 'undefined' && __ENV.GLOBLEX_PRO_URL
    ? __ENV.GLOBLEX_PRO_URL
    : 'https://globlex.pro';
const BASE_ONLINE_URL =
  typeof __ENV !== 'undefined' && __ENV.GLOBLEX_ONLINE_URL
    ? __ENV.GLOBLEX_ONLINE_URL
    : 'https://globlex.online';
const BASE_API_URL =
  typeof __ENV !== 'undefined' && __ENV.GLOBLEX_API_URL
    ? __ENV.GLOBLEX_API_URL
    : 'https://api.globlex.pro';

export const options = buildOptions(PROFILE, {
  tags: {
    suite: 'globlex-enterprise-slo',
    service: 'globlex-platform',
  },
  thresholds: {
    'http_req_duration{group:::globlex-web-surfaces}': ['p(95)<500'],
    'http_req_duration{group:::globlex-api-health}': ['p(95)<250'],
    'http_req_duration{group:::globlex-enterprise-overview}': ['p(95)<400'],
    'http_req_duration{group:::globlex-quote-parse}': ['p(95)<600'],
  },
});

export default function () {
  group('globlex-web-surfaces', () => {
    const responses = http.batch([
      ['GET', `${BASE_SHOP_URL}/`, null, { tags: { surface: 'globlex.shop' } }],
      ['GET', `${BASE_PRO_URL}/`, null, { tags: { surface: 'globlex.pro' } }],
      ['GET', `${BASE_ONLINE_URL}/`, null, { tags: { surface: 'globlex.online' } }],
    ]);

    for (const res of responses) {
      check(res, createStandardChecks(500));
    }
  });

  group('globlex-api-health', () => {
    const res = http.get(`${BASE_API_URL}/health`, {
      tags: { endpoint: 'api.globlex.pro/health' },
    });
    check(res, {
      ...createStandardChecks(250),
      'health status ok': (r) => r.status === 200,
    });
  });

  group('globlex-enterprise-overview', () => {
    const res = http.get(`${BASE_API_URL}/enterprise/overview`, {
      tags: { endpoint: 'api.globlex.pro/enterprise/overview' },
    });
    check(res, createStandardChecks(400));
  });

  group('globlex-quote-parse', () => {
    const payload = JSON.stringify({
      rfqText: '20x Cisco Catalyst 9300-24T-A, delivery Frankfurt, net 30',
      currency: 'EUR',
      source: 'k6-slo-probe',
    });
    const params = {
      headers: { 'Content-Type': 'application/json' },
      tags: { endpoint: 'api.globlex.pro/quote-parse/' },
    };
    const res = http.post(`${BASE_API_URL}/quote-parse/`, payload, params);
    check(res, {
      'status 200': (r) => r.status === 200,
      'latency < 600ms': (r) => r.timings.duration < 600,
    });
  });

  sleep(1);
}
