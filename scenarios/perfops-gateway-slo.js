import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { buildOptions, createStandardChecks } from '../lib/thresholds.js';

const PROFILE = typeof __ENV !== 'undefined' && __ENV.K6_PROFILE ? __ENV.K6_PROFILE : 'smoke';
const PERFOPS_TECH_URL =
  typeof __ENV !== 'undefined' && __ENV.PERFOPS_TECH_URL
    ? __ENV.PERFOPS_TECH_URL
    : 'https://perfops.tech';
const PERFOPS_SHOP_URL =
  typeof __ENV !== 'undefined' && __ENV.PERFOPS_SHOP_URL
    ? __ENV.PERFOPS_SHOP_URL
    : 'https://perfops.shop';
const ACO_PERFOPS_URL =
  typeof __ENV !== 'undefined' && __ENV.ACO_PERFOPS_URL
    ? __ENV.ACO_PERFOPS_URL
    : 'https://aco.perfops.shop';

export const options = buildOptions(PROFILE, {
  tags: {
    suite: 'perfops-gateway-slo',
    service: 'perfops-edge',
  },
  thresholds: {
    'http_req_duration{group:::perfops-tech-portal}': ['p(95)<400'],
    'http_req_duration{group:::perfops-shop-surface}': ['p(95)<450'],
    'http_req_duration{group:::aco-control-plane-health}': ['p(95)<250'],
  },
});

export default function () {
  group('perfops-tech-portal', () => {
    const res = http.get(`${PERFOPS_TECH_URL}/`, {
      tags: { surface: 'perfops.tech' },
    });
    check(res, createStandardChecks(400));
  });

  group('perfops-shop-surface', () => {
    const res = http.get(`${PERFOPS_SHOP_URL}/`, {
      tags: { surface: 'perfops.shop' },
    });
    check(res, createStandardChecks(450));
  });

  group('aco-control-plane-health', () => {
    const res = http.get(`${ACO_PERFOPS_URL}/health`, {
      tags: { surface: 'aco.perfops.shop/health' },
    });
    check(res, {
      ...createStandardChecks(250),
      'status 200': (r) => r.status === 200,
    });
  });

  sleep(1);
}
