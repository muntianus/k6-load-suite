import http from 'k6/http';
import { check, group } from 'k6';

export const options = {
  vus: 1,
  duration: '10s',
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<500'],
  },
};

export default function () {
  group('globlex-b2b-health', () => {
    const res = http.get('https://globlex.pro/api/health');
    check(res, { 'status 200': (r) => r.status === 200 });
  });
}
