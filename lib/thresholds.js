/**
 * Reusable SLO threshold profiles and check helpers for PerfOps & Globex k6 load scenarios.
 */

export const THRESHOLD_PROFILES = Object.freeze({
  smoke: {
    vus: 1,
    duration: '10s',
    thresholds: {
      http_req_failed: ['rate<0.01'],
      http_req_duration: ['p(95)<400', 'p(99)<800'],
      checks: ['rate>0.99'],
    },
  },
  baseline: {
    stages: [
      { duration: '30s', target: 10 },
      { duration: '1m', target: 10 },
      { duration: '15s', target: 0 },
    ],
    thresholds: {
      http_req_failed: ['rate<0.01'],
      http_req_duration: ['p(90)<300', 'p(95)<450', 'p(99)<900'],
      checks: ['rate>0.99'],
    },
  },
  stress: {
    stages: [
      { duration: '30s', target: 25 },
      { duration: '1m', target: 50 },
      { duration: '30s', target: 100 },
      { duration: '30s', target: 0 },
    ],
    thresholds: {
      http_req_failed: ['rate<0.025'],
      http_req_duration: ['p(95)<750', 'p(99)<1500'],
      checks: ['rate>0.97'],
    },
  },
  spike: {
    stages: [
      { duration: '10s', target: 5 },
      { duration: '15s', target: 120 },
      { duration: '30s', target: 120 },
      { duration: '15s', target: 5 },
      { duration: '10s', target: 0 },
    ],
    thresholds: {
      http_req_failed: ['rate<0.05'],
      http_req_duration: ['p(95)<1200', 'p(99)<2500'],
      checks: ['rate>0.95'],
    },
  },
});

/**
 * Builds a complete k6 options object from a named profile and optional overrides.
 * @param {string} profileName - 'smoke' | 'baseline' | 'stress' | 'spike'
 * @param {object} [overrides] - Custom thresholds or tags
 * @returns {object}
 */
export function buildOptions(profileName = 'smoke', overrides = {}) {
  const base = THRESHOLD_PROFILES[profileName] || THRESHOLD_PROFILES.smoke;
  const cloned = JSON.parse(JSON.stringify(base));

  if (overrides.thresholds) {
    cloned.thresholds = {
      ...cloned.thresholds,
      ...overrides.thresholds,
    };
  }

  if (overrides.tags) {
    cloned.tags = { ...(cloned.tags || {}), ...overrides.tags };
  }

  if (typeof overrides.vus === 'number') {
    cloned.vus = overrides.vus;
  }

  if (typeof overrides.duration === 'string') {
    cloned.duration = overrides.duration;
  }

  return cloned;
}

/**
 * Standard k6 check descriptors for HTTP status & latency guardrails.
 * @param {number} [maxLatencyMs=500]
 * @returns {Record<string, (r: any) => boolean>}
 */
export function createStandardChecks(maxLatencyMs = 500) {
  return {
    'status 200': (r) => r && r.status === 200,
    [`latency < ${maxLatencyMs}ms`]: (r) =>
      r && typeof r.timings?.duration === 'number'
        ? r.timings.duration < maxLatencyMs
        : true,
    'non-empty body': (r) =>
      r && typeof r.body === 'string' ? r.body.length > 0 : Boolean(r?.body),
  };
}

/**
 * Evaluates a response object against standard checks (callable both in k6 and Node tests).
 * @param {object} response
 * @param {(res: object, checks: object) => boolean} [k6CheckFn]
 * @param {number} [maxLatencyMs=500]
 * @returns {boolean}
 */
export function verifyResponse(response, k6CheckFn, maxLatencyMs = 500) {
  const checks = createStandardChecks(maxLatencyMs);
  if (typeof k6CheckFn === 'function') {
    return k6CheckFn(response, checks);
  }
  return Object.values(checks).every((fn) => fn(response));
}
