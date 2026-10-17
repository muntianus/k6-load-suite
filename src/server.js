import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { THRESHOLD_PROFILES, buildOptions } from '../lib/thresholds.js';
import { convertHarToK6 } from './har-converter.js';

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
