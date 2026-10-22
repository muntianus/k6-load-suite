import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ROUTES } from '../src/server.js';

const spec = JSON.parse(readFileSync(new URL('../docs/api/openapi.json', import.meta.url), 'utf8'));
const METHODS = new Set(['get', 'put', 'post', 'delete', 'patch', 'head', 'options']);

function specOperations() {
  return Object.entries(spec.paths).flatMap(([path, item]) =>
    Object.keys(item)
      .filter((key) => METHODS.has(key))
      .map((method) => ({ key: `${method.toUpperCase()} ${path}`, op: item[method] })),
  );
}

test('spec is OpenAPI 3.x', () => {
  assert.match(spec.openapi, /^3\.\d+\.\d+$/);
});

test('every served route is documented and every documented route is served', () => {
  const served = ROUTES.map((r) => `${r.method} ${r.path}`).sort();
  const documented = specOperations().map((o) => o.key).sort();
  assert.deepEqual(documented, served);
});

test('every operation has an operationId, a summary and a 2xx response', () => {
  const ids = new Set();
  for (const { key, op } of specOperations()) {
    assert.ok(op.operationId, `${key} lacks operationId`);
    assert.ok(!ids.has(op.operationId), `duplicate operationId ${op.operationId}`);
    ids.add(op.operationId);
    assert.ok(op.summary, `${key} lacks summary`);
    assert.ok(Object.keys(op.responses).some((code) => code.startsWith('2')), `${key} lacks a 2xx response`);
  }
});

test('JSON request bodies carry an example', () => {
  for (const { key, op } of specOperations()) {
    const media = op.requestBody?.content?.['application/json'];
    if (media) assert.ok(media.example ?? media.examples, `${key} request body lacks an example`);
  }
});
