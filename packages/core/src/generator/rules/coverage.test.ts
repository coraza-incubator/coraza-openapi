// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { generateFromText, ConfigSchema, defaultConfig } from '../../index.js';
import { petstoreYaml } from '../../samples/index.js';

const specWithXCoraza = `
openapi: 3.0.3
info: { title: X, version: "1.0.0" }
servers:
  - url: https://api.example.com
paths:
  /slow:
    get:
      operationId: slow
      x-coraza-rate-limit: 100/min
      responses: { '200': { description: OK } }
  /skip:
    get:
      operationId: skipMe
      x-coraza-skip: true
      responses: { '200': { description: OK } }
  /params/{id}:
    parameters:
      - { name: id, in: path, required: true, schema: { type: integer } }
      - { name: token, in: header, required: true, schema: { type: string, minLength: 8, maxLength: 32 } }
      - { name: kind, in: query, schema: { type: string, enum: [a, b, c] } }
      - { name: pat, in: query, schema: { type: string, pattern: '^[A-Z]+$' } }
      - { name: amt, in: query, schema: { type: number } }
      - { name: trace, in: query, schema: { type: string, format: uuid } }
    get:
      operationId: getParams
      responses: { '200': { description: OK } }
`;

describe('edge-case rule coverage', () => {
  it('emits rate-limit hints', async () => {
    const cfg = ConfigSchema.parse({ advanced: { emitRateLimitHints: true, emitCorsHints: true } });
    const r = await generateFromText(specWithXCoraza, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).toContain('rate-limit: 100/min');
    expect(r.seclang).toContain('Suggested allowed origins');
  });

  it('honors x-coraza-skip', async () => {
    const r = await generateFromText(specWithXCoraza, defaultConfig());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).not.toContain('op/skipMe');
  });

  it('generates param validators for every type, including query-level uuid + regex', async () => {
    const r = await generateFromText(specWithXCoraza, defaultConfig());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).toContain('param/type');
    expect(r.seclang).toContain('param/enum');
    expect(r.seclang).toContain('param/pattern');
    expect(r.seclang).toContain('param/length');
    expect(r.seclang).toContain('param/uuid');
    // The uuid validator fires against the query parameter itself.
    expect(r.seclang).toMatch(/SecRule ARGS_GET:trace[^\n]*\[0-9a-fA-F\]\{8\}/);
    // The regex validator uses the spec's unanchored body.
    expect(r.seclang).toMatch(/SecRule ARGS_GET:pat "!@rx \[A-Z\]\+"/);
  });

  it('strip prefix rewrites matchers', async () => {
    const cfg = ConfigSchema.parse({ routing: { stripPrefix: '/api/v1', addPrefix: '/api/v2' } });
    const r = await generateFromText(petstoreYaml, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).toContain('/api/v1');
    expect(r.seclang).toContain('tx.openapi_strip');
    expect(r.seclang).toContain('tx.openapi_add');
  });

  it('disabling all validation + limits strips those sections', async () => {
    const cfg = ConfigSchema.parse({
      validation: {
        requiredParams: false,
        validateTypes: false,
        validateEnums: false,
        validatePatterns: false,
        validateLengths: false,
        enforceContentType: false,
      },
      advanced: { emitRateLimitHints: false, emitCorsHints: false },
      banner: false,
    });
    const r = await generateFromText(petstoreYaml, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).not.toContain('Parameter validation');
    expect(r.seclang).not.toContain('Title:');
  });

  it('uuid-format path params produce uuid regex', async () => {
    const r = await generateFromText(petstoreYaml, defaultConfig());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).toMatch(/\[0-9a-fA-F\]\{8\}/);
  });

  it('custom header override flows through auth rules', async () => {
    const cfg = ConfigSchema.parse({ auth: { customHeaderName: 'X-Company-Token' } });
    const r = await generateFromText(petstoreYaml, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).toContain('X-Company-Token');
  });
});