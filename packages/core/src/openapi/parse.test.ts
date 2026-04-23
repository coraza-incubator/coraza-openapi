// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { parseSpec } from './parse.js';
import { petstoreYaml, minimalYaml } from '../samples/index.js';

describe('parseSpec', () => {
  it('parses valid YAML', async () => {
    const r = await parseSpec(petstoreYaml);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.doc.info.title).toBe('Petstore');
      expect(Object.keys(r.doc.paths!)).toContain('/pets');
    }
  });

  it('parses minimal spec', async () => {
    const r = await parseSpec(minimalYaml);
    expect(r.ok).toBe(true);
  });

  it('parses JSON', async () => {
    const json = JSON.stringify({
      openapi: '3.0.0',
      info: { title: 'J', version: '1' },
      paths: { '/a': { get: { responses: { '200': { description: 'ok' } } } } },
    });
    const r = await parseSpec(json);
    expect(r.ok).toBe(true);
  });

  it('rejects empty input', async () => {
    const r = await parseSpec('');
    expect(r.ok).toBe(false);
  });

  it('rejects non-object root', async () => {
    const r = await parseSpec('"hello"');
    expect(r.ok).toBe(false);
  });

  it('rejects missing openapi version', async () => {
    const r = await parseSpec('info: { title: x, version: 1 }\npaths: {}');
    expect(r.ok).toBe(false);
  });

  it('rejects malformed YAML', async () => {
    const r = await parseSpec(':\n::\n:');
    expect(r.ok).toBe(false);
  });

  it('converts swagger 2.0 input', async () => {
    const swagger2 = `
swagger: "2.0"
info: { title: Legacy, version: "1.0" }
host: api.example.com
basePath: /v1
schemes: [https]
paths:
  /items:
    get:
      responses:
        "200": { description: OK }
`;
    const r = await parseSpec(swagger2);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.doc.info.title).toBe('Legacy');
  });
});