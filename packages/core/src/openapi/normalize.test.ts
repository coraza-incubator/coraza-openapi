// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { parseSpec } from './parse.js';
import { normalize, pathToRegex } from './normalize.js';
import { petstoreYaml } from '../samples/index.js';

describe('normalize', () => {
  it('extracts operations from petstore', async () => {
    const p = await parseSpec(petstoreYaml);
    if (!p.ok) throw new Error(p.error);
    const n = normalize(p.doc, p.rawHash);
    expect(n.title).toBe('Petstore');
    expect(n.operations.length).toBe(5);
    const listPets = n.operations.find((op) => op.operationId === 'listPets');
    expect(listPets?.method).toBe('GET');
    expect(listPets?.parameters.find((p) => p.name === 'status')?.required).toBe(true);
  });

  it('parses servers and extracts host', async () => {
    const p = await parseSpec(petstoreYaml);
    if (!p.ok) throw new Error(p.error);
    const n = normalize(p.doc, p.rawHash);
    expect(n.servers[0].host).toBe('petstore.example.com');
    expect(n.servers[0].basePath).toBe('/api/v1');
  });

  it('detects deprecated operations', async () => {
    const p = await parseSpec(petstoreYaml);
    if (!p.ok) throw new Error(p.error);
    const n = normalize(p.doc, p.rawHash);
    expect(n.operations.find((op) => op.operationId === 'deletePet')?.deprecated).toBe(true);
  });

  it('handles empty paths', async () => {
    const empty = `openapi: 3.0.0\ninfo: { title: t, version: "1.0.0" }\npaths: {}`;
    const p = await parseSpec(empty);
    if (!p.ok) throw new Error(p.error);
    const n = normalize(p.doc, p.rawHash);
    expect(n.operations.length).toBe(0);
    expect(n.diagnostics.some((d) => d.level === 'warn')).toBe(true);
  });
});

describe('pathToRegex', () => {
  it('handles plain paths', () => {
    expect(pathToRegex('/pets', [])).toBe('^/pets(?:\\?.*)?$');
  });
  it('expands integer params', () => {
    const r = pathToRegex('/users/{id}', [
      { name: 'id', in: 'path', required: true, deprecated: false, schema: { type: 'integer' } },
    ]);
    expect(r).toContain('-?\\d+');
  });
  it('expands enum params', () => {
    const r = pathToRegex('/s/{kind}', [
      { name: 'kind', in: 'path', required: true, deprecated: false, schema: { type: 'string', enum: ['a', 'b'] } },
    ]);
    expect(r).toContain('(?:a|b)');
  });
  it('expands uuid format', () => {
    const r = pathToRegex('/x/{id}', [
      { name: 'id', in: 'path', required: true, deprecated: false, schema: { type: 'string', format: 'uuid' } },
    ]);
    expect(r).toContain('[0-9a-fA-F]{8}');
  });
  it('escapes literal dots', () => {
    expect(pathToRegex('/a.b', [])).toContain('\\.');
  });
});