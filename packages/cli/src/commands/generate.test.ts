// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runGenerate } from './generate.js';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { petstoreYaml } from '@coraza-openapi/core/samples';

describe('runGenerate', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'coraza-cli-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('writes rules to output file', async () => {
    const inPath = join(dir, 'spec.yaml');
    const outPath = join(dir, 'rules.conf');
    await writeFile(inPath, petstoreYaml);
    const code = await runGenerate(inPath, { output: outPath });
    expect(code).toBe(0);
    const out = await readFile(outPath, 'utf8');
    expect(out).toContain('SecRule');
    expect(out).toContain('listPets');
  });

  it('errors on malformed input', async () => {
    const inPath = join(dir, 'bad.yaml');
    await writeFile(inPath, ':\n::\n:');
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await runGenerate(inPath, {});
    expect(code).toBe(1);
    stderr.mockRestore();
  });

  it('reads from stdin with "-"', async () => {
    const outPath = join(dir, 'rules.conf');
    // Mock process.stdin as an async iterable
    const original = Object.getOwnPropertyDescriptor(process, 'stdin');
    const fake = (async function* () {
      yield Buffer.from(petstoreYaml);
    })() as unknown as NodeJS.ReadStream;
    Object.defineProperty(process, 'stdin', { value: fake, configurable: true });
    try {
      const code = await runGenerate('-', { output: outPath });
      expect(code).toBe(0);
      const out = await readFile(outPath, 'utf8');
      expect(out).toContain('SecRule');
    } finally {
      if (original) Object.defineProperty(process, 'stdin', original);
    }
  });

  it('--strict exits non-zero with warnings', async () => {
    const inPath = join(dir, 'empty.yaml');
    await writeFile(inPath, 'openapi: 3.0.0\ninfo: { title: t, version: "1.0.0" }\npaths: {}');
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await runGenerate(inPath, { strict: true });
    err.mockRestore();
    expect(code).toBe(2);
  });

  it('emits json format', async () => {
    const inPath = join(dir, 'spec.yaml');
    const outPath = join(dir, 'rules.json');
    await writeFile(inPath, petstoreYaml);
    const code = await runGenerate(inPath, { format: 'json', output: outPath });
    expect(code).toBe(0);
    const parsed = JSON.parse(await readFile(outPath, 'utf8'));
    expect(parsed.entries).toBeInstanceOf(Array);
    expect(parsed.ruleCount).toBeGreaterThan(0);
  });
});