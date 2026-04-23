// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runDiff } from './diff.js';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { petstoreYaml, minimalYaml } from '@coraza-openapi/core/samples';

describe('runDiff', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'coraza-diff-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('prints a markdown diff', async () => {
    const a = join(dir, 'a.yaml');
    const b = join(dir, 'b.yaml');
    await writeFile(a, minimalYaml);
    await writeFile(b, petstoreYaml);
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const code = await runDiff(a, b, {});
    log.mockRestore();
    expect(code).toBe(0);
  });

  it('fails on bad input', async () => {
    const a = join(dir, 'a.yaml');
    const b = join(dir, 'b.yaml');
    await writeFile(a, ':::');
    await writeFile(b, petstoreYaml);
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await runDiff(a, b, {});
    err.mockRestore();
    expect(code).toBe(1);
  });
});