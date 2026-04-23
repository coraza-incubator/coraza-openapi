// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runValidate } from './validate.js';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { petstoreYaml } from '@coraza-openapi/core/samples';

describe('runValidate', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'coraza-val-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('succeeds on valid spec', async () => {
    const p = join(dir, 'spec.yaml');
    await writeFile(p, petstoreYaml);
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await runValidate(p, {});
    err.mockRestore();
    expect(code).toBe(0);
  });

  it('fails on invalid spec', async () => {
    const p = join(dir, 'bad.yaml');
    await writeFile(p, ':::');
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await runValidate(p, {});
    err.mockRestore();
    expect(code).toBe(1);
  });

  it('fails under --strict on info diagnostics when none produce warnings', async () => {
    const p = join(dir, 'empty.yaml');
    await writeFile(p, 'openapi: 3.0.0\ninfo: { title: t, version: "1.0.0" }\npaths: {}');
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await runValidate(p, { strict: true });
    err.mockRestore();
    expect(code).toBe(2);
  });
});