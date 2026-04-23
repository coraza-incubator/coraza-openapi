// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runInitConfig } from './initConfig.js';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('runInitConfig', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'coraza-init-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('writes a default config', async () => {
    const out = join(dir, 'coraza-openapi.config.json');
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await runInitConfig(out);
    err.mockRestore();
    expect(code).toBe(0);
    const content = JSON.parse(await readFile(out, 'utf8'));
    expect(content.startingId).toBe(1_000_000);
    expect(content.routing.enforceHostname).toBe(true);
  });
});