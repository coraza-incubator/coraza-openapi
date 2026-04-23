// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { applyFlagOverrides } from './loadConfig.js';
import { defaultConfig } from '@coraza-openapi/core';

describe('applyFlagOverrides', () => {
  it('overrides starting id', () => {
    const c = applyFlagOverrides(defaultConfig(), { 'starting-id': 5000 });
    expect(c.startingId).toBe(5000);
  });
  it('disables auth with --no-enforce-auth (cac passes enforceAuth:false)', () => {
    const c = applyFlagOverrides(defaultConfig(), { enforceAuth: false });
    expect(c.auth.enforceSecurity).toBe(false);
  });
  it('parses host list', () => {
    const c = applyFlagOverrides(defaultConfig(), { host: 'a.example.com,b.example.com' });
    expect(c.routing.allowedHosts).toEqual(['a.example.com', 'b.example.com']);
  });
  it('sets detection mode', () => {
    const c = applyFlagOverrides(defaultConfig(), { 'detection-only': true });
    expect(c.mode).toBe('standalone-detect');
  });
  it('--crs-plugin flag flips to plugin mode', () => {
    const c = applyFlagOverrides(defaultConfig(), { 'crs-plugin': true });
    expect(c.mode).toBe('crs-plugin');
  });
  it('--mode flag accepts explicit value', () => {
    const c = applyFlagOverrides(defaultConfig(), { mode: 'crs-plugin' });
    expect(c.mode).toBe('crs-plugin');
  });
  it('block-deprecated', () => {
    const c = applyFlagOverrides(defaultConfig(), { 'block-deprecated': true });
    expect(c.routing.deprecatedHandling).toBe('block');
  });
});