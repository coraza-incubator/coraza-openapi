// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { IdAllocator } from './ids.js';

describe('IdAllocator', () => {
  it('is monotonic', () => {
    const a = new IdAllocator(1000, 100);
    expect(a.next()).toBe(1000);
    expect(a.next()).toBe(1001);
    expect(a.next()).toBe(1002);
  });
  it('advances to section boundary', () => {
    const a = new IdAllocator(1000, 100);
    a.next();
    a.next();
    a.advanceSection();
    expect(a.peek()).toBe(1100);
  });
  it('no-ops when already aligned', () => {
    const a = new IdAllocator(1000, 100);
    a.advanceSection();
    expect(a.peek()).toBe(1000);
  });
});