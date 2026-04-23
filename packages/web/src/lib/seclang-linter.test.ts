// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { lintSeclang } from './seclang-linter.js';

// Mock Monaco's MarkerSeverity.
const monaco = { MarkerSeverity: { Warning: 4, Error: 8 } } as any;

describe('seclang-linter', () => {
  it('is silent on a valid rule', () => {
    const src = `
# some comment
SecAction \\
    "id:1,\\
    phase:1,\\
    pass,\\
    nolog,\\
    t:none,\\
    setvar:'tx.x=1'"

SecRule REQUEST_METHOD "@streq GET" \\
    "id:2,\\
    phase:1,\\
    deny,\\
    status:403,\\
    msg:'hi',\\
    chain"
    SecRule REQUEST_URI_RAW "@rx ^/$" \\
        "t:none"

SecMarker END-CORAZA-OPENAPI
`;
    expect(lintSeclang(src, monaco)).toEqual([]);
  });

  it('flags an unknown directive', () => {
    const m = lintSeclang('SecSomethingMadeUp hello', monaco);
    expect(m.some((x) => x.message.includes('Unknown directive'))).toBe(true);
  });

  it('flags missing id on a non-chain rule', () => {
    const m = lintSeclang('SecRule REQUEST_METHOD "@streq GET" "phase:1,deny"', monaco);
    expect(m.some((x) => x.message.includes('missing the required `id:`'))).toBe(true);
  });

  it('does NOT flag missing id on a chain-continuation SecRule', () => {
    const src = `
SecRule REQUEST_METHOD "@streq GET" \\
    "id:1,phase:1,pass,t:none,chain"
    SecRule REQUEST_URI_RAW "@rx ^/$" "t:none"
`;
    expect(lintSeclang(src, monaco)).toEqual([]);
  });

  it('flags an unknown variable', () => {
    const m = lintSeclang('SecRule SOMETHING_WEIRD "@streq x" "id:1,phase:1,pass"', monaco);
    expect(m.some((x) => x.message.includes('Unknown variable'))).toBe(true);
  });

  it('flags an unknown operator', () => {
    const m = lintSeclang('SecRule REQUEST_METHOD "@madeupop x" "id:1,phase:1,pass"', monaco);
    expect(m.some((x) => x.message.includes('Unknown operator'))).toBe(true);
  });

  it('flags an unknown action key', () => {
    const m = lintSeclang('SecRule REQUEST_METHOD "@streq x" "id:1,phase:1,whoopsie,pass"', monaco);
    expect(m.some((x) => x.message.includes('Unknown action'))).toBe(true);
  });

  it('flags a bad phase number', () => {
    const m = lintSeclang('SecRule REQUEST_METHOD "@streq x" "id:1,phase:9,pass"', monaco);
    expect(m.some((x) => x.message.includes('phase must be'))).toBe(true);
  });

  it('accepts SecMarker labels with hyphens', () => {
    const src = `
SecMarker BEGIN-CORAZA-OPENAPI
SecMarker END-OPENAPI-OPMATCH
SecRule REQUEST_METHOD "@streq GET" \\
    "id:1,phase:1,pass,t:none,skipAfter:END-OPENAPI-OPMATCH"
`;
    expect(lintSeclang(src, monaco)).toEqual([]);
  });

  it('flags missing SecMarker argument', () => {
    const m = lintSeclang('SecMarker', monaco);
    expect(m.some((x) => x.message.includes('requires an argument'))).toBe(true);
  });
});