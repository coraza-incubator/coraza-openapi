// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { serialize, serializeRule } from './seclang.js';

describe('serializeRule', () => {
  it('renders a basic deny rule', () => {
    const s = serializeRule({
      id: 1,
      phase: 1,
      variable: 'REQUEST_METHOD',
      operator: '@streq GET',
      action: 'deny',
      status: 403,
      msg: "can't allow",
      tags: ['a/b'],
    });
    expect(s).toContain('SecRule REQUEST_METHOD');
    expect(s).toContain('id:1');
    expect(s).toContain('status:403');
    expect(s).toContain("msg:'can\\'t allow'");
    expect(s).toContain("tag:'a/b'");
  });

  it('renders chained rules', () => {
    const s = serializeRule({
      id: 2,
      phase: 1,
      variable: 'REQUEST_METHOD',
      operator: '@streq POST',
      action: 'deny',
      msg: 'chain',
      chain: [{ variable: 'REQUEST_URI_RAW', operator: '@rx ^/a$' }],
    });
    expect(s).toContain('chain');
    expect(s).toContain('REQUEST_URI_RAW');
  });
});

describe('serialize', () => {
  it('renders sections and comments', () => {
    const out = serialize([
      { type: 'comment', text: 'hello' },
      { type: 'section', title: 'T' },
      { type: 'directive', directive: 'SecRuleEngine', args: 'On' },
    ]);
    expect(out).toContain('# hello');
    expect(out).toContain('SecRuleEngine On');
    expect(out).toContain('===');
  });
});