// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { readFile } from 'node:fs/promises';
import { parseSpec, normalize } from '@coraza-openapi/core';
import pc from 'picocolors';

export async function runValidate(input: string, flags: Record<string, unknown>): Promise<number> {
  const text = await readFile(input, 'utf8');
  const parsed = await parseSpec(text);
  if (!parsed.ok) {
    console.error(pc.red(`✗ ${parsed.error}`));
    return 1;
  }
  const spec = normalize(parsed.doc, parsed.rawHash);
  for (const d of spec.diagnostics) {
    const colour = d.level === 'error' ? pc.red : d.level === 'warn' ? pc.yellow : pc.gray;
    console.error(colour(`[${d.level}] ${d.path}: ${d.message}`));
  }
  if (flags['strict'] && spec.diagnostics.some((d) => d.level !== 'info')) return 2;
  console.error(pc.green(`✓ ${spec.operations.length} operations`));
  return 0;
}