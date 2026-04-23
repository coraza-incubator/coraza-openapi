// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { readFile } from 'node:fs/promises';
import { generateFromText } from '@coraza-openapi/core';
import pc from 'picocolors';
import { loadConfig, applyFlagOverrides } from '../loadConfig.js';

export async function runDiff(a: string, b: string, flags: Record<string, unknown>): Promise<number> {
  const cfg = applyFlagOverrides(await loadConfig(flags['config'] as string | undefined), flags);
  const [ta, tb] = await Promise.all([readFile(a, 'utf8'), readFile(b, 'utf8')]);
  const [ra, rb] = await Promise.all([generateFromText(ta, cfg), generateFromText(tb, cfg)]);
  if (!ra.ok) {
    console.error(pc.red(`error parsing ${a}: ${ra.error}`));
    return 1;
  }
  if (!rb.ok) {
    console.error(pc.red(`error parsing ${b}: ${rb.error}`));
    return 1;
  }
  const la = ra.seclang.split('\n');
  const lb = rb.seclang.split('\n');
  const setA = new Set(la);
  const setB = new Set(lb);
  const added = lb.filter((l) => !setA.has(l) && l.trim());
  const removed = la.filter((l) => !setB.has(l) && l.trim());
  console.log(`## Coraza rule diff: ${a} → ${b}`);
  console.log('');
  console.log(`Rules: ${ra.ruleCount} → ${rb.ruleCount} (${rb.ruleCount - ra.ruleCount >= 0 ? '+' : ''}${rb.ruleCount - ra.ruleCount})`);
  console.log('');
  console.log('```diff');
  for (const l of removed) console.log(`- ${l}`);
  for (const l of added) console.log(`+ ${l}`);
  console.log('```');
  return 0;
}