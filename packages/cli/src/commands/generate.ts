// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { readFile, writeFile } from 'node:fs/promises';
import { generateFromText, parseSpec, normalize, generateRules } from '@coraza-openapi/core';
import pc from 'picocolors';
import { loadConfig, applyFlagOverrides } from '../loadConfig.js';

export async function runGenerate(input: string, flags: Record<string, unknown>): Promise<number> {
  const text = input === '-' ? await readStdin() : await readFile(input, 'utf8');
  const cfg = applyFlagOverrides(await loadConfig(flags['config'] as string | undefined), flags);

  if (flags['format'] === 'json') {
    const parsed = await parseSpec(text);
    if (!parsed.ok) {
      console.error(pc.red(parsed.error));
      return 1;
    }
    const spec = normalize(parsed.doc, parsed.rawHash);
    const gen = generateRules(spec, cfg);
    const out = JSON.stringify({ ruleCount: gen.ruleCount, entries: gen.entries, diagnostics: gen.diagnostics }, null, 2);
    await emit(out, flags['output'] as string | undefined);
    return 0;
  }

  const res = await generateFromText(text, cfg);
  if (!res.ok) {
    console.error(pc.red(`error: ${res.error}`));
    return 1;
  }
  if (flags['strict'] && res.diagnostics.some((d) => d.level === 'warn' || d.level === 'error')) {
    for (const d of res.diagnostics) console.error(pc.yellow(`[${d.level}] ${d.path}: ${d.message}`));
    return 2;
  }
  await emit(res.seclang, flags['output'] as string | undefined);
  console.error(pc.green(`✓ ${res.ruleCount} rules generated`));
  return 0;
}

async function emit(content: string, output?: string): Promise<void> {
  if (!output || output === '-') {
    process.stdout.write(content);
  } else {
    await writeFile(output, content, 'utf8');
  }
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}