// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { writeFile } from 'node:fs/promises';
import { defaultConfig } from '@coraza-openapi/core';
import pc from 'picocolors';

export async function runInitConfig(output: string): Promise<number> {
  const cfg = defaultConfig();
  await writeFile(output, JSON.stringify(cfg, null, 2) + '\n', 'utf8');
  console.error(pc.green(`✓ wrote ${output}`));
  return 0;
}