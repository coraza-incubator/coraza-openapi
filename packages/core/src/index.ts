// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
export { parseSpec } from './openapi/parse.js';
export { normalize, pathToRegex } from './openapi/normalize.js';
export { generateRules, type GenerateResult } from './generator/index.js';
export { ConfigSchema, defaultConfig, type Config } from './config/schema.js';
export { serialize, serializeRule, type SecEntry, type SecRule } from './generator/seclang.js';
export type {
  Diagnostic,
  NormalizedOperation,
  NormalizedParameter,
  NormalizedSchema,
  NormalizedSecurityRequirement,
  NormalizedSecurityScheme,
  NormalizedServer,
  NormalizedSpec,
  OpenAPIDocument,
} from './types.js';

import { parseSpec } from './openapi/parse.js';
import { normalize } from './openapi/normalize.js';
import { generateRules } from './generator/index.js';
import type { Config } from './config/schema.js';

/** High-level convenience: parse + normalize + generate. */
export async function generateFromText(
  specText: string,
  config: Config,
): Promise<
  | { ok: true; seclang: string; ruleCount: number; diagnostics: ReturnType<typeof generateRules>['diagnostics'] }
  | { ok: false; error: string }
> {
  const parsed = await parseSpec(specText);
  if (!parsed.ok) return { ok: false, error: parsed.error };
  const spec = normalize(parsed.doc, parsed.rawHash);
  const gen = generateRules(spec, config);
  return { ok: true, seclang: gen.seclang, ruleCount: gen.ruleCount, diagnostics: gen.diagnostics };
}