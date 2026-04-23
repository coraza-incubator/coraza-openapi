// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import type { Config } from '../../config/schema.js';
import type { NormalizedOperation, NormalizedSecurityScheme, NormalizedSpec } from '../../types.js';
import type { IdAllocator } from '../ids.js';
import type { SecEntry } from '../seclang.js';

/** Per-op authentication presence check.
 *
 *  The rule assumes it runs inside a per-op skip-block (guarded by
 *  `TX:openapi_op @streq <opId>`), so no method/URI scoping chain is needed —
 *  a single, cheap outer operator is enough. */
export function authRulesFor(
  op: NormalizedOperation,
  spec: NormalizedSpec,
  config: Config,
  ids: IdAllocator,
): SecEntry[] {
  if (!config.auth.enforceSecurity) return [];
  const schemes = spec.securitySchemes;
  if (Object.keys(schemes).length === 0) return [];
  const required = op.security ?? spec.globalSecurity;
  if (required === null) return [];
  if (required.length === 0) return []; // explicit public
  const allSchemes = new Set<string>();
  for (const branch of required) for (const r of branch) allSchemes.add(r.schemeName);
  const checks: string[] = [];
  for (const name of allSchemes) {
    const s = schemes[name];
    const tv = s ? tokenVariable(s, config) : null;
    if (tv) checks.push(tv);
  }
  if (checks.length === 0) return [];

  const opId = op.operationId ?? `${op.method}_${op.path}`;
  const [firstCheck, ...restChecks] = checks;
  const rule: SecEntry = {
    id: ids.next(),
    phase: 1,
    variable: `&${firstCheck}`,
    operator: '@eq 0',
    action: 'deny',
    status: 401,
    msg: `Missing credentials for ${opId}`,
    tags: [`${config.tagPrefix}auth`],
    comment: `Require credentials on ${op.method} ${op.path}. Declared securitySchemes: ${[...allSchemes].join(', ')}. Presence check only — the WAF does not validate token contents; upstream auth does that.`,
    chain: restChecks.map((c) => ({ variable: `&${c}`, operator: '@eq 0' })),
  } as any;
  return [rule];
}

function tokenVariable(scheme: NormalizedSecurityScheme, config: Config): string | null {
  const custom = config.auth.customHeaderName;
  if (scheme.type === 'apiKey') {
    if (scheme.in === 'header') return `REQUEST_HEADERS:${custom ?? scheme.headerName ?? 'X-API-Key'}`;
    if (scheme.in === 'query') return `ARGS_GET:${scheme.name}`;
    if (scheme.in === 'cookie') return `REQUEST_COOKIES:${scheme.name}`;
  }
  if (scheme.type === 'http') return 'REQUEST_HEADERS:Authorization';
  if (scheme.type === 'oauth2' || scheme.type === 'openIdConnect') return 'REQUEST_HEADERS:Authorization';
  return null;
}