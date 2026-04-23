// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import type { Config } from '../../config/schema.js';
import type { NormalizedSpec } from '../../types.js';
import type { IdAllocator } from '../ids.js';
import type { SecEntry } from '../seclang.js';

/** CRS-style setup block: operator-patchable knobs live as TX variables with
 *  stable names so downstream rules (and operators) can reference them, the
 *  same pattern `crs-setup.conf` uses. */
export function setupRules(spec: NormalizedSpec, config: Config, ids: IdAllocator): SecEntry[] {
  const hosts = (config.routing.allowedHosts.length
    ? config.routing.allowedHosts
    : spec.servers.map((s) => s.host).filter((h): h is string => !!h)
  ).join('|');

  const vars: Array<[string, string | number]> = [
    ['coraza_openapi_mode', config.mode],
    ['coraza_openapi_deny_status', config.defaultDenyStatus],
    ['coraza_openapi_tag_prefix', config.tagPrefix],
    ['coraza_openapi_strip_prefix', config.routing.stripPrefix],
    ['coraza_openapi_add_prefix', config.routing.addPrefix],
    ['coraza_openapi_allowed_hosts', hosts],
    ['coraza_openapi_deprecated_handling', config.routing.deprecatedHandling],
    ['coraza_openapi_undeclared_action', config.routing.undeclaredEndpointAction],
  ];

  // Deterministic init for the per-request match flag + matched-op tag used
  // by the path+method allowlist and per-op skip blocks (see pathMethod.ts).
  const runtimeVars = ['openapi_matched=0', 'openapi_op=-'];

  return [
    { type: 'section', title: 'Setup — TX variables (override these in your local crs-setup.conf)' },
    {
      type: 'secaction',
      id: ids.next(),
      phase: 1,
      // Skip empty-value entries — Coraza's setvar parser rejects them with
      // "empty data". Missing TX vars read as "" anyway, so the semantics
      // match.
      setvar: [
        ...vars
          .filter(([, v]) => String(v) !== '')
          .map(([k, v]) => `tx.${k}=${String(v)}`),
        ...runtimeVars.map((v) => `tx.${v}`),
      ],
      comment:
        'Operator-patchable configuration. Downstream rules do NOT actually read these values (the rule bodies are generated with the effective values baked in); the variables exist so operators and downstream CRS rules have a single place to introspect what this bundle was generated for.',
    },
    ...advanceSection(ids),
  ];
}

function advanceSection(ids: IdAllocator): SecEntry[] {
  ids.advanceSection();
  return [];
}