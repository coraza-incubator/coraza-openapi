// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import type { Config } from '../../config/schema.js';
import type { NormalizedSpec } from '../../types.js';
import type { IdAllocator } from '../ids.js';
import type { SecEntry } from '../seclang.js';

/** Emits `setvar` actions so downstream rules can reference TX:openapi_strip
 *  and TX:openapi_add. Coraza does not rewrite requests; this just records the
 *  configured prefixes in TX for operators / integrators. */
export function prefixRules(_spec: NormalizedSpec, config: Config, ids: IdAllocator): SecEntry[] {
  const strip = config.routing.stripPrefix.replace(/\/$/, '');
  const add = config.routing.addPrefix.replace(/\/$/, '');
  if (!strip && !add) return [];
  const sets: string[] = [];
  if (strip) sets.push(`tx.openapi_strip=${strip}`);
  if (add) sets.push(`tx.openapi_add=${add}`);
  const entries: SecEntry[] = [
    { type: 'section', title: 'Path prefix normalization (TX state)' },
    {
      type: 'secaction',
      id: ids.next(),
      phase: 1,
      setvar: sets,
      comment:
        'Record the configured strip / add prefixes as TX variables for downstream tooling. Coraza does not rewrite the URI; your upstream (proxy / gateway) is responsible for applying the rewrite before these rules run.',
    },
  ];
  ids.advanceSection();
  return entries;
}