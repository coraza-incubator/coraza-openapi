// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import type { Config } from '../../config/schema.js';
import type { NormalizedOperation } from '../../types.js';
import type { IdAllocator } from '../ids.js';
import type { SecEntry } from '../seclang.js';

/** Per-op deprecated-endpoint handling. Runs inside a per-op skip-block, so
 *  no method/URI chain scope is needed. */
export function deprecatedRuleFor(op: NormalizedOperation, config: Config, ids: IdAllocator): SecEntry[] {
  const mode = config.routing.deprecatedHandling;
  if (mode === 'allow') return [];
  if (!op.deprecated) return [];
  if (mode === 'warn') {
    // Use an always-match @unconditionalmatch pass with logdata so audit logs
    // flag the call without blocking.
    return [
      {
        id: ids.next(),
        phase: 1,
        variable: 'REQUEST_METHOD',
        operator: '@unconditionalMatch',
        action: 'pass',
        msg: `Deprecated endpoint: ${op.method} ${op.path}`,
        tags: [`${config.tagPrefix}deprecated`],
        comment: `Operation marked "deprecated: true" in the spec. Handling: "warn" (log only, not blocked).`,
      } as any,
    ];
  }
  return [
    {
      id: ids.next(),
      phase: 1,
      variable: 'REQUEST_METHOD',
      operator: '@unconditionalMatch',
      action: 'deny',
      status: 410,
      msg: `Deprecated endpoint: ${op.method} ${op.path}`,
      tags: [`${config.tagPrefix}deprecated`],
      comment: `Operation marked "deprecated: true" in the spec. Handling: "block" — 410 Gone.`,
    } as any,
  ];
}