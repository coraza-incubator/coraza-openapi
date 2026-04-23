// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import type { Config } from '../../config/schema.js';
import type { NormalizedOperation } from '../../types.js';
import type { IdAllocator } from '../ids.js';
import type { SecEntry } from '../seclang.js';

/** Per-op Content-Type enforcement. Runs inside a per-op skip-block so no
 *  method/URI chain scope is needed. */
export function contentTypeRuleFor(op: NormalizedOperation, config: Config, ids: IdAllocator): SecEntry[] {
  if (!config.validation.enforceContentType) return [];
  if (op.requestContentTypes.length === 0) return [];
  const opId = op.operationId ?? `${op.method}_${op.path}`;
  const types = op.requestContentTypes.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  return [
    {
      id: ids.next(),
      phase: 1,
      variable: 'REQUEST_HEADERS:Content-Type',
      operator: `!@rx ^(?:${types})(?:;.*)?$`,
      action: 'deny',
      status: 415,
      msg: `Unsupported Content-Type for ${opId}`,
      tags: [`${config.tagPrefix}content-type`],
      comment: `Restrict ${op.method} ${op.path} to the Content-Types declared in requestBody.content: ${op.requestContentTypes.join(', ')}. Any other content type returns 415.`,
    } as any,
  ];
}