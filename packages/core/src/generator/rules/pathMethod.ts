// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import type { Config } from '../../config/schema.js';
import type { NormalizedSpec } from '../../types.js';
import type { IdAllocator } from '../ids.js';
import type { SecEntry, SecRule } from '../seclang.js';

const MATCH_MARKER = 'END-OPENAPI-OPMATCH';

/** CRS-style path + method enforcement.
 *
 *  Design notes (see AGENTS.md):
 *    1. Each declared operation gets a self-contained rule:
 *       method @streq M chain URI @rx P → setvar tx.openapi_matched=1,
 *       skipAfter:END-OPENAPI-OPMATCH. The first match short-circuits the rest.
 *    2. Per-path method-enforcement rules (405) sit after op-match so that a
 *       request to a declared path with the wrong verb gets 405, not 404.
 *    3. A final catch-all checks tx.openapi_matched and emits 404 when the
 *       request didn't match any declared operation.
 *    4. The SecMarker closes the block so short-circuited requests land here.
 */
export function pathMethodRules(spec: NormalizedSpec, config: Config, ids: IdAllocator): SecEntry[] {
  if (!config.routing.pathAllowlist && !config.routing.methodEnforcement) return [];
  const entries: SecEntry[] = [{ type: 'section', title: 'Path + method allowlist' }];

  const stripPrefix = config.routing.stripPrefix.replace(/\/$/, '');
  const operations = spec.operations.filter((op) => op.xCoraza['x-coraza-skip'] !== true);

  // 1. Per-op match: URI + method → setvar matched + skipAfter.
  //    The URI check MUST be the outer rule: Coraza applies non-disruptive
  //    actions on the outer SecRule whenever its operator matches, so
  //    putting the coarse-grained method check outside would falsely flag
  //    the request as matched for any GET to an undeclared path.
  for (const op of operations) {
    const opId = op.operationId ?? `${op.method}_${op.path}`.replace(/[^a-zA-Z0-9]+/g, '_');
    const pathRegex = applyPrefix(op.pathRegex, stripPrefix);
    const rule: SecRule = {
      id: ids.next(),
      phase: 1,
      variable: 'REQUEST_URI_RAW',
      operator: `@rx ${pathRegex}`,
      action: 'pass',
      tags: [
        `${config.tagPrefix}op/${opId}`,
        ...op.tags.map((t) => `${config.tagPrefix}tag/${t}`),
      ],
      setvar: [`tx.openapi_matched=1`, `tx.openapi_op=${opId}`],
      skipAfter: MATCH_MARKER,
      comment: `Match ${op.method} ${op.path} (${opId}). On match: record the operation in tx.openapi_op so downstream per-op blocks can scope via a single string compare instead of re-matching method+URI.`,
      chain: [{ variable: 'REQUEST_METHOD', operator: `@streq ${op.method}` }],
    };
    if (config.debug) rule.msg = `debug: matched ${op.method} ${op.path} (${opId})`;
    entries.push(rule);
  }

  // 2. Per-path method enforcement (405): URI matches a declared path but the
  //    method is not one of the declared verbs.
  if (config.routing.methodEnforcement) {
    const byPath = new Map<string, string[]>();
    for (const op of operations) {
      const key = applyPrefix(op.pathRegex, stripPrefix);
      byPath.set(key, [...(byPath.get(key) ?? []), op.method]);
    }
    for (const [regex, methods] of byPath) {
      entries.push({
        id: ids.next(),
        phase: 1,
        variable: 'REQUEST_URI_RAW',
        operator: `@rx ${regex}`,
        action: 'deny',
        status: 405,
        msg: 'Method not allowed for path',
        tags: [`${config.tagPrefix}method`],
        comment: `Enforce allowed methods for this declared path. Declared: ${methods.sort().join(', ')}. Any other verb gets 405 (the catch-all 404 will never see it).`,
        chain: [{ variable: 'REQUEST_METHOD', operator: `!@rx ^(?:${methods.join('|')})$` }],
      });
    }
  }

  // 3. Catch-all: no operation matched.
  if (config.routing.pathAllowlist && config.routing.undeclaredEndpointAction !== 'allow') {
    const alertOnly = config.routing.undeclaredEndpointAction === 'alert';
    entries.push({ type: 'comment', text: '' });
    entries.push({
      type: 'comment',
      text: '--- Undeclared-endpoint verdict (the rule the spec\'s allowlist hinges on) ---',
    });
    entries.push({
      id: ids.next(),
      phase: 1,
      variable: 'TX:openapi_matched',
      operator: '!@streq 1',
      action: alertOnly ? 'pass' : 'deny',
      status: alertOnly ? undefined : 404,
      msg: alertOnly
        ? 'Undeclared endpoint hit (alert only — not blocked)'
        : 'Path not defined in OpenAPI spec',
      tags: [
        `${config.tagPrefix}allowlist`,
        ...(alertOnly ? [`${config.tagPrefix}allowlist/alert-only`] : []),
      ],
      logdata: '%{REQUEST_METHOD} %{REQUEST_URI_RAW}',
      comment: `Final verdict: no operation matched. Spec declared ${operations.length} operation(s). Policy: "${config.routing.undeclaredEndpointAction}" — ${alertOnly ? 'log the hit but let it through' : 'reject with 404'}.`,
    } as any);
  }

  // 4. Marker — op-match rules skipAfter here.
  entries.push({ type: 'directive', directive: 'SecMarker', args: MATCH_MARKER });

  ids.advanceSection();
  return entries;
}

function applyPrefix(regex: string, strip: string): string {
  if (!strip) return regex;
  const esc = strip.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return regex.replace(/^\^/, `^${esc}`);
}