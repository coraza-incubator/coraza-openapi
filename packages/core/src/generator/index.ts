// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import type { Config } from '../config/schema.js';
import type { Diagnostic, NormalizedOperation, NormalizedSpec } from '../types.js';
import { IdAllocator } from './ids.js';
import { bannerRules } from './rules/banner.js';
import { hostnameRules } from './rules/hostname.js';
import { prefixRules } from './rules/prefix.js';
import { pathMethodRules } from './rules/pathMethod.js';
import { deprecatedRuleFor } from './rules/deprecated.js';
import { authRulesFor } from './rules/auth.js';
import { paramRulesFor } from './rules/params.js';
import { contentTypeRuleFor } from './rules/contentType.js';
import { rateLimitHints, corsHints } from './rules/hints.js';
import { setupRules } from './rules/setup.js';
import { serialize, type SecEntry, type SecRule } from './seclang.js';

export type GenerateResult = {
  entries: SecEntry[];
  seclang: string;
  ruleCount: number;
  diagnostics: Diagnostic[];
};

export const GENERATOR_VERSION = '0.1.0';

/** ID layout mirrors CRS's practice of reserving ranges per category. The
 *  `perOp` range is a block we hand out 100 IDs per op inside, so operators
 *  can `skipAfter:END-OP-<opId>` surgically. Offsets are relative to
 *  `config.startingId`. */
const SECTION_OFFSETS = {
  setup: 0,
  hostname: 2000,
  prefix: 3000,
  pathMethod: 4000,
  perOp: 10000,
  hints: 900000,
} as const;

const SECTION_SEVERITY: Record<string, SecRule['severity']> = {
  setup: 'INFO',
  hostname: 'CRITICAL',
  prefix: 'INFO',
  pathMethod: 'ERROR',
  perOpGuard: 'INFO',
  deprecated: 'NOTICE',
  auth: 'CRITICAL',
  contentType: 'WARNING',
  params: 'WARNING',
  hints: 'INFO',
};

function baseTags(tagPrefix: string, section: string): string[] {
  return [
    'application-multi',
    'language-multi',
    'platform-multi',
    'paranoia-level/1',
    `${tagPrefix}category/${section}`,
  ];
}

const CRS_ANOMALY_SETVARS: Record<NonNullable<SecRule['severity']>, string[]> = {
  EMERGENCY: ['tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'],
  ALERT: ['tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'],
  CRITICAL: ['tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'],
  ERROR: ['tx.inbound_anomaly_score_pl1=+%{tx.error_anomaly_score}'],
  WARNING: ['tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}'],
  NOTICE: ['tx.inbound_anomaly_score_pl1=+%{tx.notice_anomaly_score}'],
  INFO: [],
  DEBUG: [],
};

function applyMode(entries: SecEntry[], mode: Config['mode']): SecEntry[] {
  if (mode === 'standalone-block') return entries;
  return entries.map((e) => {
    if ((e as any).type) return e;
    const r = e as SecRule;
    if (r.action !== 'deny') return r;
    if (mode === 'standalone-detect') {
      const { status: _status, ...rest } = r;
      return { ...rest, action: 'pass' } as SecRule;
    }
    // crs-plugin: pass + contribute to anomaly score. The contribution must
    // live on the innermost chain element (or on non-chained rules directly)
    // so it only fires when the whole condition matches.
    const sev = r.severity ?? 'WARNING';
    const { status: _status, ...rest } = r;
    const contribution = CRS_ANOMALY_SETVARS[sev];
    const extraTags = ['OWASP_CRS', 'OWASP_CRS/PLUGIN/CORAZA-OPENAPI'];
    if (r.chain && r.chain.length > 0) {
      const newChain = r.chain.map((c, i, arr) =>
        i === arr.length - 1
          ? { ...c, setvar: [...((c as any).setvar ?? []), ...contribution] }
          : c,
      );
      return {
        ...rest,
        action: 'pass',
        tags: [...(r.tags ?? []), ...extraTags],
        chain: newChain,
      } as SecRule;
    }
    return {
      ...rest,
      action: 'pass',
      setvar: [...(r.setvar ?? []), ...contribution],
      tags: [...(r.tags ?? []), ...extraTags],
    } as SecRule;
  });
}

function stamp(entries: SecEntry[], section: string, config: Config): SecEntry[] {
  const sev = SECTION_SEVERITY[section];
  const extra = baseTags(config.tagPrefix, section);
  return entries.map((e) => {
    if ((e as any).type) return e;
    const r = e as SecRule;
    return {
      ...r,
      ver: `coraza-openapi/${GENERATOR_VERSION}`,
      severity: r.severity ?? sev,
      tags: [...extra, ...(r.tags ?? [])],
    };
  });
}

/** Build the per-operation block for `op`. The block is guarded by
 *  `SecRule TX:openapi_op "!@streq <opId>"` → `skipAfter:END-OP-<opId>`, so
 *  its inner rules never have to re-match method/URI. */
function perOpBlock(
  op: NormalizedOperation,
  spec: NormalizedSpec,
  config: Config,
  ids: IdAllocator,
): SecEntry[] {
  const opId = op.operationId ?? `${op.method}_${op.path}`.replace(/[^a-zA-Z0-9]+/g, '_');
  const inner: SecEntry[] = [];
  inner.push(...stamp(deprecatedRuleFor(op, config, ids), 'deprecated', config));
  inner.push(...stamp(authRulesFor(op, spec, config, ids), 'auth', config));
  inner.push(...stamp(contentTypeRuleFor(op, config, ids), 'contentType', config));
  inner.push(...stamp(paramRulesFor(op, config, ids), 'params', config));
  const rulesCount = inner.filter((e) => !(e as any).type).length;
  if (rulesCount === 0) return [];
  const marker = `END-OP-${opId}`;
  const guard: SecEntry = {
    id: ids.next(),
    phase: 1,
    variable: 'TX:openapi_op',
    operator: `!@streq ${opId}`,
    action: 'pass',
    skipAfter: marker,
    tags: [`${config.tagPrefix}op-guard`],
    comment: `Skip this block unless the matched operation is ${opId}. Cuts evaluation cost for specs with many operations — only the matched op's rules run.`,
  } as any;
  return [
    { type: 'section', title: `Operation: ${op.method} ${op.path} (${opId})` },
    ...stamp([guard], 'perOpGuard', config),
    ...inner,
    { type: 'directive', directive: 'SecMarker', args: marker },
  ];
}

export function generateRules(spec: NormalizedSpec, config: Config): GenerateResult {
  const entries: SecEntry[] = [];

  entries.push(...bannerRules(spec, config));

  const section = (key: keyof typeof SECTION_OFFSETS) =>
    new IdAllocator(config.startingId + SECTION_OFFSETS[key], config.idStep);

  entries.push(...stamp(setupRules(spec, config, section('setup')), 'setup', config));
  entries.push(...stamp(hostnameRules(spec, config, section('hostname')), 'hostname', config));
  entries.push(...stamp(prefixRules(spec, config, section('prefix')), 'prefix', config));
  entries.push(...stamp(pathMethodRules(spec, config, section('pathMethod')), 'pathMethod', config));

  // Per-op validation blocks. Each op gets a dedicated ID range (step 100)
  // so IDs are readable and operators can skipAfter:END-OP-<opId> from CRS.
  const perOpBase = config.startingId + SECTION_OFFSETS.perOp;
  let opIndex = 0;
  for (const op of spec.operations) {
    if (op.xCoraza['x-coraza-skip'] === true) continue;
    const opIds = new IdAllocator(perOpBase + opIndex * 100, 1);
    opIndex++;
    entries.push(...perOpBlock(op, spec, config, opIds));
  }

  entries.push(...rateLimitHints(spec, config));
  entries.push(...corsHints(spec, config));

  if (config.banner) {
    entries.push({ type: 'comment', text: '' });
    entries.push({ type: 'directive', directive: 'SecMarker', args: 'END-CORAZA-OPENAPI' });
  }

  const transformed = applyMode(entries, config.mode);
  const seclang = serialize(transformed);
  const ruleCount = transformed.filter((e) => !(e as any).type).length;
  return { entries: transformed, seclang, ruleCount, diagnostics: spec.diagnostics };
}