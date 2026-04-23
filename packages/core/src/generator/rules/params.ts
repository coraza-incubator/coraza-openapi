// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import type { Config } from '../../config/schema.js';
import type { NormalizedOperation, NormalizedParameter } from '../../types.js';
import type { IdAllocator } from '../ids.js';
import type { SecEntry } from '../seclang.js';

/** Per-op parameter validators. Runs inside a per-op skip-block so the rules
 *  don't need a method/URI chain scope — just the single validator outer. */
export function paramRulesFor(op: NormalizedOperation, config: Config, ids: IdAllocator): SecEntry[] {
  const { requiredParams, validateTypes, validateEnums, validatePatterns, validateLengths } = config.validation;
  if (!requiredParams && !validateTypes && !validateEnums && !validatePatterns && !validateLengths) return [];
  if (op.xCoraza['x-coraza-skip'] === true) return [];

  const opId = op.operationId ?? `${op.method}_${op.path}`;
  const rules: SecEntry[] = [];

  // Merge missing-required checks into a single rule per op: if any of the
  // required params' count is 0, this rule fires (status 400) and identifies
  // which parameter via `%{MATCHED_VAR_NAME}`.
  if (requiredParams) {
    const requiredVars = op.parameters
      .filter((p) => p.in !== 'path' && p.required)
      .map(paramVar);
    if (requiredVars.length > 0) {
      rules.push({
        id: ids.next(),
        phase: 1,
        variable: requiredVars.map((v) => `&${v}`).join('|'),
        operator: '@eq 0',
        action: 'deny',
        status: 400,
        msg: `Missing required parameter for ${opId}`,
        logdata: 'missing=%{MATCHED_VAR_NAME}',
        tags: [`${config.tagPrefix}param/missing`],
        comment: `Required parameters for ${op.method} ${op.path}: ${op.parameters.filter((p) => p.in !== 'path' && p.required).map((p) => `${p.in}:${p.name}`).join(', ')}. A single rule checks them all; the offending parameter is captured in logdata.`,
      } as any);
    }
  }

  for (const p of op.parameters) {
    if (p.in === 'path') continue; // enforced by the path regex on op-match
    if (!p.schema) continue;
    if (validateEnums && p.schema.enum?.length) {
      rules.push(enumRule(p, opId, config, ids));
    }
    if (validatePatterns && p.schema.pattern) {
      rules.push(patternRule(p, opId, config, ids));
    }
    if (validateTypes && p.schema.type && ['integer', 'number', 'boolean'].includes(p.schema.type)) {
      rules.push(typeRule(p, opId, config, ids));
    }
    if (validateTypes && p.schema.format === 'uuid') {
      rules.push(uuidRule(p, opId, config, ids));
    }
    if (validateLengths && (p.schema.minLength !== undefined || p.schema.maxLength !== undefined)) {
      rules.push(lengthRule(p, opId, config, ids));
    }
  }
  return rules;
}

function paramVar(p: NormalizedParameter): string {
  if (p.in === 'query') return `ARGS_GET:${p.name}`;
  if (p.in === 'header') return `REQUEST_HEADERS:${p.name}`;
  if (p.in === 'cookie') return `REQUEST_COOKIES:${p.name}`;
  return `ARGS:${p.name}`;
}

function enumRule(p: NormalizedParameter, opId: string, config: Config, ids: IdAllocator): SecEntry {
  const raw = (p.schema!.enum ?? []).map((v) => String(v));
  const vals = raw.map((v) => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  return {
    id: ids.next(),
    phase: 1,
    variable: paramVar(p),
    operator: `!@rx ^(?:${vals})$`,
    action: 'deny',
    status: 400,
    msg: `Invalid enum value for "${p.name}" in ${opId}`,
    tags: [`${config.tagPrefix}param/enum`],
    comment: `Enum validation for ${p.in} parameter "${p.name}". Allowed: ${raw.join(', ')}.`,
  } as any;
}

function patternRule(p: NormalizedParameter, opId: string, config: Config, ids: IdAllocator): SecEntry {
  const pat = p.schema!.pattern!.replace(/^\^/, '').replace(/\$$/, '');
  return {
    id: ids.next(),
    phase: 1,
    variable: paramVar(p),
    operator: `!@rx ${pat}`,
    action: 'deny',
    status: 400,
    msg: `Pattern mismatch for "${p.name}" in ${opId}`,
    tags: [`${config.tagPrefix}param/pattern`],
    comment: `Regex pattern check for ${p.in} parameter "${p.name}" (spec schema.pattern).`,
  } as any;
}

function typeRule(p: NormalizedParameter, opId: string, config: Config, ids: IdAllocator): SecEntry {
  const t = p.schema!.type!;
  const pat = t === 'integer' ? '^-?\\d+$' : t === 'number' ? '^-?\\d+(?:\\.\\d+)?$' : '^(?:true|false)$';
  return {
    id: ids.next(),
    phase: 1,
    variable: paramVar(p),
    operator: `!@rx ${pat}`,
    action: 'deny',
    status: 400,
    msg: `Type mismatch (${t}) for "${p.name}" in ${opId}`,
    tags: [`${config.tagPrefix}param/type`],
    comment: `Type check for ${p.in} parameter "${p.name}" — must match the "${t}" type declared in the spec.`,
  } as any;
}

function uuidRule(p: NormalizedParameter, opId: string, config: Config, ids: IdAllocator): SecEntry {
  return {
    id: ids.next(),
    phase: 1,
    variable: paramVar(p),
    operator: '!@rx ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
    action: 'deny',
    status: 400,
    msg: `Invalid UUID for "${p.name}" in ${opId}`,
    tags: [`${config.tagPrefix}param/uuid`],
    comment: `UUID check for ${p.in} parameter "${p.name}" (spec format: "uuid").`,
  } as any;
}

function lengthRule(p: NormalizedParameter, opId: string, config: Config, ids: IdAllocator): SecEntry {
  const min = p.schema!.minLength ?? 0;
  const max = p.schema!.maxLength;
  const pat = max !== undefined ? `^.{${min},${max}}$` : `^.{${min},}$`;
  return {
    id: ids.next(),
    phase: 1,
    variable: paramVar(p),
    operator: `!@rx ${pat}`,
    action: 'deny',
    status: 400,
    msg: `Length out of bounds for "${p.name}" in ${opId}`,
    tags: [`${config.tagPrefix}param/length`],
    comment: `Length check for ${p.in} parameter "${p.name}" — minLength: ${min}${max !== undefined ? `, maxLength: ${max}` : ''}.`,
  } as any;
}