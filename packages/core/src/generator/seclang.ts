// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
export type SecRule = {
  id: number;
  phase: 1 | 2 | 3 | 4 | 5;
  variable: string;
  operator: string;
  msg?: string;
  tags?: string[];
  action?: 'deny' | 'pass' | 'block';
  status?: number;
  logdata?: string;
  transform?: string[];
  ver?: string;
  severity?: 'EMERGENCY' | 'ALERT' | 'CRITICAL' | 'ERROR' | 'WARNING' | 'NOTICE' | 'INFO' | 'DEBUG';
  setvar?: string[];
  /** `skipAfter:MARKER` — when this rule fires, jump past all subsequent
   *  rules until a matching `SecMarker MARKER` is found. Lets us cut off
   *  op-matching early once an operation matches. */
  skipAfter?: string;
  chain?: Omit<SecRule, 'id' | 'phase' | 'msg' | 'tags' | 'action' | 'status' | 'ver' | 'severity' | 'setvar' | 'skipAfter'>[];
  comment?: string;
};

export type SecComment = { type: 'comment'; text: string };
export type SecSection = { type: 'section'; title: string };
export type SecDirective = { type: 'directive'; directive: string; args: string };
/** CRS-formatted SecAction block — rendered multi-line like SecRule actions.
 *  Use this for setup / setvar-only actions so the output stays consistent. */
export type SecActionBlock = {
  type: 'secaction';
  id: number;
  phase?: 1 | 2 | 3 | 4 | 5;
  nolog?: boolean;
  transform?: string[];
  setvar?: string[];
  comment?: string;
};
export type SecEntry = SecRule | SecComment | SecSection | SecDirective | SecActionBlock;

export function isRule(e: SecEntry): e is SecRule {
  return !(e as any).type;
}

const INDENT = '    ';

export function serialize(entries: SecEntry[]): string {
  const out: string[] = [];
  for (const e of entries) {
    if ((e as any).type === 'comment') {
      const t = (e as SecComment).text;
      out.push(t === '' ? '#' : `# ${t}`);
      continue;
    }
    if ((e as any).type === 'section') {
      const title = (e as SecSection).title;
      out.push('');
      out.push(`# ${'='.repeat(72)}`);
      out.push(`# ${title}`);
      out.push(`# ${'='.repeat(72)}`);
      continue;
    }
    if ((e as any).type === 'directive') {
      const d = e as SecDirective;
      out.push(`${d.directive} ${d.args}`.trim());
      continue;
    }
    if ((e as any).type === 'secaction') {
      out.push(serializeSecAction(e as SecActionBlock));
      out.push('');
      continue;
    }
    out.push(serializeRule(e as SecRule));
    out.push('');
  }
  // Collapse trailing blank lines into a single newline.
  while (out.length > 0 && out[out.length - 1] === '') out.pop();
  return out.join('\n') + '\n';
}

/** CRS-style multi-line rule. Actions are listed one per line, terminated by
 *  `\` continuations, in the canonical CRS ordering: id, phase, action, t:,
 *  msg, logdata, tag, ctl, ver, severity, setvar, chain. */
export function serializeRule(r: SecRule): string {
  const lines: string[] = [];
  if (r.comment) {
    for (const line of wrapComment(r.comment, 96)) lines.push(`# ${line}`);
  }
  const actions = actionLinesForHead(r);
  const hasChain = !!r.chain && r.chain.length > 0;
  if (hasChain) actions.push('chain');
  lines.push(`SecRule ${r.variable} "${escape(r.operator)}" \\`);
  lines.push(formatActions(actions, INDENT));
  if (hasChain) {
    for (let i = 0; i < r.chain!.length; i++) {
      const c = r.chain![i];
      const last = i === r.chain!.length - 1;
      const chainActions = ['t:none', ...(c.transform ?? []).map((t) => `t:${t}`)];
      // setvar on inner chain rules only fires when the whole chain matches —
      // used by crs-plugin mode to gate anomaly-score contributions.
      if ((c as any).setvar) {
        for (const sv of (c as any).setvar as string[]) chainActions.push(`setvar:'${escape(sv)}'`);
      }
      if (!last) chainActions.push('chain');
      lines.push(`${INDENT}SecRule ${c.variable} "${escape(c.operator)}" \\`);
      lines.push(formatActions(chainActions, INDENT + INDENT));
    }
  }
  return lines.join('\n');
}

/** Format a list of actions as a CRS-style block:
 *      "id:123,\
 *      phase:1,\
 *      block,\
 *      msg:'…'"
 *  The opening `"` sits on the first action; closing `"` on the last. No
 *  trailing `\` on the last line. */
function formatActions(actions: string[], indent: string): string {
  if (actions.length === 0) return `${indent}""`;
  if (actions.length === 1) return `${indent}"${actions[0]}"`;
  const lines: string[] = [];
  lines.push(`${indent}"${actions[0]},\\`);
  for (let i = 1; i < actions.length - 1; i++) {
    lines.push(`${indent}${actions[i]},\\`);
  }
  lines.push(`${indent}${actions[actions.length - 1]}"`);
  return lines.join('\n');
}

function actionLinesForHead(r: SecRule): string[] {
  const out: string[] = [];
  out.push(`id:${r.id}`);
  out.push(`phase:${r.phase}`);
  if (r.action) out.push(r.action);
  if (r.status) out.push(`status:${r.status}`);
  if (r.transform && r.transform.length > 0) {
    for (const t of r.transform) out.push(`t:${t}`);
  } else {
    out.push('t:none');
  }
  if (r.msg) out.push(`msg:'${escape(r.msg)}'`);
  if (r.logdata) out.push(`logdata:'${escape(r.logdata)}'`);
  if (r.tags) for (const t of r.tags) out.push(`tag:'${escape(t)}'`);
  if (r.ver) out.push(`ver:'${escape(r.ver)}'`);
  if (r.severity) out.push(`severity:'${r.severity}'`);
  if (r.setvar) for (const sv of r.setvar) out.push(`setvar:'${escape(sv)}'`);
  if (r.skipAfter) out.push(`skipAfter:${r.skipAfter}`);
  return out;
}

export function serializeSecAction(a: SecActionBlock): string {
  const lines: string[] = [];
  if (a.comment) {
    for (const line of wrapComment(a.comment, 96)) lines.push(`# ${line}`);
  }
  const actions: string[] = [];
  actions.push(`id:${a.id}`);
  actions.push(`phase:${a.phase ?? 1}`);
  actions.push('pass');
  if (a.nolog !== false) actions.push('nolog');
  if (a.transform && a.transform.length > 0) {
    for (const t of a.transform) actions.push(`t:${t}`);
  } else {
    actions.push('t:none');
  }
  if (a.setvar) for (const sv of a.setvar) actions.push(`setvar:'${escape(sv)}'`);
  lines.push('SecAction \\');
  lines.push(formatActions(actions, INDENT));
  return lines.join('\n');
}

function wrapComment(s: string, width: number): string[] {
  const out: string[] = [];
  for (const paragraph of s.split('\n')) {
    const words = paragraph.split(/\s+/);
    let line = '';
    for (const w of words) {
      if (line.length === 0) {
        line = w;
      } else if (line.length + 1 + w.length > width) {
        out.push(line);
        line = w;
      } else {
        line += ' ' + w;
      }
    }
    if (line.length > 0) out.push(line);
  }
  return out;
}

/** SecLang doesn't interpret `\\` as an escape in operator arguments or in
 *  quoted action values — the regex / string engine receives the bytes as
 *  written. We only need to escape the quote character that terminates the
 *  containing context. We escape both flavors because the same helper feeds
 *  `"..."`-wrapped operators and `'...'`-wrapped action values.
 *  CRS writes `\.` literally, exactly like this. */
function escape(s: string): string {
  return s.replace(/"/g, '\\"').replace(/'/g, "\\'");
}