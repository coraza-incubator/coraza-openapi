// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import type { Config } from '../../config/schema.js';
import type { NormalizedSpec } from '../../types.js';
import type { SecEntry } from '../seclang.js';

/** CRS-style banner + acknowledgement block. Mirrors the shape you see at
 *  the top of `crs-setup.conf` / `REQUEST-901-INITIALIZATION.conf`. */
export function bannerRules(spec: NormalizedSpec, config: Config): SecEntry[] {
  if (!config.banner) return [];
  const line = '# ' + '-'.repeat(76);
  return [
    { type: 'comment', text: '-'.repeat(76) },
    { type: 'comment', text: 'Coraza-OpenAPI Rule Set — generated from an OpenAPI specification.' },
    { type: 'comment', text: '' },
    { type: 'comment', text: `OpenAPI:  ${spec.title} v${spec.version} (sha256:${spec.hash})` },
    { type: 'comment', text: `Mode:     ${modeLabel(config.mode)}` },
    { type: 'comment', text: `Paranoia: 1 (only one level is emitted today)` },
    { type: 'comment', text: '' },
    ...modeLoadOrder(config.mode),
    { type: 'comment', text: '' },
    { type: 'comment', text: 'Licensed under Apache-2.0. Generator: coraza-openapi.' },
    { type: 'comment', text: '-'.repeat(76) },
    { type: 'comment', text: '' },
    { type: 'directive', directive: 'SecMarker', args: 'BEGIN-CORAZA-OPENAPI' },
    { type: 'comment', text: line },
  ];
}

function modeLabel(mode: Config['mode']): string {
  switch (mode) {
    case 'standalone-block':
      return 'standalone-block (rules deny on violation)';
    case 'standalone-detect':
      return 'standalone-detect (rules log, never deny)';
    case 'crs-plugin':
      return 'crs-plugin (contributes to CRS inbound anomaly score)';
  }
}

function modeLoadOrder(mode: Config['mode']): { type: 'comment'; text: string }[] {
  if (mode === 'crs-plugin') {
    return [
      { type: 'comment', text: 'CRS plugin mode.' },
      { type: 'comment', text: 'Load this file as an OWASP CRS plugin — *.conf rules here' },
      { type: 'comment', text: 'contribute to the inbound anomaly score via setvar but never deny' },
      { type: 'comment', text: 'on their own; CRS rules 949110/949120 do the final blocking.' },
      { type: 'comment', text: 'Plugin docs: https://coreruleset.org/docs/concepts/plugins/' },
      { type: 'comment', text: '' },
      { type: 'comment', text: 'Load order:' },
      { type: 'comment', text: '  1. crs-setup.conf' },
      { type: 'comment', text: '  2. coraza-openapi-plugin-before.conf  (setup TX vars)' },
      { type: 'comment', text: '  3. OWASP CRS rules/*.conf' },
      { type: 'comment', text: '  4. coraza-openapi-plugin-after.conf   (this file)' },
    ];
  }
  return [
    { type: 'comment', text: 'Standalone mode — these rules stand on their own and do NOT need CRS.' },
    { type: 'comment', text: 'They CAN sit in front of CRS to reject malformed input before deep scans.' },
    { type: 'comment', text: '' },
    { type: 'comment', text: 'Load order suggestion:' },
    { type: 'comment', text: '  1. crs-setup.conf  (if you use CRS)' },
    { type: 'comment', text: '  2. This file (coraza-openapi.conf)' },
    { type: 'comment', text: '  3. OWASP CRS rules/*.conf  (if you use CRS)' },
  ];
}