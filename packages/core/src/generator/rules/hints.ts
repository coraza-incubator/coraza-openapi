// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import type { Config } from '../../config/schema.js';
import type { NormalizedSpec } from '../../types.js';
import type { SecEntry } from '../seclang.js';

export function rateLimitHints(spec: NormalizedSpec, config: Config): SecEntry[] {
  if (!config.advanced.emitRateLimitHints) return [];
  const flagged = spec.operations.filter((op) => 'x-coraza-rate-limit' in op.xCoraza);
  if (flagged.length === 0) return [];
  const out: SecEntry[] = [{ type: 'section', title: 'Rate-limit hints (informational)' }];
  for (const op of flagged) {
    out.push({ type: 'comment', text: `${op.method} ${op.path} → rate-limit: ${op.xCoraza['x-coraza-rate-limit']}` });
  }
  out.push({ type: 'comment', text: 'NOTE: Coraza core has no native rate limiter — enforce upstream (e.g. Envoy/NGINX).' });
  return out;
}

export function corsHints(spec: NormalizedSpec, config: Config): SecEntry[] {
  if (!config.advanced.emitCorsHints) return [];
  const hosts = spec.servers.map((s) => s.host).filter(Boolean);
  if (hosts.length === 0) return [];
  return [
    { type: 'section', title: 'CORS origin allowlist (informational)' },
    { type: 'comment', text: `Suggested allowed origins: ${hosts.join(', ')}` },
    { type: 'comment', text: `Configure your reverse proxy to echo only these in Access-Control-Allow-Origin.` },
  ];
}