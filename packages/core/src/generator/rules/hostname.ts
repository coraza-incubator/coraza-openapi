// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import type { Config } from '../../config/schema.js';
import type { NormalizedSpec } from '../../types.js';
import type { IdAllocator } from '../ids.js';
import type { SecEntry } from '../seclang.js';

export function hostnameRules(spec: NormalizedSpec, config: Config, ids: IdAllocator): SecEntry[] {
  if (!config.routing.enforceHostname) return [];
  const hosts = config.routing.allowedHosts.length
    ? config.routing.allowedHosts
    : spec.servers.map((s) => s.host).filter((h): h is string => !!h);
  if (hosts.length === 0) return [];
  const entries: SecEntry[] = [{ type: 'section', title: 'Hostname enforcement' }];
  const alternation = hosts.map((h) => h.replace(/[.]/g, '\\.')).join('|');
  entries.push({
    id: ids.next(),
    phase: 1,
    variable: 'REQUEST_HEADERS:Host',
    operator: `!@rx ^(?:${alternation})(?::\\d+)?$`,
    action: 'deny',
    status: config.defaultDenyStatus,
    msg: 'Host header not in OpenAPI-allowed hosts',
    tags: [`${config.tagPrefix}host`],
    comment: `Reject any request whose Host header is not one of: ${hosts.join(', ')}. The allowlist comes from the OpenAPI servers[] entries (or the "Allowed hosts" config override).`,
  });
  ids.advanceSection();
  return entries;
}