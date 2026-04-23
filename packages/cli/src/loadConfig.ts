// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { cosmiconfig } from 'cosmiconfig';
import { ConfigSchema, defaultConfig, type Config } from '@coraza-openapi/core';

export async function loadConfig(explicit?: string): Promise<Config> {
  const explorer = cosmiconfig('coraza-openapi');
  const result = explicit ? await explorer.load(explicit) : await explorer.search();
  if (!result || !result.config) return defaultConfig();
  return ConfigSchema.parse(result.config);
}

export function applyFlagOverrides(config: Config, flags: Record<string, unknown>): Config {
  const next: Config = structuredClone(config);
  // cac passes both kebab-case and camelCase keys; read whichever is set.
  const get = (...keys: string[]): unknown => {
    for (const k of keys) if (flags[k] !== undefined) return flags[k];
    return undefined;
  };
  const startingId = get('starting-id', 'startingId');
  if (typeof startingId === 'number') next.startingId = startingId;
  const tagPrefix = get('tag-prefix', 'tagPrefix');
  if (typeof tagPrefix === 'string') next.tagPrefix = tagPrefix;
  if (get('detection-only', 'detectionOnly')) next.mode = 'standalone-detect';
  if (get('crs-plugin', 'crsPlugin')) next.mode = 'crs-plugin';
  const mode = get('mode');
  if (typeof mode === 'string') next.mode = mode as Config['mode'];
  if (get('debug')) next.debug = true;
  const host = get('host');
  if (typeof host === 'string')
    next.routing.allowedHosts = host.split(',').map((s) => s.trim()).filter(Boolean);
  const stripPrefix = get('strip-prefix', 'stripPrefix');
  if (typeof stripPrefix === 'string') next.routing.stripPrefix = stripPrefix;
  const addPrefix = get('add-prefix', 'addPrefix');
  if (typeof addPrefix === 'string') next.routing.addPrefix = addPrefix;
  // cac maps --no-enforce-auth to `enforceAuth: false`.
  const enforceAuth = get('enforce-auth', 'enforceAuth');
  if (enforceAuth === false) next.auth.enforceSecurity = false;
  if (enforceAuth === true) next.auth.enforceSecurity = true;
  const validateTypes = get('validate-types', 'validateTypes');
  if (validateTypes === false) next.validation.validateTypes = false;
  if (get('block-deprecated', 'blockDeprecated')) next.routing.deprecatedHandling = 'block';
  return ConfigSchema.parse(next);
}