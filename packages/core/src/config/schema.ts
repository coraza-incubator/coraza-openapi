// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { z } from 'zod';

export const ConfigSchema = z.object({
  startingId: z.number().int().min(1).max(2_147_483_647).default(1_000_000),
  idStep: z.number().int().min(1).max(1000).default(100),
  /**
   * Output profile:
   *  - `standalone-block`: each rule denies immediately (default).
   *  - `standalone-detect`: rules log but do not deny (good for shadow rollouts).
   *  - `crs-plugin`: emit as an OWASP CRS plugin — rules contribute to the
   *    inbound anomaly score via `setvar` instead of denying. CRS's
   *    949xxx blocking evaluation then decides whether to block.
   *    See https://coreruleset.org/docs/concepts/plugins/
   */
  mode: z
    .enum(['standalone-block', 'standalone-detect', 'crs-plugin', 'block', 'detectionOnly'])
    .default('standalone-block')
    .transform((v) => (v === 'block' ? 'standalone-block' : v === 'detectionOnly' ? 'standalone-detect' : v)),
  defaultDenyStatus: z.number().int().min(400).max(599).default(403),
  tagPrefix: z.string().default('openapi/'),
  banner: z.boolean().default(true),
  /** When true, attach `msg:` to every emitted rule (including pass/allowlist
   *  markers). Off by default — we only want `msg` on deny rules so audit logs
   *  surface contract violations, not "I matched /pets". */
  debug: z.boolean().default(false),

  routing: z
    .object({
      enforceHostname: z.boolean().default(true),
      allowedHosts: z.array(z.string()).default([]),
      stripPrefix: z.string().default(''),
      addPrefix: z.string().default(''),
      pathAllowlist: z.boolean().default(true),
      /** How to handle requests to URIs not declared in the spec:
       *  - block: deny (subject to global mode)
       *  - alert: force pass + log even in standalone-block mode
       *  - allow: skip entirely (same as pathAllowlist=false) */
      undeclaredEndpointAction: z.enum(['block', 'alert', 'allow']).default('block'),
      methodEnforcement: z.boolean().default(true),
      deprecatedHandling: z.enum(['allow', 'warn', 'block']).default('warn'),
    })
    .default({}),

  auth: z
    .object({
      enforceSecurity: z.boolean().default(true),
      customHeaderName: z.string().optional(),
    })
    .default({}),

  validation: z
    .object({
      requiredParams: z.boolean().default(true),
      validateTypes: z.boolean().default(true),
      validateEnums: z.boolean().default(true),
      validatePatterns: z.boolean().default(true),
      validateLengths: z.boolean().default(true),
      enforceContentType: z.boolean().default(true),
    })
    .default({}),

  advanced: z
    .object({
      emitRateLimitHints: z.boolean().default(true),
      emitCorsHints: z.boolean().default(false),
    })
    .default({}),
});

export type Config = z.infer<typeof ConfigSchema>;

export const defaultConfig = (): Config => ConfigSchema.parse({});