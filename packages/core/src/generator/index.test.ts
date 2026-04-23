// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { generateFromText, defaultConfig, ConfigSchema } from '../index.js';
import { petstoreYaml, minimalYaml } from '../samples/index.js';

describe('generateFromText', () => {
  it('produces rules for petstore with default config', async () => {
    const r = await generateFromText(petstoreYaml, defaultConfig());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.ruleCount).toBeGreaterThan(5);
    expect(r.seclang).toContain('SecRule');
    expect(r.seclang).toContain('Petstore');
    expect(r.seclang).toContain('Host header not in OpenAPI-allowed hosts');
    expect(r.seclang).toContain('Path not defined in OpenAPI spec');
  });

  it('disables hostname rule when toggled off', async () => {
    const cfg = ConfigSchema.parse({ routing: { enforceHostname: false } });
    const r = await generateFromText(petstoreYaml, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).not.toContain('Host header not in OpenAPI-allowed hosts');
  });

  it('respects starting rule id (CRS-style category ranges)', async () => {
    const cfg = ConfigSchema.parse({ startingId: 5000000 });
    const r = await generateFromText(petstoreYaml, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    // Setup block starts at +0, limits at +1000, pathMethod at +4000, etc.
    expect(r.seclang).toMatch(/id:50000\d{2}/); // setup TX setter
    expect(r.seclang).toMatch(/id:50040\d{2}/); // path/method rules
  });

  it('surfaces detectionOnly mode as a TX variable (no SecRuleEngine directive)', async () => {
    const cfg = ConfigSchema.parse({ mode: 'detectionOnly' });
    const r = await generateFromText(minimalYaml, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).not.toContain('SecRuleEngine');
    expect(r.seclang).not.toContain('SecDefaultAction');
    expect(r.seclang).toContain("setvar:'tx.coraza_openapi_mode=standalone-detect'");
  });

  it('crs-plugin mode contributes to anomaly score instead of denying', async () => {
    const cfg = ConfigSchema.parse({ mode: 'crs-plugin' });
    const r = await generateFromText(petstoreYaml, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).toContain('tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}');
    expect(r.seclang).toContain('OWASP_CRS/PLUGIN/CORAZA-OPENAPI');
    // No direct deny actions in plugin mode.
    expect(r.seclang).not.toMatch(/\bdeny,status:/);
    expect(r.seclang).toContain('CRS plugin mode.');
  });

  it('standalone-detect mode never denies', async () => {
    const cfg = ConfigSchema.parse({ mode: 'standalone-detect' });
    const r = await generateFromText(petstoreYaml, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).not.toMatch(/\bdeny,status:/);
    expect(r.seclang).toContain('standalone-detect');
  });

  it('undeclaredEndpointAction: "alert" turns the catch-all into a pass+log', async () => {
    const cfg = ConfigSchema.parse({ routing: { undeclaredEndpointAction: 'alert' } });
    const r = await generateFromText(petstoreYaml, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).toContain('alert only — not blocked');
    expect(r.seclang).toContain('openapi/allowlist/alert-only');
  });

  it('op-match rules use setvar+skipAfter, and a single TX catch-all decides', async () => {
    const r = await generateFromText(petstoreYaml, defaultConfig());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).toContain("setvar:'tx.openapi_matched=1'");
    expect(r.seclang).toContain('skipAfter:END-OPENAPI-OPMATCH');
    expect(r.seclang).toContain('SecMarker END-OPENAPI-OPMATCH');
    expect(r.seclang).toContain('SecRule TX:openapi_matched "!@streq 1"');
    // No giant negative alternation anymore.
    expect(r.seclang).not.toMatch(/!@rx \(\?:\^\/pets.*\|\^\/pets/);
  });

  it('closes the top-level SecMarker block', async () => {
    const r = await generateFromText(petstoreYaml, defaultConfig());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).toContain('SecMarker BEGIN-CORAZA-OPENAPI');
    expect(r.seclang).toContain('SecMarker END-CORAZA-OPENAPI');
    // Order matters — BEGIN must precede END.
    expect(r.seclang.indexOf('BEGIN-CORAZA-OPENAPI')).toBeLessThan(
      r.seclang.indexOf('END-CORAZA-OPENAPI'),
    );
  });

  it('setup block initializes tx.openapi_matched=0', async () => {
    const r = await generateFromText(petstoreYaml, defaultConfig());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).toContain("setvar:'tx.openapi_matched=0'");
  });

  it('undeclaredEndpointAction: "allow" removes the catch-all entirely', async () => {
    const cfg = ConfigSchema.parse({ routing: { undeclaredEndpointAction: 'allow' } });
    const r = await generateFromText(petstoreYaml, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).not.toContain('Path not defined in OpenAPI spec');
    expect(r.seclang).not.toContain('alert only — not blocked');
  });

  it('accepts legacy "block" / "detectionOnly" mode aliases', async () => {
    expect(ConfigSchema.parse({ mode: 'block' }).mode).toBe('standalone-block');
    expect(ConfigSchema.parse({ mode: 'detectionOnly' }).mode).toBe('standalone-detect');
  });

  it('does not emit SecRequestBodyLimit* — those are engine-global', async () => {
    const r = await generateFromText(petstoreYaml, defaultConfig());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).not.toContain('SecRequestBodyLimit');
    expect(r.seclang).not.toContain('SecRequestBodyLimitAction');
  });

  it('disables auth rules when toggled off', async () => {
    const cfg = ConfigSchema.parse({ auth: { enforceSecurity: false } });
    const r = await generateFromText(petstoreYaml, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).not.toContain('Missing credentials for');
  });

  it('blocks deprecated ops when configured', async () => {
    const cfg = ConfigSchema.parse({ routing: { deprecatedHandling: 'block' } });
    const r = await generateFromText(petstoreYaml, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).toContain('Deprecated endpoint');
    expect(r.seclang).toContain('status:410');
  });

  it('by default does not emit msg on pass rules', async () => {
    const r = await generateFromText(petstoreYaml, defaultConfig());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    // The only "Matched GET /pets" style message should appear in debug mode.
    expect(r.seclang).not.toContain('debug: matched');
    // Deny rules must still carry msg so audit logs are useful.
    expect(r.seclang).toMatch(/msg:'(Host header|Path not defined|Missing)/);
  });

  it('debug flag annotates pass rules too', async () => {
    const cfg = ConfigSchema.parse({ debug: true });
    const r = await generateFromText(petstoreYaml, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.seclang).toContain('debug: matched');
  });

  it('returns an error on malformed input', async () => {
    const r = await generateFromText('not yaml: : :', defaultConfig());
    expect(r.ok).toBe(false);
  });
});