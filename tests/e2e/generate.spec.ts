// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { test, expect, Page } from '@playwright/test';

async function rulesText(page: Page): Promise<string> {
  // Wait for regeneration to settle.
  await page.waitForFunction(() => typeof (window as any).__getRules === 'function');
  return await page.evaluate(() => (window as any).__getRules() as string);
}

async function expectRulesContain(page: Page, needle: string, timeout = 5000) {
  await expect
    .poll(async () => rulesText(page), { timeout })
    .toContain(needle);
}

async function expectRulesNotContain(page: Page, needle: string, timeout = 5000) {
  await expect
    .poll(async () => rulesText(page), { timeout })
    .not.toContain(needle);
}

test.describe('rule generation', () => {
  test('loads petstore sample and shows rules', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByTestId('rule-count')).toContainText(/\d+ rule/);
    await expectRulesContain(page, 'SecRule');
    await expectRulesContain(page, 'Path not defined in OpenAPI spec');
    await expectRulesContain(page, 'Host header not in OpenAPI-allowed hosts');
  });

  test('Monaco editor loads with YAML language highlighting', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByTestId('spec-editor').locator('.monaco-editor').first()).toBeVisible();
    await expect(page.getByTestId('language')).toHaveText('YAML');
  });

  test('rules output is rendered in a Monaco editor (SecLang)', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByTestId('rules-output').locator('.monaco-editor').first()).toBeVisible();
  });

  test('by default, pass rules do not carry msg (noise-free audit log)', async ({ page }) => {
    await page.goto('/');
    await expectRulesNotContain(page, 'debug: matched');
  });

  test('toggling debug mode re-enables msg on pass rules', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('toggle-debug').click();
    await expectRulesContain(page, 'debug: matched');
  });

  test('switching to a JSON sample flips the language indicator', async ({ page }) => {
    await page.goto('/');
    await page.evaluate(() =>
      (window as any).__setSpec(
        JSON.stringify(
          {
            openapi: '3.0.0',
            info: { title: 'J', version: '1.0.0' },
            paths: { '/a': { get: { responses: { '200': { description: 'ok' } } } } },
          },
          null,
          2,
        ),
      ),
    );
    await expect(page.getByTestId('language')).toHaveText('JSON');
    await expectRulesContain(page, 'SecRule');
  });

  test('toggling hostname enforcement removes the host rule', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('tab-routing').click();
    await page.getByTestId('toggle-hostname').click();
    await expectRulesNotContain(page, 'Host header');
  });

  test('changing starting rule id updates output', async ({ page }) => {
    await page.goto('/');
    const input = page.getByTestId('starting-id');
    await input.fill('5000000');
    await input.blur();
    await expect.poll(async () => rulesText(page), { timeout: 5000 }).toMatch(/id:50040\d{2}/);
  });

  test('strip-prefix config shifts URI matchers', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('tab-routing').click();
    await page.getByTestId('strip-prefix').fill('/api/v1');
    await expectRulesContain(page, '/api/v1');
  });

  test('standalone-detect mode drops deny actions', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('mode-select').selectOption('standalone-detect');
    await expectRulesContain(page, 'tx.coraza_openapi_mode=standalone-detect');
    await expectRulesNotContain(page, 'deny,status:');
  });

  test('crs-plugin mode emits anomaly-score contributions', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('mode-select').selectOption('crs-plugin');
    await expectRulesContain(page, 'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}');
    await expectRulesContain(page, 'OWASP_CRS/PLUGIN/CORAZA-OPENAPI');
  });

  test('disabling auth drops the Missing credentials rules', async ({ page }) => {
    await page.goto('/');
    await expectRulesContain(page, 'Missing credentials');
    await page.getByTestId('tab-auth').click();
    await page.getByTestId('toggle-auth').click();
    await expectRulesNotContain(page, 'Missing credentials');
  });

  test('blocking deprecated endpoints produces a 410 rule', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('tab-routing').click();
    await page.getByTestId('deprecated-select').selectOption('block');
    await expectRulesContain(page, 'status:410');
  });

  test('malformed spec shows error', async ({ page }) => {
    await page.goto('/');
    await page.evaluate(() => (window as any).__setSpec(':\n::\n:'));
    await expect(page.getByTestId('parse-error')).toBeVisible();
  });

  test('switching sample via button loads the minimal spec', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('sample-minimal').click();
    await expectRulesContain(page, 'Minimal');
  });

  test('download dropdown offers rules file and bundle', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('download-button').click();
    await expect(page.getByTestId('download-menu')).toBeVisible();
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByTestId('download-rules').click(),
    ]);
    expect(download.suggestedFilename()).toBe('openapi.conf');
  });

  test('download bundle yields a zip named after the CRS plugin convention', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('download-button').click();
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByTestId('download-bundle').click(),
    ]);
    expect(download.suggestedFilename()).toBe('coraza-openapi-bundle.zip');
  });

  test('crs-plugin mode downloads as coraza-openapi-plugin-after.conf', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('mode-select').selectOption('crs-plugin');
    await expect(page.getByTestId('output-filename')).toHaveText('coraza-openapi-plugin-after.conf');
    await page.getByTestId('download-button').click();
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByTestId('download-rules').click(),
    ]);
    expect(download.suggestedFilename()).toBe('coraza-openapi-plugin-after.conf');
  });

  test('undeclared endpoints — alert only drops deny, keeps rule', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('tab-routing').click();
    await page.getByTestId('undeclared-select').selectOption('alert');
    await expectRulesContain(page, 'alert only — not blocked');
    await expectRulesNotContain(page, 'Path not defined in OpenAPI spec');
  });

  test('undeclared endpoints — allow drops the catch-all entirely', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('tab-routing').click();
    await page.getByTestId('undeclared-select').selectOption('allow');
    await expectRulesNotContain(page, 'openapi/allowlist');
  });

  test('copy button shows a confirmation state + toast', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('/');
    const copy = page.getByTestId('copy-button');
    await copy.click();
    await expect(copy).toHaveAttribute('data-copied', 'true');
    await expect(copy).toContainText('Copied');
    await expect(page.getByTestId('toast').first()).toContainText('Copied');
  });

  test('clicking a sample button flashes and toasts', async ({ page }) => {
    await page.goto('/');
    const btn = page.getByTestId('sample-minimal');
    await btn.click();
    await expect(btn).toHaveAttribute('data-flashed', 'true');
    await expect(page.getByTestId('toast').first()).toContainText('Loaded minimal');
  });

  test('copy button writes to clipboard', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('/');
    await page.getByTestId('copy-button').click();
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    expect(clip).toContain('SecRule');
  });
});