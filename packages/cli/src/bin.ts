#!/usr/bin/env node

// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import cac from 'cac';
import { runGenerate } from './commands/generate.js';
import { runValidate } from './commands/validate.js';
import { runInitConfig } from './commands/initConfig.js';
import { runDiff } from './commands/diff.js';
import { runServe } from './commands/serve.js';

const cli = cac('coraza-openapi');

cli
  .command('generate <input>', 'Generate Coraza rules from an OpenAPI spec (use - for stdin)')
  .option('-o, --output <file>', 'Write output to file instead of stdout')
  .option('--config <file>', 'Config file (JSON/YAML/JS)')
  .option('--format <fmt>', 'Output format: seclang (default) or json')
  .option('--starting-id <n>', 'Starting rule ID', { type: [Number] })
  .option('--tag-prefix <prefix>', 'Tag prefix (default: openapi/)')
  .option('--host <list>', 'Comma-separated allowed hosts')
  .option('--strip-prefix <p>', 'Strip this path prefix before matching')
  .option('--add-prefix <p>', 'Add this path prefix when matching')
  .option('--enforce-auth', 'Enforce security schemes (default: on)')
  .option('--no-enforce-auth', 'Disable auth enforcement')
  .option('--no-validate-types', 'Disable parameter type validation')
  .option('--block-deprecated', 'Block deprecated endpoints with 410')
  .option('--mode <mode>', 'standalone-block | standalone-detect | crs-plugin')
  .option('--detection-only', 'Alias for --mode standalone-detect')
  .option('--crs-plugin', 'Alias for --mode crs-plugin (contributes to CRS anomaly score)')
  .option('--debug', 'Annotate every rule with a msg: (off by default; deny rules always get msg)')
  .option('--strict', 'Fail on warnings')
  .action(async (input: string, flags: Record<string, unknown>) => {
    process.exit(await runGenerate(input, flags));
  });

cli
  .command('validate <input>', 'Parse a spec and print diagnostics')
  .option('--strict', 'Fail on warnings')
  .action(async (input: string, flags: Record<string, unknown>) => {
    process.exit(await runValidate(input, flags));
  });

cli
  .command('init-config [output]', 'Write a default config file')
  .action(async (output = 'coraza-openapi.config.json') => {
    process.exit(await runInitConfig(output));
  });

cli
  .command('diff <old> <new>', 'Diff generated rules between two spec versions')
  .option('--config <file>', 'Config file')
  .action(async (a: string, b: string, flags: Record<string, unknown>) => {
    process.exit(await runDiff(a, b, flags));
  });

cli
  .command('serve', 'Serve the web UI from bundled assets')
  .option('--port <n>', 'Port', { default: 4173 })
  .option('--open', 'Open browser (not implemented yet)')
  .action(async (flags: Record<string, unknown>) => {
    process.exit(await runServe(flags));
  });

cli.help();
cli.version('0.1.0');
cli.parse();
