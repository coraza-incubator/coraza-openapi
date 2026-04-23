// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { loader } from '@monaco-editor/react';
import * as monaco from 'monaco-editor';
import editorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker';
import jsonWorker from 'monaco-editor/esm/vs/language/json/json.worker?worker';
import { configureMonacoYaml } from 'monaco-yaml';
import yamlWorker from 'monaco-yaml/yaml.worker?worker';

// Point @monaco-editor/react at our bundled monaco (no CDN).
loader.config({ monaco });

// Register workers.
(self as any).MonacoEnvironment = {
  getWorker(_: string, label: string) {
    if (label === 'json') return new jsonWorker();
    if (label === 'yaml') return new yamlWorker();
    return new editorWorker();
  },
};

const OPENAPI_31_SCHEMA_URI = 'https://spec.openapis.org/oas/3.1/schema/2022-10-07';
const OPENAPI_30_SCHEMA_URI = 'https://spec.openapis.org/oas/3.0/schema/2021-09-28';

// JSON: hook OpenAPI 3.1 + 3.0 schemas against the single model URI the editor uses.
(monaco.languages as any).json.jsonDefaults.setDiagnosticsOptions({
  validate: true,
  allowComments: false,
  schemas: [
    {
      uri: OPENAPI_31_SCHEMA_URI,
      fileMatch: ['openapi.json', 'inmemory://model/*.json'],
      schema: { $ref: OPENAPI_31_SCHEMA_URI },
    },
  ],
  enableSchemaRequest: true,
});

// YAML: same deal, via monaco-yaml.
configureMonacoYaml(monaco, {
  enableSchemaRequest: true,
  hover: true,
  completion: true,
  validate: true,
  format: true,
  schemas: [
    {
      uri: OPENAPI_31_SCHEMA_URI,
      fileMatch: ['*'],
      schema: { $ref: OPENAPI_31_SCHEMA_URI } as any,
    },
    {
      uri: OPENAPI_30_SCHEMA_URI,
      fileMatch: [],
      schema: { $ref: OPENAPI_30_SCHEMA_URI } as any,
    },
  ],
});

// ─── SecLang (ModSecurity / Coraza) custom language ───────────────────────
monaco.languages.register({ id: 'seclang', extensions: ['.conf'], aliases: ['SecLang', 'seclang', 'ModSecurity'] });

monaco.languages.setLanguageConfiguration('seclang', {
  comments: { lineComment: '#' },
  brackets: [['(', ')'], ['[', ']'], ['{', '}']],
  autoClosingPairs: [
    { open: '"', close: '"' },
    { open: "'", close: "'" },
    { open: '(', close: ')' },
  ],
});

monaco.languages.setMonarchTokensProvider('seclang', {
  defaultToken: '',
  tokenPostfix: '.seclang',
  keywords: [
    'SecRule',
    'SecAction',
    'SecRuleEngine',
    'SecDefaultAction',
    'SecRequestBodyLimit',
    'SecRequestBodyLimitAction',
    'SecRequestBodyAccess',
    'SecResponseBodyAccess',
    'SecMarker',
    'SecComponentSignature',
    'Include',
    'IncludeOptional',
  ],
  variables: [
    'REQUEST_METHOD', 'REQUEST_URI', 'REQUEST_URI_RAW', 'REQUEST_HEADERS', 'REQUEST_COOKIES',
    'REQUEST_BODY', 'REQUEST_PROTOCOL', 'ARGS', 'ARGS_GET', 'ARGS_POST', 'ARGS_NAMES',
    'RESPONSE_BODY', 'RESPONSE_HEADERS', 'RESPONSE_STATUS', 'TX', 'REMOTE_ADDR', 'SERVER_NAME',
  ],
  actions: [
    'id', 'phase', 'deny', 'pass', 'block', 'allow', 'drop', 'redirect',
    'status', 'msg', 'logdata', 'tag', 't', 'chain', 'nolog', 'log', 'auditlog',
    'noauditlog', 'initcol', 'setvar', 'setenv', 'skip', 'skipAfter', 'ctl', 'rev', 'ver', 'severity',
  ],
  operators: [
    '@rx', '@streq', '@eq', '@gt', '@ge', '@lt', '@le', '@contains', '@beginsWith',
    '@endsWith', '@within', '@pm', '@pmFromFile', '@ipMatch',
  ],
  tokenizer: {
    root: [
      [/#.*$/, 'comment'],
      // SecMarker labels can contain hyphens — tokenize the whole label
      // after the directive as an identifier so syntax highlighting stays
      // intact for things like `SecMarker END-OPENAPI-OPMATCH`.
      [/\bSecMarker\s+[A-Za-z0-9_][A-Za-z0-9_-]*/, 'keyword'],
      // Match the directive anywhere on a line (not just at column 0) so
      // chain-continuation SecRules, which are indented under their outer
      // rule, still get highlighted.
      [/\b(SecRule|SecAction|SecRuleEngine|SecDefaultAction|SecRequestBodyLimit|SecRequestBodyLimitAction|SecMarker|Include|IncludeOptional)\b/, 'keyword'],
      [/\b(REQUEST_METHOD|REQUEST_URI_RAW|REQUEST_URI|REQUEST_HEADERS|REQUEST_COOKIES|REQUEST_BODY|ARGS_GET|ARGS_POST|ARGS_NAMES|ARGS|TX|REMOTE_ADDR|SERVER_NAME|RESPONSE_BODY|RESPONSE_HEADERS|RESPONSE_STATUS|REQUEST_PROTOCOL)\b/, 'type'],
      [/!?@(rx|streq|eq|gt|ge|lt|le|contains|beginsWith|endsWith|within|pmFromFile|pm|ipMatch)\b/, 'operator'],
      [/\b(id|phase|status|msg|logdata|tag|t|chain|nolog|log|auditlog|noauditlog|setvar|setenv|skip|skipAfter|ctl|rev|ver|severity|initcol):/, 'attribute.name'],
      [/\b(deny|pass|block|allow|drop|redirect)\b/, 'keyword.control'],
      [/"([^"\\]|\\.)*"/, 'string'],
      [/'([^'\\]|\\.)*'/, 'string'],
      [/\b\d+\b/, 'number'],
      [/&?[A-Z_][A-Z0-9_-]*/, 'type'],
      [/:[A-Za-z0-9_-]+/, 'string.attribute'],
    ],
  },
});

// Wire the SecLang diagnostics linter (markers in the gutter for unknown
// directives, misspelled actions, missing `id:`, bad `phase:`, etc.).
import { registerSeclangLinter } from './seclang-linter.js';
registerSeclangLinter(monaco);

export { monaco };