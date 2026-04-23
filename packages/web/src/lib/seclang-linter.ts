// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
// Minimal SecLang linter, surfaced as Monaco markers. Not a full parser —
// just a shallow line-oriented sanity check against known directives,
// variables, operators, and action keys. The goal is to flag obvious typos
// in the generated output (and any hand-edits).

import type { monaco as Monaco } from './monaco-setup.js';

const OWNER = 'seclang';

// Lowercased for case-insensitive comparisons.
const KNOWN_DIRECTIVES = new Set([
  'secrule',
  'secaction',
  'secmarker',
  'secruleengine',
  'secdefaultaction',
  'secrequestbodyaccess',
  'secrequestbodylimit',
  'secrequestbodylimitaction',
  'secrequestbodynofileslimit',
  'secrequestbodyinmemorylimit',
  'secresponsebodyaccess',
  'secresponsebodylimit',
  'secresponsebodylimitaction',
  'secresponsebodymimetype',
  'seccomponentsignature',
  'secauditengine',
  'secauditlog',
  'secauditlogformat',
  'secauditlogparts',
  'secauditlogrelevantstatus',
  'secauditlogtype',
  'secauditlogstoragedir',
  'secdata',
  'secdebuglog',
  'secdebugloglevel',
  'secgeodatabase',
  'secmarker',
  'secpcrematchlimit',
  'secpcrematchlimitrecursion',
  'secrequestbodyjsondepthlimit',
  'secrulestarttime',
  'secruleupdateactionbyid',
  'secruleupdatetargetbyid',
  'secruleupdatetargetbytag',
  'secruleremovebyid',
  'secruleremovebytag',
  'secruleremovebymsg',
  'secsensoid',
  'secserverlogformat',
  'sectmpdir',
  'secupload',
  'secuploadkeepfiles',
  'secuploaddir',
  'include',
  'includeoptional',
]);

const KNOWN_VARIABLES = new Set([
  'args',
  'args_get',
  'args_post',
  'args_names',
  'args_get_names',
  'args_post_names',
  'request_method',
  'request_uri',
  'request_uri_raw',
  'request_headers',
  'request_headers_names',
  'request_cookies',
  'request_cookies_names',
  'request_body',
  'request_body_length',
  'request_filename',
  'request_basename',
  'request_protocol',
  'request_line',
  'query_string',
  'response_body',
  'response_headers',
  'response_headers_names',
  'response_status',
  'response_protocol',
  'matched_var',
  'matched_var_name',
  'matched_vars',
  'matched_vars_names',
  'files',
  'files_names',
  'files_sizes',
  'files_combined_size',
  'files_tmpnames',
  'remote_addr',
  'remote_host',
  'remote_port',
  'remote_user',
  'server_name',
  'server_addr',
  'server_port',
  'session',
  'sessionid',
  'ip',
  'tx',
  'env',
  'global',
  'resource',
  'user',
  'unique_id',
  'duration',
  'highest_severity',
  'inbound_data_error',
  'outbound_data_error',
  'multipart_crlf_lf_lines',
  'multipart_strict_error',
  'multipart_unmatched_boundary',
  'reqbody_error',
  'reqbody_error_msg',
  'reqbody_processor',
  'reqbody_processor_error',
  'full_request',
  'full_request_length',
  'stream_input_body',
  'stream_output_body',
  'urlencoded_error',
  'xml',
  'auth_type',
]);

const KNOWN_OPERATORS = new Set([
  '@rx',
  '@beginswith',
  '@endswith',
  '@contains',
  '@containsword',
  '@streq',
  '@eq',
  '@ne',
  '@ge',
  '@gt',
  '@le',
  '@lt',
  '@within',
  '@pm',
  '@pmfromfile',
  '@pmf',
  '@ipmatch',
  '@ipmatchfromfile',
  '@ipmatchf',
  '@geolookup',
  '@gsblookup',
  '@validateurl',
  '@validateutf8encoding',
  '@validatebyterange',
  '@validateschema',
  '@validatedtd',
  '@verifycc',
  '@verifycpf',
  '@verifyssn',
  '@detectsqli',
  '@detectxss',
  '@fuzzyhash',
  '@noop',
  '@unconditionalmatch',
  '@inspectfile',
  '@rbl',
]);

const KNOWN_ACTION_KEYS = new Set([
  'id',
  'phase',
  'deny',
  'pass',
  'block',
  'allow',
  'drop',
  'redirect',
  'proxy',
  'status',
  'msg',
  'logdata',
  'tag',
  't',
  'chain',
  'nolog',
  'log',
  'auditlog',
  'noauditlog',
  'ctl',
  'setvar',
  'setenv',
  'setuid',
  'setsid',
  'setrsc',
  'expirevar',
  'initcol',
  'exec',
  'skip',
  'skipafter',
  'append',
  'prepend',
  'rev',
  'ver',
  'severity',
  'capture',
  'multimatch',
  'sanitisearg',
  'sanitisematched',
  'sanitisematchedbytes',
  'sanitiserequestheader',
  'sanitiseresponseheader',
  'accuracy',
  'maturity',
  'transform',
  'xmlns',
]);

const KNOWN_TRANSFORMS = new Set([
  'none',
  'lowercase',
  'uppercase',
  'length',
  'hexencode',
  'hexdecode',
  'base64decode',
  'base64decodeext',
  'base64encode',
  'cssdecode',
  'cmdline',
  'compresswhitespace',
  'removewhitespace',
  'removenulls',
  'removecommentschar',
  'removecomments',
  'replacecomments',
  'replacenulls',
  'escapeseqdecode',
  'htmlentitydecode',
  'jsdecode',
  'md5',
  'sha1',
  'normalisepath',
  'normalisepathwin',
  'normalizepath',
  'normalizepathwin',
  'parityeven7bit',
  'parityodd7bit',
  'parityzero7bit',
  'sqlhexdecode',
  'trim',
  'trimleft',
  'trimright',
  'urldecode',
  'urldecodeuni',
  'urlencode',
  'utf8tounicode',
]);

type Marker = {
  startLineNumber: number;
  startColumn: number;
  endLineNumber: number;
  endColumn: number;
  message: string;
  severity: number;
};

/** Join `\`-continued lines into logical lines, keeping a map back to the
 *  starting physical line number so markers can point somewhere useful. */
function joinLogicalLines(text: string): { logical: string; physicalLine: number }[] {
  const out: { logical: string; physicalLine: number }[] = [];
  const lines = text.split('\n');
  let buf = '';
  let start = 0;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (buf === '') start = i;
    if (raw.endsWith('\\')) {
      buf += raw.slice(0, -1) + ' ';
      continue;
    }
    buf += raw;
    out.push({ logical: buf, physicalLine: start + 1 });
    buf = '';
  }
  if (buf !== '') out.push({ logical: buf, physicalLine: start + 1 });
  return out;
}

export function lintSeclang(text: string, monaco: typeof Monaco): Marker[] {
  const WARNING = monaco.MarkerSeverity.Warning;
  const ERROR = monaco.MarkerSeverity.Error;
  const markers: Marker[] = [];

  const logicals = joinLogicalLines(text);
  let continuingChain = false; // true when the previous logical line ended in `chain` or `chain"`
  for (const { logical, physicalLine } of logicals) {
    const line = logical.trim();
    if (!line || line.startsWith('#')) continue;

    const directive = (line.match(/^(\w+)/)?.[1] ?? '').toLowerCase();
    if (!KNOWN_DIRECTIVES.has(directive)) {
      markers.push(mark(physicalLine, 1, physicalLine, 1 + directive.length,
        `Unknown directive "${directive}".`, ERROR));
      continuingChain = false;
      continue;
    }

    if (directive === 'secrule') {
      // A SecRule that continues a chain has no id and limited actions —
      // skip the id check but still lint the operator and variables.
      lintSecRule(line, physicalLine, markers, WARNING, ERROR, continuingChain);
    } else if (directive === 'secaction') {
      const action = extractQuoted(line.slice('secaction'.length).trim());
      if (action) lintActions(action, physicalLine, markers, WARNING, ERROR);
    } else if (directive === 'secmarker' || directive === 'include' || directive === 'includeoptional') {
      const rest = line.slice(directive.length).trim();
      if (!rest) {
        markers.push(mark(physicalLine, 1, physicalLine, line.length + 1,
          `${directive} requires an argument.`, ERROR));
      }
    }

    // A logical line "continues a chain" into the next one if its action
    // block ends with the literal `chain` action. Joined logical lines can
    // have whitespace between the comma separator and the action because
    // CRS-style rules use `\`-continuations + indentation.
    continuingChain = /(?:^|,)\s*chain\s*"?\s*$/.test(line);
  }
  return markers;
}

function mark(
  sl: number, sc: number, el: number, ec: number, message: string, severity: number,
): Marker {
  return { startLineNumber: sl, startColumn: sc, endLineNumber: el, endColumn: ec, message, severity };
}

function extractQuoted(s: string): string | null {
  const m = s.match(/^"([\s\S]*)"\s*$/);
  return m ? m[1] : null;
}

function lintSecRule(
  line: string, physicalLine: number, markers: Marker[],
  WARNING: number, ERROR: number, isChainContinuation: boolean,
) {
  // A chain-continuation SecRule looks like: SecRule VARS "OP" "t:none[,...]"
  // (no id, no phase). The full form is: SecRule VARS "OP" "ACTIONS".
  const full = line.match(/^SecRule\s+(\S+)\s+"([^"]*)"\s+"([\s\S]*)"\s*$/i);
  const noActions = line.match(/^SecRule\s+(\S+)\s+"([^"]*)"\s*$/i);
  if (!full && !noActions) {
    markers.push(mark(physicalLine, 1, physicalLine, 8,
      'SecRule must be: SecRule VARIABLES "OPERATOR" ["ACTIONS"].', ERROR));
    return;
  }
  const varPart = (full ?? noActions!)[1];
  const opPart = (full ?? noActions!)[2];
  lintVariables(varPart, physicalLine, markers, WARNING);
  lintOperator(opPart, physicalLine, markers, WARNING);
  if (full) {
    lintActions(full[3], physicalLine, markers, WARNING, ERROR, isChainContinuation);
  }
}

function lintVariables(varPart: string, physicalLine: number, markers: Marker[], WARNING: number) {
  for (const segment of varPart.split('|')) {
    const bare = segment.replace(/^[!&]+/, '').split(':')[0];
    if (!bare) continue;
    if (!KNOWN_VARIABLES.has(bare.toLowerCase())) {
      markers.push(mark(physicalLine, 1, physicalLine, 1,
        `Unknown variable "${bare}".`, WARNING));
    }
  }
}

function lintOperator(opPart: string, physicalLine: number, markers: Marker[], WARNING: number) {
  const m = opPart.match(/^!?(@\w+)/);
  if (!m) {
    // No operator → defaults to @rx; ok.
    return;
  }
  const op = m[1].toLowerCase();
  if (!KNOWN_OPERATORS.has(op)) {
    markers.push(mark(physicalLine, 1, physicalLine, 1,
      `Unknown operator "${op}".`, WARNING));
  }
}

function lintActions(
  actionPart: string, physicalLine: number, markers: Marker[],
  WARNING: number, ERROR: number, isChainContinuation: boolean = false,
) {
  // Split on commas that are not inside quotes.
  const parts: string[] = [];
  let buf = '';
  let quote: string | null = null;
  for (const ch of actionPart) {
    if (quote) {
      if (ch === quote) quote = null;
      buf += ch;
      continue;
    }
    if (ch === '"' || ch === '\'') {
      quote = ch;
      buf += ch;
      continue;
    }
    if (ch === ',') {
      parts.push(buf.trim());
      buf = '';
      continue;
    }
    buf += ch;
  }
  if (buf.trim()) parts.push(buf.trim());

  let hasId = false;
  for (const p of parts) {
    if (!p) continue;
    const key = p.split(':')[0].toLowerCase();
    if (key === 'id') hasId = true;
    if (!KNOWN_ACTION_KEYS.has(key)) {
      markers.push(mark(physicalLine, 1, physicalLine, 1,
        `Unknown action "${key}".`, WARNING));
      continue;
    }
    if (key === 't') {
      const val = p.slice(2).toLowerCase();
      if (val && !KNOWN_TRANSFORMS.has(val)) {
        markers.push(mark(physicalLine, 1, physicalLine, 1,
          `Unknown transform "t:${val}".`, WARNING));
      }
    }
    if (key === 'phase') {
      const v = p.slice(6).trim();
      if (!/^[1-5]$|^(request|response|logging)$/i.test(v)) {
        markers.push(mark(physicalLine, 1, physicalLine, 1,
          `phase must be 1..5 (or request/response/logging), got "${v}".`, ERROR));
      }
    }
  }
  if (!hasId && !isChainContinuation) {
    markers.push(mark(physicalLine, 1, physicalLine, 1,
      'SecRule/SecAction is missing the required `id:` action.', ERROR));
  }
}

/** Wire the linter onto the Monaco global. Call once. */
export function registerSeclangLinter(monaco: typeof Monaco): void {
  const run = (model: ReturnType<typeof monaco.editor.createModel>) => {
    if (model.getLanguageId() !== 'seclang') return;
    const markers = lintSeclang(model.getValue(), monaco);
    monaco.editor.setModelMarkers(model, OWNER, markers);
  };
  for (const m of monaco.editor.getModels()) run(m);
  monaco.editor.onDidCreateModel((m) => {
    run(m);
    m.onDidChangeContent(() => run(m));
  });
}