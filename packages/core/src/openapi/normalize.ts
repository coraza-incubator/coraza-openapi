// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import type {
  Diagnostic,
  NormalizedOperation,
  NormalizedParameter,
  NormalizedSchema,
  NormalizedSecurityRequirement,
  NormalizedSecurityScheme,
  NormalizedServer,
  NormalizedSpec,
  OpenAPIDocument,
} from '../types.js';

const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'] as const;

export function normalize(doc: OpenAPIDocument, rawHash: string): NormalizedSpec {
  const diagnostics: Diagnostic[] = [];
  const info = doc.info ?? { title: 'Untitled API', version: '0.0.0' };
  const servers = normalizeServers(doc, diagnostics);
  const securitySchemes = normalizeSecuritySchemes(doc, diagnostics);
  const globalSecurity = normalizeSecurity(doc.security);

  const operations: NormalizedOperation[] = [];
  const paths = doc.paths ?? {};
  for (const [pathItem, item] of Object.entries(paths)) {
    if (!item) continue;
    const pathLevelParams = extractParameters((item as any).parameters ?? [], diagnostics, `#/paths/${escapePath(pathItem)}`);
    for (const method of METHODS) {
      const op = (item as any)[method];
      if (!op) continue;
      const opPath = `#/paths/${escapePath(pathItem)}/${method}`;
      const opParams = extractParameters(op.parameters ?? [], diagnostics, opPath);
      const merged = mergeParams(pathLevelParams, opParams);
      const requestBody = op.requestBody;
      const requestContentTypes = requestBody?.content ? Object.keys(requestBody.content) : [];
      const requestBodyRequired = !!requestBody?.required;
      const security = op.security === undefined ? null : normalizeSecurity(op.security);

      operations.push({
        operationId: op.operationId,
        method: method.toUpperCase() as NormalizedOperation['method'],
        path: pathItem,
        pathRegex: pathToRegex(pathItem, merged),
        parameters: merged,
        requestContentTypes,
        requestBodyRequired,
        security,
        deprecated: !!op.deprecated,
        tags: op.tags ?? [],
        xCoraza: extractXCoraza(op),
      });
    }
  }

  if (operations.length === 0) {
    diagnostics.push({ level: 'warn', path: '#/paths', message: 'Spec contains no operations.' });
  }

  return {
    title: info.title,
    version: info.version,
    hash: rawHash,
    servers,
    operations,
    securitySchemes,
    globalSecurity,
    diagnostics,
  };
}

function escapePath(p: string): string {
  return p.replace(/~/g, '~0').replace(/\//g, '~1');
}

function mergeParams(a: NormalizedParameter[], b: NormalizedParameter[]): NormalizedParameter[] {
  const key = (p: NormalizedParameter) => `${p.in}:${p.name}`;
  const map = new Map<string, NormalizedParameter>();
  for (const p of a) map.set(key(p), p);
  for (const p of b) map.set(key(p), p);
  return [...map.values()];
}

function extractParameters(arr: any[], diagnostics: Diagnostic[], path: string): NormalizedParameter[] {
  const out: NormalizedParameter[] = [];
  for (const p of arr) {
    if (!p || typeof p !== 'object' || !p.name || !p.in) continue;
    if (!['query', 'header', 'path', 'cookie'].includes(p.in)) {
      diagnostics.push({ level: 'warn', path, message: `Unknown parameter location "${p.in}".` });
      continue;
    }
    out.push({
      name: p.name,
      in: p.in,
      required: p.in === 'path' ? true : !!p.required,
      deprecated: !!p.deprecated,
      schema: normalizeSchema(p.schema),
      style: p.style,
      explode: p.explode,
    });
  }
  return out;
}

function normalizeSchema(schema: any): NormalizedSchema | undefined {
  if (!schema || typeof schema !== 'object') return undefined;
  // OpenAPI 3.1 allows type to be an array.
  let type = schema.type;
  let nullable = schema.nullable;
  if (Array.isArray(type)) {
    if (type.includes('null')) nullable = true;
    type = type.find((t: string) => t !== 'null');
  }
  return {
    type,
    format: schema.format,
    enum: schema.enum,
    pattern: schema.pattern,
    minimum: schema.minimum,
    maximum: schema.maximum,
    minLength: schema.minLength,
    maxLength: schema.maxLength,
    nullable,
    items: normalizeSchema(schema.items),
  };
}

function normalizeServers(doc: OpenAPIDocument, diagnostics: Diagnostic[]): NormalizedServer[] {
  const servers = (doc.servers as any[]) ?? [];
  if (servers.length === 0) {
    diagnostics.push({
      level: 'info',
      path: '#/servers',
      message: 'No servers defined; hostname enforcement may need manual configuration.',
    });
    return [];
  }
  const out: NormalizedServer[] = [];
  for (const s of servers) {
    const resolved = applyServerVariables(s.url, s.variables);
    for (const url of resolved) {
      try {
        // Allow relative URLs like "/api/v1"
        const abs = url.startsWith('http') ? new URL(url) : new URL(url, 'http://localhost');
        out.push({
          url,
          host: url.startsWith('http') ? abs.host : undefined,
          basePath: abs.pathname === '/' ? '' : abs.pathname.replace(/\/$/, ''),
        });
      } catch {
        diagnostics.push({ level: 'warn', path: '#/servers', message: `Invalid server URL: ${url}` });
      }
    }
  }
  return out;
}

function applyServerVariables(url: string, variables: any): string[] {
  if (!variables) return [url];
  const names = Object.keys(variables);
  let out = [url];
  for (const name of names) {
    const values = variables[name].enum?.length ? variables[name].enum : [variables[name].default ?? ''];
    const next: string[] = [];
    for (const u of out) for (const v of values) next.push(u.replaceAll(`{${name}}`, String(v)));
    out = next;
  }
  return out;
}

function normalizeSecuritySchemes(doc: OpenAPIDocument, _diag: Diagnostic[]): Record<string, NormalizedSecurityScheme> {
  const schemes = (doc.components as any)?.securitySchemes ?? {};
  const out: Record<string, NormalizedSecurityScheme> = {};
  for (const [name, raw] of Object.entries<any>(schemes)) {
    if (!raw) continue;
    out[name] = {
      name,
      type: raw.type,
      in: raw.in,
      headerName: raw.type === 'apiKey' && raw.in === 'header' ? raw.name : undefined,
      scheme: raw.scheme,
      bearerFormat: raw.bearerFormat,
    };
  }
  return out;
}

function normalizeSecurity(sec: any): NormalizedSecurityRequirement[][] | null {
  if (sec === undefined || sec === null) return null;
  if (!Array.isArray(sec)) return null;
  return sec.map((req) =>
    Object.entries(req).map(([schemeName, scopes]) => ({
      schemeName,
      scopes: Array.isArray(scopes) ? (scopes as string[]) : [],
    })),
  );
}

function extractXCoraza(op: any): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(op)) {
    if (k.startsWith('x-coraza-')) out[k] = v;
  }
  return out;
}

/** Convert an OpenAPI path template (`/users/{id}`) to a Coraza/PCRE regex.
 *  Parameter patterns come from the schema: integer → \d+, uuid → uuid regex,
 *  enum → alternation, pattern → literal, default → [^/]+. */
export function pathToRegex(path: string, params: NormalizedParameter[]): string {
  const byName = new Map(params.filter((p) => p.in === 'path').map((p) => [p.name, p] as const));
  let regex = '^';
  let i = 0;
  while (i < path.length) {
    const c = path[i];
    if (c === '{') {
      const end = path.indexOf('}', i);
      if (end === -1) {
        regex += escapeRegex(path.slice(i));
        break;
      }
      const name = path.slice(i + 1, end);
      const p = byName.get(name);
      regex += paramRegex(p?.schema);
      i = end + 1;
    } else {
      regex += escapeRegex(c);
      i++;
    }
  }
  regex += '(?:\\?.*)?$';
  return regex;
}

function paramRegex(schema?: NormalizedSchema): string {
  if (!schema) return '[^/]+';
  if (schema.enum && schema.enum.length > 0) {
    return '(?:' + schema.enum.map((v) => escapeRegex(String(v))).join('|') + ')';
  }
  if (schema.pattern) {
    return '(?:' + safePattern(schema.pattern) + ')';
  }
  if (schema.type === 'integer') return '-?\\d+';
  if (schema.type === 'number') return '-?\\d+(?:\\.\\d+)?';
  if (schema.type === 'boolean') return '(?:true|false)';
  if (schema.format === 'uuid') {
    return '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
  }
  return '[^/]+';
}

function safePattern(p: string): string {
  // Strip outer anchors; Coraza @rx patterns are unanchored unless we add them.
  let s = p;
  if (s.startsWith('^')) s = s.slice(1);
  if (s.endsWith('$')) s = s.slice(0, -1);
  return s;
}

export function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}