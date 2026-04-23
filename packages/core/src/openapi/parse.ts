// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import SwaggerParser from '@apidevtools/swagger-parser';
import YAML from 'yaml';
import type { OpenAPIDocument } from '../types.js';

export type ParseResult =
  | { ok: true; doc: OpenAPIDocument; rawHash: string; raw: string }
  | { ok: false; error: string };

/** Parse raw YAML/JSON text into a dereferenced OpenAPI 3.x document.
 *  Swagger 2.0 inputs are auto-converted. */
export async function parseSpec(text: string): Promise<ParseResult> {
  if (!text || !text.trim()) {
    return { ok: false, error: 'Empty spec input.' };
  }
  let raw: unknown;
  try {
    raw = YAML.parse(text);
  } catch (e) {
    return { ok: false, error: `Failed to parse YAML/JSON: ${(e as Error).message}` };
  }
  if (!raw || typeof raw !== 'object') {
    return { ok: false, error: 'Spec root must be an object.' };
  }

  const rec = raw as Record<string, unknown>;

  // Swagger 2.0 → OpenAPI 3.0 conversion (dynamically imported so the
  // Node-only deps aren't loaded in browser bundles unless actually needed).
  if (typeof rec.swagger === 'string' && rec.swagger.startsWith('2.')) {
    try {
      const { convertObj } = await import('swagger2openapi');
      const converted = await convertObj(rec as any, { patch: true, warnOnly: true });
      rec['openapi'] = '3.0.0';
      Object.assign(rec, converted.openapi);
    } catch (e) {
      return { ok: false, error: `Failed to convert Swagger 2.0: ${(e as Error).message}` };
    }
  }

  if (typeof rec.openapi !== 'string') {
    return { ok: false, error: 'Missing "openapi" version string.' };
  }

  try {
    const doc = (await SwaggerParser.dereference(rec as any, {
      dereference: { circular: 'ignore' },
    })) as OpenAPIDocument;
    const rawHash = await sha256(text);
    return { ok: true, doc, rawHash, raw: text };
  } catch (e) {
    return { ok: false, error: `Invalid OpenAPI document: ${(e as Error).message}` };
  }
}

async function sha256(text: string): Promise<string> {
  // Works in Node ≥ 20 and all modern browsers.
  const bytes = new TextEncoder().encode(text);
  if (typeof globalThis.crypto?.subtle?.digest === 'function') {
    const hash = await globalThis.crypto.subtle.digest('SHA-256', bytes);
    return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
  }
  // Fallback: simple FNV-1a (test environments only).
  let h = 0x811c9dc5;
  for (const b of bytes) {
    h ^= b;
    h = (h * 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}