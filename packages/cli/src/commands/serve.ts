// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize, resolve } from 'node:path';
import pc from 'picocolors';

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json',
  '.map': 'application/json',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

export async function runServe(flags: Record<string, unknown>): Promise<number> {
  const port = Number(flags['port'] ?? 4173);
  // dist/bin.js → dist/../www  (populated at publish time)
  const here = dirname(fileURLToPath(import.meta.url));
  const root = resolve(here, '..', 'www');
  try {
    await stat(root);
  } catch {
    console.error(
      pc.red(
        `Bundled web UI not found at ${root}.\n` +
          `Run "npm run build" in the monorepo so packages/web/dist is available,\n` +
          `or install a published release that includes the bundled assets.`,
      ),
    );
    return 1;
  }
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      let path = normalize(url.pathname);
      if (path === '/' || path.endsWith('/')) path += 'index.html';
      const file = join(root, path);
      if (!file.startsWith(root)) {
        res.statusCode = 403;
        res.end('forbidden');
        return;
      }
      const data = await readFile(file);
      const ext = file.slice(file.lastIndexOf('.'));
      res.setHeader('Content-Type', MIME[ext] ?? 'application/octet-stream');
      res.end(data);
    } catch {
      res.statusCode = 404;
      res.end('not found');
    }
  });
  server.listen(port, () => {
    console.error(pc.green(`coraza-openapi serving on http://localhost:${port}`));
  });
  return await new Promise((resolvePromise) => {
    server.on('close', () => resolvePromise(0));
  });
}