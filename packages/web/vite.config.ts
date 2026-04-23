// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default defineConfig({
  base: process.env.VITE_BASE ?? '/',
  plugins: [
    react(),
    nodePolyfills({
      include: ['path', 'util', 'url', 'fs', 'http', 'buffer', 'process', 'events', 'stream'],
      globals: { process: true, Buffer: true, global: true },
    }),
  ],
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
  server: {
    port: 5173,
  },
  preview: {
    port: 4173,
  },
});