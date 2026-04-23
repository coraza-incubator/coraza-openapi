import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['packages/web/test/setup.ts'],
    include: [
      'packages/core/src/**/*.test.ts',
      'packages/cli/src/**/*.test.ts',
      'packages/web/src/**/*.test.{ts,tsx}',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['packages/core/src/**/*.ts', 'packages/cli/src/**/*.ts'],
      exclude: [
        '**/*.test.*',
        '**/dist/**',
        'packages/cli/src/bin.ts',
        'packages/cli/src/commands/serve.ts',
      ],
      thresholds: {
        lines: 85,
        statements: 85,
        functions: 85,
        branches: 75,
      },
    },
  },
});
