# AGENTS.md

Instructions for AI coding agents (Claude Code, Cursor, Copilot, etc.) working in this repository.

## What this project is

`coraza-openapi` converts an OpenAPI 3.x specification into a Coraza WAF ruleset. It ships as:

1. **`@coraza-openapi/core`** — pure-TS library (`packages/core`). No DOM, no Node-only APIs at the top level. All rule-generation logic lives here.
2. **`@coraza-openapi/web`** — Vite + React 19 single-page app (`packages/web`). Depends on `core`.
3. **`coraza-openapi`** — Node CLI (`packages/cli`). Depends on `core`. Ships a `serve` subcommand that serves the SPA from bundled assets (paved for future `npm publish`).

The monorepo uses npm workspaces. Deployed via GitHub Actions to GitHub Pages on every push to `main` (base path `/coraza-openapi/`).

## Ground rules

- **Keep generation logic in `core`.** The web app and CLI must not duplicate parsing/rule code — if they need new behavior, it goes in `core` first and both consumers pick it up.
- **Do not break the browser bundle.** `core` must stay importable from a Vite/rolldown build. Avoid top-level imports of Node-only packages (e.g. `swagger2openapi` is dynamically imported only when a Swagger 2.0 input is detected). Node polyfills are configured in `packages/web/vite.config.ts`; prefer avoiding new Node deps over adding more polyfills.
- **Config is a single zod schema** (`packages/core/src/config/schema.ts`). The CLI flag mapper and the React config panel both derive from it. When adding a new option: update the schema, add the generator hook in `packages/core/src/generator/`, surface it in `ConfigPanel.tsx`, and add a `--flag` in `packages/cli/src/loadConfig.ts` and `packages/cli/src/bin.ts`.
- **Tests gate merges.** `npm test` (Vitest) + `npm run test:e2e` (Playwright) must pass before a PR can land. `npm run lint` and `npm run typecheck` too. CI enforces these.
- **Coverage threshold.** Core + CLI paths should stay above the thresholds configured in `vitest.config.ts`. Add tests alongside new generators.
- **OpenAPI fidelity matters.** This tool is advertised as having "strong OpenAPI support." When in doubt, consult the spec rather than guessing (OpenAPI 3.1 — https://spec.openapis.org/oas/v3.1.0; Coraza SecLang — https://coraza.io/docs/seclang/directives/).

## Common tasks

### Add a new rule generator

1. Add a pure function under `packages/core/src/generator/rules/<name>.ts` with signature
   `(spec: NormalizedSpec, config: Config, ids: IdAllocator) => SecEntry[]`.
2. Wire it into `packages/core/src/generator/index.ts` in the right position.
3. Extend the zod schema (`config/schema.ts`) if it needs configuration.
4. Add unit tests in `packages/core/src/generator/index.test.ts` that toggle the option on/off and assert on generated SecLang output.
5. Surface it in `ConfigPanel.tsx` under the appropriate tab.
6. Add a CLI flag in `packages/cli/src/loadConfig.ts` (`applyFlagOverrides`) and `packages/cli/src/bin.ts`.

### Add support for an OpenAPI feature

1. Extend `NormalizedSpec` / `NormalizedOperation` in `packages/core/src/types.ts`.
2. Populate it in `packages/core/src/openapi/normalize.ts`.
3. Consume it in the relevant generator.
4. Add a fixture-based test.

### Update dependencies

- Use the latest stable versions. Avoid deprecated transitive deps — run `npm ls <dep>` if `npm install` warns.
- Do not downgrade Vite/Vitest/React majors without a reason documented in the PR.

## Scripts

```bash
npm install
npm run build:core       # must run before web/cli typecheck (workspace dep)
npm run dev              # vite dev server for the SPA
npm test                 # vitest
npm run test:coverage    # vitest with coverage thresholds
npm run test:e2e         # playwright (builds and previews the SPA first)
npm run lint
npm run typecheck
```

## Do / Don't

- **Do** use `data-testid` attributes for anything the Playwright suite needs to locate.
- **Do** keep generator output deterministic — rule ordering and IDs are stable; don't introduce `Math.random()` or `Date.now()` outputs.
- **Don't** add UI state that isn't derivable from the Zustand store — the test suite relies on regeneration being triggered by store changes.
- **Don't** commit `packages/web/dist`, coverage artifacts, or Playwright reports (see `.gitignore`).
- **Don't** skip hooks (`--no-verify`) on commits.

## Release (future — not yet enabled)

When the maintainers decide to publish:

1. `packages/cli` will bundle `packages/web/dist` into `cli/dist/www/` so `coraza-openapi serve` works standalone.
2. `coraza-openapi` on npm will be published from `packages/cli`.
3. `@coraza-openapi/core` on npm will be published for programmatic use.

Until then, do not add any `npm publish` workflow.
