# coraza-openapi

> ⚠️ **Experimental.** This project is a work-in-progress and its output has
> not been battle-tested against production traffic. Rule IDs, tag
> conventions, and the CLI surface may change without notice. Review the
> generated rules before deploying them in front of real services.

Generate [Coraza](https://coraza.io) WAF rules from an OpenAPI 3.x specification.
A one-page web UI plus a Node CLI share the same rule generator.

- **Web UI** — paste a spec, get rules on the right, tweak enforcement in the config panel.
- **CLI** (`coraza-openapi`) — runs the same generator from a terminal or CI pipeline.
- **Deployed** automatically to GitHub Pages on every push to `main`.

## What this bundle is (and is not)

- It emits **rules only**. Engine-global directives (`SecRuleEngine`,
  `SecDefaultAction`, `SecRequestBodyLimit`, `SecRequestBodyLimitAction`,
  audit engine settings, etc.) are **intentionally not** emitted — those
  belong in your `coraza.conf` / `crs-setup.conf`. The configured values are
  surfaced as `tx.coraza_openapi_*` TX variables at the top of the output
  so operators can patch them without regenerating.
- It's designed to load **in front of** the OWASP CRS, not replace it.

## What the generator enforces

From any OpenAPI 3.0 / 3.1 document (Swagger 2.0 is auto-upgraded):

- **Routing**: allowlist of paths, method-per-path, hostname from `servers[]`, path prefix strip/add.
- **Auth**: required credentials (`apiKey`, `http`, `oauth2`, `openIdConnect`) per operation, honoring global and per-operation `security`.
- **Validation**: required query/header/cookie params, type (`integer`/`number`/`boolean`/`uuid`), enums, regex `pattern`, length bounds, `Content-Type` allowlist from `requestBody.content`.
- **Limits**: max body size, URI length, header count, query-parameter count.
- **Policy**: deprecated endpoints (allow / warn / 410), detection-only vs block, custom starting rule ID + tag prefix.
- **Hints**: `x-coraza-rate-limit` spec extensions are emitted as comments; CORS origin allowlist from servers.

Spec authors can override per-operation behavior inline with `x-coraza-*` extensions
(e.g. `x-coraza-skip: true`, `x-coraza-rate-limit: 100/min`).

## Repo layout

```
packages/
  core/    # @coraza-openapi/core — parse + generate (pure TS, no DOM/Node deps)
  web/     # @coraza-openapi/web  — Vite + React 19 SPA
  cli/     # coraza-openapi       — CLI wrapping core + serving the SPA
```

## Local development

```bash
npm install
npm run build:core   # build the shared core first (workspace dep)
npm run dev          # starts web at http://localhost:5173
npm test             # vitest
npm run test:e2e     # playwright
```

## CLI

```bash
# One-shot from a file
npx coraza-openapi generate openapi.yaml -o coraza.conf

# From stdin
cat openapi.yaml | npx coraza-openapi generate - > coraza.conf

# CI-friendly (non-zero exit on parse error; --strict fails on warnings)
npx coraza-openapi validate openapi.yaml
npx coraza-openapi generate openapi.yaml \
  --host api.example.com --strip-prefix /api/v1 --block-deprecated -o coraza.conf

# Diff the rule output between two spec versions (great for PR bots)
npx coraza-openapi diff openapi-old.yaml openapi-new.yaml

# Serve the bundled web UI
npx coraza-openapi serve --port 4173
```

A `coraza-openapi.config.json` in the project root is picked up automatically
(JSON, YAML, `.js`, `.ts` all supported via cosmiconfig). Generate a starter
with `npx coraza-openapi init-config`.

## GitHub Pages deploy (one-time setup)

1. On `coraza-incubator/coraza-openapi`, Settings → Pages → **Source: GitHub Actions**.
2. Push to `main`. The `Deploy to GitHub Pages` workflow builds with `VITE_BASE=/coraza-openapi/` and publishes `packages/web/dist`.
3. Site is then live at `https://coraza-incubator.github.io/coraza-openapi/`.

## Verifying generated rules

The emitted rules use ModSecurity-compatible SecLang and are designed to load
directly into Coraza. To sanity-check:

```bash
# Using coraza-cli (https://github.com/jcchavezs/coraza-cli)
coraza-cli -rules coraza.conf -input sample-request.http
```

## References

- OpenAPI 3.1 — https://spec.openapis.org/oas/v3.1.0
- Coraza — https://coraza.io/docs/seclang/directives/
- OWASP CRS — https://coreruleset.org/ (this output is designed to sit *in front of* CRS, not replace it)

## License

Apache 2.0.
