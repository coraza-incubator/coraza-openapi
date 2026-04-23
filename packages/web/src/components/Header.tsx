// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
export function Header({ ruleCount, status }: { ruleCount: number; status: string }) {
  return (
    <header className="flex items-center justify-between border-b border-zinc-800 bg-zinc-950/80 px-6 py-3 backdrop-blur">
      <div className="flex items-center gap-3">
        <img
          src={`${import.meta.env.BASE_URL}coraza-logo.png`}
          alt="Coraza"
          className="h-8 w-8"
          data-testid="logo"
        />
        <div>
          <h1 className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
            Coraza OpenAPI Rule Generator
            <span
              data-testid="experimental-badge"
              className="rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-amber-300"
            >
              Experimental
            </span>
          </h1>
          <p className="text-xs text-zinc-500">Turn an OpenAPI spec into a Coraza WAF ruleset.</p>
        </div>
      </div>
      <div className="flex items-center gap-4 text-xs text-zinc-400">
        <span data-testid="rule-count" className="rounded bg-zinc-800 px-2 py-1 font-mono">
          {ruleCount} rule{ruleCount === 1 ? '' : 's'}
        </span>
        <span
          data-testid="status"
          className={
            status === 'error'
              ? 'text-red-400'
              : status === 'generating'
                ? 'text-amber-400'
                : 'text-emerald-400'
          }
        >
          {status}
        </span>
        <a
          href="https://github.com/coraza-incubator/coraza-openapi"
          target="_blank"
          rel="noreferrer"
          className="hover:text-zinc-100"
        >
          GitHub ↗
        </a>
      </div>
    </header>
  );
}