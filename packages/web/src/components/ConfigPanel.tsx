// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { useState } from 'react';
import { useStore } from '../store.js';
import { cn } from '../lib/cn.js';
import type { Config } from '@coraza-openapi/core';

const TABS = ['General', 'Routing', 'Auth', 'Validation', 'Advanced'] as const;
type Tab = (typeof TABS)[number];

export function ConfigPanel() {
  const [tab, setTab] = useState<Tab>('General');
  const config = useStore((s) => s.config);
  const setConfig = useStore((s) => s.setConfig);

  return (
    <div className="flex h-full min-h-0 flex-col border-t border-zinc-800 bg-zinc-900/40">
      <div className="flex gap-1 border-b border-zinc-800 px-4 pt-2 text-xs">
        {TABS.map((t) => (
          <button
            key={t}
            type="button"
            data-testid={`tab-${t.toLowerCase()}`}
            onClick={() => setTab(t)}
            className={cn(
              'rounded-t px-3 py-1.5',
              tab === t
                ? 'bg-zinc-950 text-zinc-100'
                : 'text-zinc-400 hover:text-zinc-200',
            )}
          >
            {t}
          </button>
        ))}
      </div>
      <div className="flex-1 min-h-0 overflow-auto p-4 text-sm">
        {tab === 'General' && <General config={config} set={setConfig} />}
        {tab === 'Routing' && <Routing config={config} set={setConfig} />}
        {tab === 'Auth' && <Auth config={config} set={setConfig} />}
        {tab === 'Validation' && <Validation config={config} set={setConfig} />}
        {tab === 'Advanced' && <Advanced config={config} set={setConfig} />}
      </div>
    </div>
  );
}

type Setter = (patch: Partial<Config> | ((c: Config) => Config)) => void;
type PanelProps = { config: Config; set: Setter };

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex items-center justify-between gap-4 py-1.5">
      <span className="text-xs text-zinc-400">{label}</span>
      <span>{children}</span>
    </label>
  );
}

function Toggle({
  checked,
  onChange,
  testId,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  testId?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      data-testid={testId}
      onClick={() => onChange(!checked)}
      className={cn(
        'h-5 w-9 rounded-full transition-colors',
        checked ? 'bg-coraza' : 'bg-zinc-700',
      )}
    >
      <span
        className={cn(
          'block h-4 w-4 translate-x-0.5 rounded-full bg-white transition-transform',
          checked && 'translate-x-[18px]',
        )}
      />
    </button>
  );
}

function NumberInput({
  value,
  onChange,
  testId,
}: {
  value: number;
  onChange: (v: number) => void;
  testId?: string;
}) {
  return (
    <input
      type="number"
      value={value}
      data-testid={testId}
      onChange={(e) => onChange(Number(e.target.value))}
      className="w-28 rounded bg-zinc-800 px-2 py-1 font-mono text-xs text-zinc-100 outline-none"
    />
  );
}

function TextInput({ value, onChange, testId, placeholder }: { value: string; onChange: (v: string) => void; testId?: string; placeholder?: string }) {
  return (
    <input
      type="text"
      value={value}
      placeholder={placeholder}
      data-testid={testId}
      onChange={(e) => onChange(e.target.value)}
      className="w-60 rounded bg-zinc-800 px-2 py-1 font-mono text-xs text-zinc-100 outline-none"
    />
  );
}

function General({ config, set }: PanelProps) {
  return (
    <div className="max-w-5xl gap-x-10 columns-1 lg:columns-2 [&>label]:break-inside-avoid">
      <Row label="Starting rule ID">
        <NumberInput
          value={config.startingId}
          testId="starting-id"
          onChange={(v) => set({ startingId: v })}
        />
      </Row>
      <Row label="ID step (section boundary)">
        <NumberInput value={config.idStep} onChange={(v) => set({ idStep: v })} />
      </Row>
      <Row label="Mode">
        <select
          value={config.mode}
          data-testid="mode-select"
          onChange={(e) => set({ mode: e.target.value as Config['mode'] })}
          className="rounded bg-zinc-800 px-2 py-1 text-xs text-zinc-100"
        >
          <option value="standalone-block">Standalone · block</option>
          <option value="standalone-detect">Standalone · detect only</option>
          <option value="crs-plugin">CRS plugin (anomaly score)</option>
        </select>
      </Row>
      <Row label="Default deny status">
        <NumberInput
          value={config.defaultDenyStatus}
          onChange={(v) => set({ defaultDenyStatus: v })}
        />
      </Row>
      <Row label="Tag prefix">
        <TextInput value={config.tagPrefix} onChange={(v) => set({ tagPrefix: v })} />
      </Row>
      <Row label="Include banner comment">
        <Toggle checked={config.banner} onChange={(v) => set({ banner: v })} />
      </Row>
      <Row label="Debug mode (msg on every rule)">
        <Toggle
          testId="toggle-debug"
          checked={config.debug}
          onChange={(v) => set({ debug: v })}
        />
      </Row>
    </div>
  );
}

function Routing({ config, set }: PanelProps) {
  const r = config.routing;
  return (
    <div className="max-w-5xl gap-x-10 columns-1 lg:columns-2 [&>label]:break-inside-avoid">
      <Row label="Enforce hostname">
        <Toggle
          testId="toggle-hostname"
          checked={r.enforceHostname}
          onChange={(v) => set({ routing: { ...r, enforceHostname: v } })}
        />
      </Row>
      <Row label="Allowed hosts (comma separated)">
        <TextInput
          value={r.allowedHosts.join(',')}
          placeholder="auto-detected"
          onChange={(v) =>
            set({
              routing: {
                ...r,
                allowedHosts: v
                  .split(',')
                  .map((s) => s.trim())
                  .filter(Boolean),
              },
            })
          }
        />
      </Row>
      <Row label="Strip prefix">
        <TextInput
          value={r.stripPrefix}
          testId="strip-prefix"
          placeholder="/api/v1"
          onChange={(v) => set({ routing: { ...r, stripPrefix: v } })}
        />
      </Row>
      <Row label="Add prefix">
        <TextInput
          value={r.addPrefix}
          placeholder="(none)"
          onChange={(v) => set({ routing: { ...r, addPrefix: v } })}
        />
      </Row>
      <Row label="Path allowlist">
        <Toggle checked={r.pathAllowlist} onChange={(v) => set({ routing: { ...r, pathAllowlist: v } })} />
      </Row>
      <Row label="Undeclared endpoints">
        <select
          value={r.undeclaredEndpointAction}
          data-testid="undeclared-select"
          onChange={(e) =>
            set({
              routing: {
                ...r,
                undeclaredEndpointAction: e.target.value as typeof r.undeclaredEndpointAction,
              },
            })
          }
          className="rounded bg-zinc-800 px-2 py-1 text-xs text-zinc-100"
        >
          <option value="block">Block</option>
          <option value="alert">Alert only</option>
          <option value="allow">Allow</option>
        </select>
      </Row>
      <Row label="Method enforcement">
        <Toggle checked={r.methodEnforcement} onChange={(v) => set({ routing: { ...r, methodEnforcement: v } })} />
      </Row>
      <Row label="Deprecated endpoints">
        <select
          value={r.deprecatedHandling}
          data-testid="deprecated-select"
          onChange={(e) =>
            set({ routing: { ...r, deprecatedHandling: e.target.value as typeof r.deprecatedHandling } })
          }
          className="rounded bg-zinc-800 px-2 py-1 text-xs text-zinc-100"
        >
          <option value="allow">Allow</option>
          <option value="warn">Warn (tag)</option>
          <option value="block">Block 410</option>
        </select>
      </Row>
    </div>
  );
}

function Auth({ config, set }: PanelProps) {
  const a = config.auth;
  return (
    <div className="max-w-5xl gap-x-10 columns-1 lg:columns-2 [&>label]:break-inside-avoid">
      <Row label="Enforce securitySchemes">
        <Toggle
          testId="toggle-auth"
          checked={a.enforceSecurity}
          onChange={(v) => set({ auth: { ...a, enforceSecurity: v } })}
        />
      </Row>
      <Row label="Custom API key header (override)">
        <TextInput
          value={a.customHeaderName ?? ''}
          placeholder="X-API-Key"
          onChange={(v) => set({ auth: { ...a, customHeaderName: v || undefined } })}
        />
      </Row>
    </div>
  );
}

function Validation({ config, set }: PanelProps) {
  const v = config.validation;
  const keys: (keyof typeof v)[] = [
    'requiredParams',
    'validateTypes',
    'validateEnums',
    'validatePatterns',
    'validateLengths',
    'enforceContentType',
  ];
  return (
    <div className="max-w-5xl gap-x-10 columns-1 lg:columns-2 [&>label]:break-inside-avoid">
      {keys.map((k) => (
        <Row key={k} label={k}>
          <Toggle checked={v[k]} onChange={(val) => set({ validation: { ...v, [k]: val } })} />
        </Row>
      ))}
    </div>
  );
}

function Advanced({ config, set }: PanelProps) {
  const a = config.advanced;
  return (
    <div className="max-w-5xl gap-x-10 columns-1 lg:columns-2 [&>label]:break-inside-avoid">
      <Row label="Emit rate-limit hints as comments">
        <Toggle checked={a.emitRateLimitHints} onChange={(v) => set({ advanced: { ...a, emitRateLimitHints: v } })} />
      </Row>
      <Row label="Emit CORS hints">
        <Toggle checked={a.emitCorsHints} onChange={(v) => set({ advanced: { ...a, emitCorsHints: v } })} />
      </Row>
    </div>
  );
}