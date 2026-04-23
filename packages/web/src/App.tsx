// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { Header } from './components/Header.js';
import { SpecInput } from './components/SpecInput.js';
import { RulesOutput } from './components/RulesOutput.js';
import { ConfigPanel } from './components/ConfigPanel.js';
import { Toasts } from './components/Toasts.js';
import { useStore } from './store.js';

export function App() {
  const ruleCount = useStore((s) => s.ruleCount);
  const status = useStore((s) => s.status);
  return (
    <div className="flex h-screen flex-col bg-zinc-950 text-zinc-100">
      <Header ruleCount={ruleCount} status={status} />
      <main className="grid min-h-0 flex-1 grid-cols-2 overflow-hidden border-b border-zinc-800">
        <section className="min-h-0 min-w-0 overflow-hidden border-r border-zinc-800">
          <SpecInput />
        </section>
        <section className="min-h-0 min-w-0 overflow-hidden">
          <RulesOutput />
        </section>
      </main>
      <section className="h-[42%] min-h-[260px] overflow-hidden">
        <ConfigPanel />
      </section>
      <Toasts />
    </div>
  );
}