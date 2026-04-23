// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { create } from 'zustand';
import { ConfigSchema, defaultConfig, generateFromText, type Config } from '@coraza-openapi/core';
import { samples } from '@coraza-openapi/core/samples';

type Status = 'idle' | 'generating' | 'ok' | 'error';

type State = {
  specText: string;
  config: Config;
  output: string;
  ruleCount: number;
  diagnostics: { level: string; path: string; message: string }[];
  error: string | null;
  status: Status;
  setSpec: (text: string) => void;
  setConfig: (patch: Partial<Config> | ((c: Config) => Config)) => void;
  loadSample: (name: keyof typeof samples) => void;
  regenerate: () => Promise<void>;
};

let token = 0;

export const useStore = create<State>((set, get) => ({
  specText: samples.petstore.yaml,
  config: defaultConfig(),
  output: '',
  ruleCount: 0,
  diagnostics: [],
  error: null,
  status: 'idle',
  setSpec: (text) => {
    set({ specText: text });
    void get().regenerate();
  },
  setConfig: (patch) => {
    const next = typeof patch === 'function' ? patch(get().config) : ConfigSchema.parse({ ...get().config, ...patch });
    set({ config: next });
    void get().regenerate();
  },
  loadSample: (name) => {
    set({ specText: samples[name].yaml });
    void get().regenerate();
  },
  regenerate: async () => {
    const my = ++token;
    set({ status: 'generating' });
    const r = await generateFromText(get().specText, get().config);
    if (my !== token) return;
    if (!r.ok) {
      set({ error: r.error, status: 'error', output: '', ruleCount: 0, diagnostics: [] });
      return;
    }
    set({
      output: r.seclang,
      ruleCount: r.ruleCount,
      diagnostics: r.diagnostics,
      error: null,
      status: 'ok',
    });
  },
}));

// Kick off initial generation.
if (typeof window !== 'undefined') {
  void useStore.getState().regenerate();
}