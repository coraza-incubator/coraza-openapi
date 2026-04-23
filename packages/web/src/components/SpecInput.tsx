// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState } from 'react';
import Editor, { type OnMount } from '@monaco-editor/react';
import '../lib/monaco-setup.js';
import { useStore } from '../store.js';
import { useToasts } from './Toasts.js';
import { CheckIcon } from './icons.js';

function SampleButton({
  label,
  testid,
  flashed,
  onClick,
}: {
  name: string;
  label: string;
  testid: string;
  flashed: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      data-testid={testid}
      data-flashed={flashed ? 'true' : 'false'}
      className={`flex items-center gap-1 rounded px-2 py-1 transition-colors ${
        flashed ? 'bg-emerald-600 text-white' : 'bg-zinc-800 hover:bg-zinc-700'
      }`}
    >
      {flashed && <CheckIcon />}
      <span>{label}</span>
    </button>
  );
}

export function SpecInput() {
  const specText = useStore((s) => s.specText);
  const setSpec = useStore((s) => s.setSpec);
  const loadSample = useStore((s) => s.loadSample);
  const error = useStore((s) => s.error);
  const fileRef = useRef<HTMLInputElement>(null);
  const editorRef = useRef<Parameters<OnMount>[0] | null>(null);
  const [flash, setFlash] = useState<string | null>(null);
  const toast = useToasts((s) => s.push);

  function loadAndFlash(name: Parameters<typeof loadSample>[0]) {
    loadSample(name);
    setFlash(name);
    toast(`Loaded ${name} sample`);
    setTimeout(() => setFlash((f) => (f === name ? null : f)), 1400);
  }

  const language = specText.trimStart().startsWith('{') ? 'json' : 'yaml';

  useEffect(() => {
    // Expose a setter for Playwright/E2E so we can drive the editor without
    // emulating Monaco keystrokes.
    (window as any).__setSpec = (text: string) => setSpec(text);
    return () => {
      delete (window as any).__setSpec;
    };
  }, [setSpec]);

  return (
    <div
      className="flex h-full min-h-0 min-w-0 flex-col overflow-hidden"
      data-testid="spec-input-container"
      onDragOver={(e) => e.preventDefault()}
      onDrop={async (e) => {
        e.preventDefault();
        const f = e.dataTransfer.files[0];
        if (f) setSpec(await f.text());
      }}
    >
      <div className="flex items-center justify-between border-b border-zinc-800 bg-zinc-900/50 px-4 py-2 text-xs">
        <span className="font-medium text-zinc-400">
          OpenAPI spec · <span data-testid="language">{language.toUpperCase()}</span>
        </span>
        <div className="flex gap-2">
          <SampleButton
            name="petstore"
            label="Petstore"
            testid="sample-petstore"
            flashed={flash === 'petstore'}
            onClick={() => loadAndFlash('petstore')}
          />
          <SampleButton
            name="minimal"
            label="Minimal"
            testid="sample-minimal"
            flashed={flash === 'minimal'}
            onClick={() => loadAndFlash('minimal')}
          />
          <button
            type="button"
            onClick={() => fileRef.current?.click()}
            className="rounded bg-zinc-800 px-2 py-1 hover:bg-zinc-700"
          >
            Upload…
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".yaml,.yml,.json"
            className="hidden"
            data-testid="file-input"
            onChange={async (e) => {
              const f = e.target.files?.[0];
              if (f) setSpec(await f.text());
              e.target.value = '';
            }}
          />
        </div>
      </div>
      <div className="flex-1 min-h-0 overflow-hidden" data-testid="spec-editor">
        <Editor
          value={specText}
          language={language}
          path={language === 'json' ? 'openapi.json' : 'openapi.yaml'}
          theme="vs-dark"
          options={{
            minimap: { enabled: false },
            fontSize: 12,
            wordWrap: 'on',
            scrollBeyondLastLine: false,
            tabSize: 2,
            renderWhitespace: 'selection',
            quickSuggestions: { other: true, strings: true },
          }}
          onMount={(editor) => {
            editorRef.current = editor;
          }}
          onChange={(v) => setSpec(v ?? '')}
        />
      </div>
      {error && (
        <div
          data-testid="parse-error"
          className="border-t border-red-500/40 bg-red-950/50 p-3 font-mono text-xs text-red-300"
        >
          {error}
        </div>
      )}
    </div>
  );
}