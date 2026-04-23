// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { create } from 'zustand';
import { CheckIcon } from './icons.js';

type Toast = { id: number; text: string };

type ToastState = {
  toasts: Toast[];
  push: (text: string) => void;
};

let seq = 0;

export const useToasts = create<ToastState>((set, get) => ({
  toasts: [],
  push: (text) => {
    const id = ++seq;
    set({ toasts: [...get().toasts, { id, text }] });
    setTimeout(() => {
      set({ toasts: get().toasts.filter((t) => t.id !== id) });
    }, 1800);
  },
}));

export function Toasts() {
  const toasts = useToasts((s) => s.toasts);
  return (
    <div
      data-testid="toasts"
      className="pointer-events-none fixed bottom-4 right-4 z-50 flex flex-col items-end gap-2"
    >
      {toasts.map((t) => (
        <div
          key={t.id}
          role="status"
          data-testid="toast"
          className="pointer-events-auto flex items-center gap-2 rounded-md border border-emerald-500/40 bg-emerald-950/90 px-3 py-2 text-xs text-emerald-200 shadow-lg backdrop-blur animate-[fadein_.15s_ease-out]"
        >
          <CheckIcon className="h-4 w-4 text-emerald-400" />
          {t.text}
        </div>
      ))}
    </div>
  );
}