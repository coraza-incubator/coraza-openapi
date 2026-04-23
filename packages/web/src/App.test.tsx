// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from './App.js';

// Monaco pulls in workers that jsdom can't construct. Stub the whole editor
// for component tests — we have Playwright E2E coverage against a real browser.
let __stubId = 0;
vi.mock('@monaco-editor/react', () => ({
  __esModule: true,
  default: ({
    value,
    onChange,
    options,
  }: {
    value: string;
    onChange?: (v: string) => void;
    options?: { readOnly?: boolean };
  }) => {
    const ro = !!options?.readOnly;
    return (
      <textarea
        data-testid={ro ? `monaco-readonly-${++__stubId}` : 'spec-input'}
        value={value}
        readOnly={ro}
        onChange={(e) => onChange?.(e.target.value)}
      />
    );
  },
  loader: { config: () => {} },
}));
vi.mock('../lib/monaco-setup.js', () => ({}));
vi.mock('./lib/monaco-setup.js', () => ({}));

describe('App', () => {
  beforeEach(async () => {
    const { useStore } = await import('./store.js');
    const { defaultConfig } = await import('@coraza-openapi/core');
    const { samples } = await import('@coraza-openapi/core/samples');
    useStore.setState({
      specText: samples.petstore.yaml,
      config: defaultConfig(),
      output: '',
      ruleCount: 0,
      error: null,
      diagnostics: [],
      status: 'idle',
    });
    await useStore.getState().regenerate();
  });

  it('renders petstore sample and generates rules', async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByTestId('rule-count')).toHaveTextContent(/\d+ rules?/));
    const output = screen.getByTestId('rules-output');
    await waitFor(() => expect(output.textContent).toContain('SecRule'));
    expect(output.textContent).toContain('listPets');
  });

  it('toggling hostname enforcement removes the host rule', async () => {
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() =>
      expect(screen.getByTestId('rules-output').getAttribute('data-rules-text')).toContain('Host header'),
    );
    await user.click(screen.getByTestId('tab-routing'));
    await user.click(screen.getByTestId('toggle-hostname'));
    await waitFor(() =>
      expect(screen.getByTestId('rules-output').getAttribute('data-rules-text')).not.toContain('Host header'),
    );
  });

  it('shows parse error for malformed spec', async () => {
    const user = userEvent.setup();
    render(<App />);
    const input = screen.getByTestId('spec-input');
    await user.clear(input);
    await user.type(input, ':::');
    await waitFor(() => expect(screen.getByTestId('parse-error')).toBeInTheDocument());
  });

  it('switches samples via button', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByTestId('sample-minimal'));
    await waitFor(() =>
      expect(screen.getByTestId('rules-output').getAttribute('data-rules-text')).toContain('Minimal'),
    );
  });

  it('config panel — adjusting starting id updates rule IDs', async () => {
    render(<App />);
    fireEvent.change(screen.getByTestId('starting-id'), { target: { value: '5000000' } });
    await waitFor(() =>
      expect(screen.getByTestId('rules-output').getAttribute('data-rules-text')).toMatch(/id:50040\d{2}/),
    );
  });

  it('config panel — standalone-detect drops deny actions', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.selectOptions(screen.getByTestId('mode-select'), 'standalone-detect');
    await waitFor(() =>
      expect(screen.getByTestId('rules-output').getAttribute('data-rules-text')).not.toContain(
        'deny,status:',
      ),
    );
  });

  it('config panel — crs-plugin mode contributes to anomaly score', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.selectOptions(screen.getByTestId('mode-select'), 'crs-plugin');
    await waitFor(() =>
      expect(screen.getByTestId('rules-output').getAttribute('data-rules-text')).toContain(
        'tx.inbound_anomaly_score_pl1',
      ),
    );
  });

  it('config panel — disabling auth removes auth rules', async () => {
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() =>
      expect(screen.getByTestId('rules-output').getAttribute('data-rules-text')).toContain('Missing credentials'),
    );
    await user.click(screen.getByTestId('tab-auth'));
    await user.click(screen.getByTestId('toggle-auth'));
    await waitFor(() =>
      expect(screen.getByTestId('rules-output').getAttribute('data-rules-text')).not.toContain('Missing credentials'),
    );
  });

  it('config panel — strip prefix rewrites URI matcher', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByTestId('tab-routing'));
    fireEvent.change(screen.getByTestId('strip-prefix'), { target: { value: '/api/v1' } });
    await waitFor(() =>
      expect(screen.getByTestId('rules-output').getAttribute('data-rules-text')).toContain('/api/v1'),
    );
  });
});