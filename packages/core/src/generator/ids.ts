// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
export class IdAllocator {
  private current: number;
  private readonly step: number;
  constructor(start: number, step: number) {
    this.current = start;
    this.step = Math.max(1, step);
  }
  next(): number {
    const id = this.current;
    this.current += 1;
    return id;
  }
  /** Skip to the next "section" boundary — aligns to the configured step size. */
  advanceSection(): void {
    const over = this.current % this.step;
    if (over !== 0) this.current += this.step - over;
  }
  peek(): number {
    return this.current;
  }
}