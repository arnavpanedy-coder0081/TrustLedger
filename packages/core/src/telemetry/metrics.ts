export interface MetricSummary {
  count: number;
  totalMs: number;
  minMs: number;
  maxMs: number;
  avgMs: number;
}

export class MetricsCollector {
  private static instance: MetricsCollector;

  private counters = new Map<string, number>();
  private timings = new Map<string, number[]>();
  private gauges = new Map<string, number>();

  public static getInstance(): MetricsCollector {
    if (!MetricsCollector.instance) {
      MetricsCollector.instance = new MetricsCollector();
    }
    return MetricsCollector.instance;
  }

  public incrementCounter(name: string, by = 1): void {
    const current = this.counters.get(name) ?? 0;
    this.counters.set(name, current + by);
  }

  public getCounter(name: string): number {
    return this.counters.get(name) ?? 0;
  }

  public setGauge(name: string, value: number): void {
    this.gauges.set(name, value);
  }

  public getGauge(name: string): number {
    return this.gauges.get(name) ?? 0;
  }

  public recordTiming(name: string, durationMs: number): void {
    let list = this.timings.get(name);
    if (!list) {
      list = [];
      this.timings.set(name, list);
    }
    list.push(durationMs);
    // Keep max 1000 samples in memory
    if (list.length > 1000) {
      list.shift();
    }
  }

  public async timeAsync<T>(name: string, fn: () => Promise<T>): Promise<T> {
    const start = performance.now();
    try {
      return await fn();
    } finally {
      const elapsed = performance.now() - start;
      this.recordTiming(name, elapsed);
    }
  }

  public timeSync<T>(name: string, fn: () => T): T {
    const start = performance.now();
    try {
      return fn();
    } finally {
      const elapsed = performance.now() - start;
      this.recordTiming(name, elapsed);
    }
  }

  public getTimingSummary(name: string): MetricSummary {
    const list = this.timings.get(name) ?? [];
    if (list.length === 0) {
      return { count: 0, totalMs: 0, minMs: 0, maxMs: 0, avgMs: 0 };
    }
    const totalMs = list.reduce((a, b) => a + b, 0);
    const minMs = Math.min(...list);
    const maxMs = Math.max(...list);
    const avgMs = totalMs / list.length;
    return { count: list.length, totalMs, minMs, maxMs, avgMs };
  }

  public getSnapshot(): {
    counters: Record<string, number>;
    gauges: Record<string, number>;
    timings: Record<string, MetricSummary>;
  } {
    const countersObj: Record<string, number> = {};
    for (const [k, v] of this.counters.entries()) {
      countersObj[k] = v;
    }

    const gaugesObj: Record<string, number> = {};
    for (const [k, v] of this.gauges.entries()) {
      gaugesObj[k] = v;
    }

    const timingsObj: Record<string, MetricSummary> = {};
    for (const k of this.timings.keys()) {
      timingsObj[k] = this.getTimingSummary(k);
    }

    return {
      counters: countersObj,
      gauges: gaugesObj,
      timings: timingsObj
    };
  }

  public reset(): void {
    this.counters.clear();
    this.timings.clear();
    this.gauges.clear();
  }
}

export const defaultMetrics = MetricsCollector.getInstance();
