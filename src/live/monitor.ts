import type { DetectionConfig, Finding, LogEvent } from '../types.ts';
import { DEFAULT_CONFIG, SEVERITY_ORDER } from '../types.ts';
import { parseAuthLine } from '../parsers/auth-log.ts';
import { parseAccessLine } from '../parsers/access-log.ts';
import { buildReport } from '../analyzer.ts';
import type { Report } from '../analyzer.ts';

export interface LiveLine {
    raw: string;
    parsed: boolean;
    time?: string;
    ip?: string;
    method?: string;
    path?: string;
    status?: number;
}

export interface AlertChange {
    kind: 'new' | 'escalated';
    finding: Finding;
}

export interface MonitorUpdate {
    lines: LiveLine[];
    changes: AlertChange[];
    findings: Finding[];
    events: number;
}

const keyOf = (f: Finding) => `${f.rule}|${f.ip ?? ''}|${f.user ?? ''}`;

/**
 * Mantiene en memoria los eventos de un log que va creciendo y, con cada lote de líneas
 * nuevas, vuelve a pasar las reglas. Compara con la pasada anterior para saber qué alertas
 * son nuevas y cuáles han subido de gravedad (por ejemplo, de "fuerza bruta" a "acceso conseguido").
 */
export function createMonitor(options: {
    type: 'auth' | 'web';
    source: string;
    year?: number;
    config?: DetectionConfig;
}) {
    const config = options.config ?? DEFAULT_CONFIG;
    const year = options.year ?? new Date().getFullYear();
    const events: LogEvent[] = [];
    let lineNumber = 0;
    let skipped = 0;
    let known = new Map<string, Finding>();

    function ingest(rawLines: string[]): MonitorUpdate {
        const lines: LiveLine[] = rawLines.map((raw) => {
            lineNumber++;
            const event = options.type === 'auth'
                ? parseAuthLine(raw, lineNumber, options.source, year)
                : parseAccessLine(raw, lineNumber, options.source);
            if (!event) {
                skipped++;
                return { raw, parsed: false };
            }
            events.push(event);
            const base = { raw, parsed: true, time: event.timestamp.toISOString(), ip: event.ip };
            return event.kind === 'web'
                ? { ...base, method: event.method, path: event.path, status: event.status }
                : base;
        });

        const findings = report().findings;
        const changes: AlertChange[] = [];
        const next = new Map<string, Finding>();

        for (const f of findings) {
            const key = keyOf(f);
            const previous = known.get(key);
            if (!previous) changes.push({ kind: 'new', finding: f });
            else if (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[previous.severity]) changes.push({ kind: 'escalated', finding: f });
            next.set(key, f);
        }

        // Una regla puede "transformarse" en otra más grave (p. ej. web-login-bruteforce →
        // web-login-success-after-failures): se notifica como nueva.
        known = next;
        return { lines, changes, findings, events: events.length };
    }

    function report(): Report {
        return buildReport(events, [{ file: options.source, type: options.type, events: events.length, skipped }], config);
    }

    return { ingest, report };
}
