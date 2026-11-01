import type { AuthEvent, DetectionConfig, Finding, LogEvent, Severity, WebEvent } from './types.ts';
import { DEFAULT_CONFIG, SEVERITY_ORDER } from './types.ts';
import { sshDetectors } from './detectors/ssh.ts';
import { webDetectors } from './detectors/web.ts';

const SEVERITY_WEIGHT: Record<Severity, number> = { low: 1, medium: 3, high: 7, critical: 10 };

export interface IpSummary {
    ip: string;
    score: number;
    findings: number;
    worst: Severity;
    rules: string[];
}

export interface Report {
    generatedAt: Date;
    sources: { file: string; type: 'auth' | 'web'; events: number; skipped: number }[];
    period: { from: Date; to: Date } | null;
    totals: { events: number; findings: number; bySeverity: Record<Severity, number> };
    topIps: IpSummary[];
    findings: Finding[];
}

export function runDetectors(events: LogEvent[], config: DetectionConfig = DEFAULT_CONFIG): Finding[] {
    const auth = events.filter((e): e is AuthEvent => e.kind === 'auth');
    const web = events.filter((e): e is WebEvent => e.kind === 'web');

    const findings = [
        ...sshDetectors.flatMap((detect) => detect(auth, config)),
        ...webDetectors.flatMap((detect) => detect(web, config)),
    ];

    return findings.sort(
        (a, b) =>
            SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
            a.firstSeen.getTime() - b.firstSeen.getTime(),
    );
}

/** Puntuación de riesgo por IP: suma ponderada de sus hallazgos, para priorizar qué bloquear primero. */
export function scoreIps(findings: Finding[]): IpSummary[] {
    const byIp = new Map<string, IpSummary>();

    for (const f of findings) {
        if (!f.ip) continue;
        const entry = byIp.get(f.ip) ?? { ip: f.ip, score: 0, findings: 0, worst: 'low' as Severity, rules: [] };
        entry.score += SEVERITY_WEIGHT[f.severity];
        entry.findings += 1;
        if (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[entry.worst]) entry.worst = f.severity;
        if (!entry.rules.includes(f.rule)) entry.rules.push(f.rule);
        byIp.set(f.ip, entry);
    }

    return [...byIp.values()].sort((a, b) => b.score - a.score);
}

export function buildReport(
    events: LogEvent[],
    sources: Report['sources'],
    config: DetectionConfig = DEFAULT_CONFIG,
): Report {
    const findings = runDetectors(events, config);
    const bySeverity: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    for (const f of findings) bySeverity[f.severity]++;

    let period: Report['period'] = null;
    if (events.length > 0) {
        // Bucle en lugar de Math.min(...array): con logs de cientos de miles de líneas
        // el spread desborda la pila.
        let min = Infinity;
        let max = -Infinity;
        for (const e of events) {
            const t = e.timestamp.getTime();
            if (t < min) min = t;
            if (t > max) max = t;
        }
        period = { from: new Date(min), to: new Date(max) };
    }

    return {
        generatedAt: new Date(),
        sources,
        period,
        totals: { events: events.length, findings: findings.length, bySeverity },
        topIps: scoreIps(findings),
        findings,
    };
}

export function filterBySeverity(findings: Finding[], min: Severity): Finding[] {
    return findings.filter((f) => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[min]);
}

/** Devuelve el informe solo con los hallazgos indicados, recalculando totales y ranking de IPs. */
export function withFindings(report: Report, findings: Finding[]): Report {
    const bySeverity: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    for (const f of findings) bySeverity[f.severity]++;
    return {
        ...report,
        totals: { ...report.totals, findings: findings.length, bySeverity },
        topIps: scoreIps(findings),
        findings,
    };
}
