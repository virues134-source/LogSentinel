import type { Report } from '../analyzer.ts';
import type { Severity } from '../types.ts';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string, text: string) => (useColor ? `\x1b[${code}m${text}\x1b[0m` : text);

const SEVERITY_STYLE: Record<Severity, string> = {
    critical: '1;37;41',
    high: '1;31',
    medium: '33',
    low: '36',
};

const label = (s: Severity) => paint(SEVERITY_STYLE[s], s.toUpperCase().padEnd(8));
const dim = (t: string) => paint('2', t);
const bold = (t: string) => paint('1', t);

function formatDate(date: Date): string {
    return date.toISOString().replace('T', ' ').slice(0, 19);
}

export function renderTerminal(report: Report): string {
    const out: string[] = [];
    const { totals } = report;

    out.push(bold('LogSentinel · informe de análisis'));
    out.push(dim('─'.repeat(60)));
    for (const s of report.sources) {
        out.push(`${dim('fuente')}  ${s.file} ${dim(`(${s.type}, ${s.events} eventos, ${s.skipped} líneas ignoradas)`)}`);
    }
    if (report.period) {
        out.push(`${dim('periodo')} ${formatDate(report.period.from)} → ${formatDate(report.period.to)} UTC`);
    }
    out.push('');
    out.push(
        `${bold(String(totals.findings))} hallazgos  ` +
        `${label('critical')}${totals.bySeverity.critical}  ` +
        `${label('high')}${totals.bySeverity.high}  ` +
        `${label('medium')}${totals.bySeverity.medium}  ` +
        `${label('low')}${totals.bySeverity.low}`,
    );

    if (report.topIps.length > 0) {
        out.push('');
        out.push(bold('IPs con más riesgo'));
        for (const ip of report.topIps.slice(0, 10)) {
            out.push(`  ${ip.ip.padEnd(18)} ${label(ip.worst)} score ${String(ip.score).padStart(3)}  ${dim(ip.rules.join(', '))}`);
        }
    }

    if (report.findings.length > 0) {
        out.push('');
        out.push(bold('Hallazgos'));
        report.findings.forEach((f, i) => {
            out.push('');
            out.push(`${String(i + 1).padStart(3)}. ${label(f.severity)} ${bold(f.title)} ${dim(`[${f.rule}]`)}`);
            out.push(`     ${f.description}`);
            out.push(`     ${dim('MITRE')} ${f.mitre.map((m) => `${m.id} ${m.name}`).join(' · ')}`);
            out.push(`     ${dim(`${formatDate(f.firstSeen)} → ${formatDate(f.lastSeen)} · ${f.count} evento(s)`)}`);
            for (const line of f.evidence.slice(0, 3)) {
                out.push(`     ${dim('│')} ${dim(line.length > 140 ? `${line.slice(0, 139)}…` : line)}`);
            }
        });
    } else {
        out.push('');
        out.push('No se han detectado actividades sospechosas.');
    }

    return out.join('\n');
}
