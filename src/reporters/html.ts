import type { Report } from '../analyzer.ts';
import type { Severity } from '../types.ts';
import { mitreUrl } from '../mitre.ts';

/**
 * Escapa todo lo que viene de los logs. Las líneas de log las controla el atacante:
 * sin esto, una petición como GET /<script>... ejecutaría código al abrir el informe.
 */
export function escapeHtml(value: string): string {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

const SEVERITY_LABEL: Record<Severity, string> = {
    critical: 'Crítica',
    high: 'Alta',
    medium: 'Media',
    low: 'Baja',
};

function formatDate(date: Date): string {
    return date.toISOString().replace('T', ' ').slice(0, 19);
}

export function renderHtml(report: Report): string {
    const e = escapeHtml;
    const { totals } = report;

    const severityCards = (['critical', 'high', 'medium', 'low'] as Severity[])
        .map((s) => `<div class="stat sev-${s}"><span>${SEVERITY_LABEL[s]}</span><b>${totals.bySeverity[s]}</b></div>`)
        .join('');

    const sources = report.sources
        .map((s) => `<li><code>${e(s.file)}</code> · ${s.type === 'auth' ? 'auth.log' : 'access log'} · ${s.events} eventos${s.skipped ? ` · ${s.skipped} líneas ignoradas` : ''}</li>`)
        .join('');

    const ipRows = report.topIps
        .slice(0, 15)
        .map((ip) => `<tr><td><code>${e(ip.ip)}</code></td><td><span class="pill sev-${ip.worst}">${SEVERITY_LABEL[ip.worst]}</span></td><td class="num">${ip.score}</td><td class="num">${ip.findings}</td><td>${ip.rules.map((r) => `<code>${e(r)}</code>`).join(' ')}</td></tr>`)
        .join('');

    const findings = report.findings
        .map((f, i) => `
        <article class="finding">
            <header>
                <span class="pill sev-${f.severity}">${SEVERITY_LABEL[f.severity]}</span>
                <h3>${i + 1}. ${e(f.title)}</h3>
                <code class="rule">${e(f.rule)}</code>
            </header>
            <p>${e(f.description)}</p>
            <dl>
                ${f.ip ? `<div><dt>IP</dt><dd><code>${e(f.ip)}</code></dd></div>` : ''}
                ${f.user ? `<div><dt>Usuario</dt><dd><code>${e(f.user)}</code></dd></div>` : ''}
                <div><dt>Periodo</dt><dd>${formatDate(f.firstSeen)} → ${formatDate(f.lastSeen)} UTC</dd></div>
                <div><dt>Eventos</dt><dd>${f.count}</dd></div>
                <div><dt>MITRE ATT&amp;CK</dt><dd>${f.mitre.map((m) => `<a href="${mitreUrl(m.id)}" target="_blank" rel="noopener noreferrer">${e(m.id)}</a> ${e(m.name)}`).join('<br>')}</dd></div>
            </dl>
            <pre>${f.evidence.map(e).join('\n')}</pre>
        </article>`)
        .join('');

    return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>LogSentinel · Informe</title>
<style>
:root{--bg:#f5f6f4;--card:#fff;--ink:#15181b;--ink2:#555b62;--rule:#dcdfdb;--crit:#9f1d1d;--high:#c2410c;--med:#a16207;--low:#0e7490}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:40px 20px 80px}
h1{font-size:30px;margin:0 0 4px;letter-spacing:-.02em}h2{font-size:20px;margin:48px 0 16px;padding-bottom:10px;border-bottom:1.5px solid var(--ink)}
.meta{color:var(--ink2);margin:0}ul{padding-left:18px;color:var(--ink2)}
code,pre{font-family:ui-monospace,"Cascadia Code",Consolas,monospace;font-size:13px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-top:28px}
.stat{background:var(--card);border:1px solid var(--rule);padding:14px 16px;display:flex;flex-direction:column;gap:2px}
.stat span{color:var(--ink2);font-size:13px}.stat b{font-size:28px}
.stat.sev-critical b{color:var(--crit)}.stat.sev-high b{color:var(--high)}.stat.sev-medium b{color:var(--med)}.stat.sev-low b{color:var(--low)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--rule)}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--rule);vertical-align:top}th{font-size:13px;color:var(--ink2);font-weight:600}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-block;font-size:12px;font-weight:700;padding:2px 8px;color:#fff;white-space:nowrap}
.pill.sev-critical{background:var(--crit)}.pill.sev-high{background:var(--high)}.pill.sev-medium{background:var(--med)}.pill.sev-low{background:var(--low)}
.finding{background:var(--card);border:1px solid var(--rule);padding:20px;margin-bottom:14px}
.finding header{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.finding h3{margin:0;font-size:17px}
.rule{color:var(--ink2);margin-left:auto}
dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px 24px;margin:14px 0}
dt{font-size:12px;color:var(--ink2)}dd{margin:0}a{color:var(--low)}
pre{background:#15181b;color:#e6e8e6;padding:14px;overflow-x:auto;margin:0;white-space:pre}
.empty{background:var(--card);border:1px solid var(--rule);padding:20px}
@media (max-width:700px){.stats{grid-template-columns:repeat(2,1fr)}.rule{margin-left:0}}
</style>
</head>
<body>
<main>
<h1>LogSentinel · Informe de análisis</h1>
<p class="meta">Generado el ${formatDate(report.generatedAt)} UTC${report.period ? ` · Periodo analizado: ${formatDate(report.period.from)} → ${formatDate(report.period.to)} UTC` : ''}</p>
<ul>${sources}</ul>
<div class="stats"><div class="stat"><span>Hallazgos</span><b>${totals.findings}</b></div>${severityCards}</div>

<h2>IPs con más riesgo</h2>
${ipRows ? `<table><thead><tr><th>IP</th><th>Peor gravedad</th><th>Score</th><th>Hallazgos</th><th>Reglas</th></tr></thead><tbody>${ipRows}</tbody></table>` : '<p class="empty">Sin IPs sospechosas.</p>'}

<h2>Hallazgos</h2>
${findings || '<p class="empty">No se han detectado actividades sospechosas.</p>'}
</main>
</body>
</html>
`;
}
