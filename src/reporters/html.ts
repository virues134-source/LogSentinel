import type { Report } from '../analyzer.ts';
import type { Finding, Severity } from '../types.ts';
import { SEVERITY_ORDER } from '../types.ts';
import { mitreUrl } from '../mitre.ts';
import { GUIDANCE } from '../guidance.ts';

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

const e = escapeHtml;
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

const LABEL: Record<Severity, string> = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' };

const VERDICT: Record<Severity | 'none', { title: string; text: string }> = {
    critical: {
        title: 'Riesgo crítico',
        text: 'Hay indicios de ataques que han tenido éxito. Requiere actuar de inmediato.',
    },
    high: {
        title: 'Riesgo alto',
        text: 'Hay ataques activos contra el servidor, sin indicios claros de que hayan tenido éxito.',
    },
    medium: {
        title: 'Riesgo medio',
        text: 'Se ha detectado actividad de reconocimiento y escaneo. Conviene revisarla.',
    },
    low: {
        title: 'Riesgo bajo',
        text: 'Solo hay hallazgos menores.',
    },
    none: {
        title: 'Sin incidencias',
        text: 'No se ha detectado actividad sospechosa en los logs analizados.',
    },
};

function formatDate(date: Date): string {
    return date.toISOString().replace('T', ' ').slice(0, 19);
}

function formatTime(date: Date): string {
    return date.toISOString().slice(11, 16);
}

function formatRange(from: Date, to: Date): string {
    const sameDay = from.toISOString().slice(0, 10) === to.toISOString().slice(0, 10);
    if (from.getTime() === to.getTime()) return formatDate(from);
    return sameDay ? `${formatDate(from)} – ${to.toISOString().slice(11, 19)}` : `${formatDate(from)} – ${formatDate(to)}`;
}

const pill = (s: Severity) => `<span class="pill" data-sev="${s}">${LABEL[s]}</span>`;
const subject = (f: Finding) => [f.user ? `usuario ${e(f.user)}` : '', f.ip ? `<code>${e(f.ip)}</code>` : ''].filter(Boolean).join(' · ');

function renderFinding(f: Finding, index: number): string {
    const guide = GUIDANCE[f.rule];
    return `
<article class="finding" id="f-${index + 1}" data-sev="${f.severity}">
  <header class="finding-head">
    ${pill(f.severity)}
    <h3><span class="num">${index + 1}</span>${e(f.title)}</h3>
    <code class="rule">${e(f.rule)}</code>
  </header>
  <p class="finding-desc">${e(f.description)}</p>
  ${guide ? `
  <div class="guide">
    <div><h4>Qué significa</h4><p>${e(guide.meaning)}</p></div>
    <div><h4>Qué hacer</h4><ol>${guide.actions.map((a) => `<li>${e(a)}</li>`).join('')}</ol></div>
  </div>` : ''}
  <dl class="facts">
    ${f.ip ? `<div><dt>IP de origen</dt><dd><code>${e(f.ip)}</code></dd></div>` : ''}
    ${f.user ? `<div><dt>Usuario</dt><dd><code>${e(f.user)}</code></dd></div>` : ''}
    <div><dt>Cuándo (UTC)</dt><dd>${formatRange(f.firstSeen, f.lastSeen)}</dd></div>
    <div><dt>Eventos</dt><dd>${f.count}</dd></div>
    <div class="wide"><dt>MITRE ATT&amp;CK</dt><dd>${f.mitre.map((m) => `<a href="${mitreUrl(m.id)}" target="_blank" rel="noopener noreferrer"><code>${e(m.id)}</code> ${e(m.name)}</a>`).join('')}</dd></div>
  </dl>
  <details>
    <summary>Ver las ${f.evidence.length} líneas del log que lo demuestran</summary>
    <pre>${f.evidence.map(e).join('\n')}</pre>
  </details>
</article>`;
}

export function renderHtml(report: Report): string {
    const { totals, findings } = report;
    const worst = findings.reduce<Severity | 'none'>(
        (acc, f) => (acc === 'none' || SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[acc] ? f.severity : acc),
        'none',
    );
    const verdict = VERDICT[worst];
    const indexOf = new Map(findings.map((f, i) => [f, i]));

    const key = findings
        .filter((f) => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.high)
        .slice(0, 6)
        .map((f) => `<li><a href="#f-${indexOf.get(f)! + 1}">${pill(f.severity)}<span><b>${e(f.title)}</b>${subject(f) ? ` · ${subject(f)}` : ''}</span></a></li>`)
        .join('');

    const timeline = [...findings]
        .sort((a, b) => a.firstSeen.getTime() - b.firstSeen.getTime())
        .map((f) => `<tr><td class="mono">${formatTime(f.firstSeen)}</td><td>${pill(f.severity)}</td><td><a href="#f-${indexOf.get(f)! + 1}">${e(f.title)}</a></td><td>${subject(f)}</td></tr>`)
        .join('');

    const ipRows = report.topIps
        .slice(0, 15)
        .map((ip) => `<tr><td><code>${e(ip.ip)}</code></td><td>${pill(ip.worst)}</td><td class="num-cell">${ip.score}</td><td class="num-cell">${ip.findings}</td><td class="rules">${ip.rules.map((r) => `<code>${e(r)}</code>`).join(' ')}</td></tr>`)
        .join('');

    const sources = report.sources
        .map((s) => `<li><code>${e(s.file)}</code><span>${s.type === 'auth' ? 'SSH · auth.log' : 'Web · access log'} · ${s.events.toLocaleString('es-ES')} eventos${s.skipped ? ` · ${s.skipped.toLocaleString('es-ES')} líneas ignoradas` : ''}</span></li>`)
        .join('');

    const filters = [
        `<input type="radio" name="sev" id="sev-all" checked><label for="sev-all">Todos <b>${totals.findings}</b></label>`,
        ...SEVERITIES.filter((s) => totals.bySeverity[s] > 0).map(
            (s) => `<input type="radio" name="sev" id="sev-${s}"><label for="sev-${s}" data-sev="${s}">${LABEL[s]} <b>${totals.bySeverity[s]}</b></label>`,
        ),
    ].join('');

    const filterRules = SEVERITIES.map((s) => `main:has(#sev-${s}:checked) .finding:not([data-sev="${s}"]){display:none}`).join('\n');

    return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Informe LogSentinel · ${formatDate(report.generatedAt).slice(0, 10)}</title>
<style>
:root{--bg:#f4f5f3;--card:#fff;--ink:#14171a;--ink2:#4f5660;--ink3:#7b828b;--rule:#dfe2de;--crit:#a3161a;--crit-bg:#fbeaea;--high:#c2410c;--high-bg:#fdf0e7;--med:#9a6700;--med-bg:#fbf4e1;--low:#0b6e8a;--low-bg:#e6f3f7;--ok:#1d6b45;--ok-bg:#e7f3ec;--mono:ui-monospace,"Cascadia Mono",Consolas,monospace}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:20px}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:1120px;margin:0 auto;padding:0 24px 96px}
a{color:inherit}code,.mono{font-family:var(--mono);font-size:.86em}
h1,h2,h3,h4,p,ol,ul,dl,dd{margin:0}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;flex-wrap:wrap;padding:40px 0 24px;border-bottom:1.5px solid var(--ink)}
.brand{font:700 13px/1 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--ink2);margin-bottom:10px}
h1{font-size:32px;line-height:1.1;letter-spacing:-.02em}
.meta{text-align:right;color:var(--ink2);font-size:13px;line-height:1.7}
.meta b{color:var(--ink);font-weight:600}
nav.toc{display:flex;gap:20px;flex-wrap:wrap;padding:14px 0;font-size:14px;color:var(--ink2)}
nav.toc a{text-decoration:none}nav.toc a:hover{color:var(--ink);text-decoration:underline}
.verdict{display:grid;grid-template-columns:1.3fr 1fr;gap:32px;align-items:center;margin-top:12px;padding:28px 32px;background:var(--card);border:1px solid var(--rule);border-top:4px solid var(--v)}
.verdict[data-sev=critical]{--v:var(--crit)}.verdict[data-sev=high]{--v:var(--high)}.verdict[data-sev=medium]{--v:var(--med)}.verdict[data-sev=low]{--v:var(--low)}.verdict[data-sev=none]{--v:var(--ok)}
.verdict h2{font-size:28px;letter-spacing:-.02em;color:var(--v);border:0;padding:0;margin:0 0 6px}
.verdict p{color:var(--ink2);font-size:16px;max-width:52ch}
.counts{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--rule);border:1px solid var(--rule)}
.counts div{background:var(--card);padding:12px 14px}
.counts b{display:block;font-size:26px;line-height:1.1;font-variant-numeric:tabular-nums}
.counts span{font-size:12px;color:var(--ink2)}
.counts [data-sev=critical] b{color:var(--crit)}.counts [data-sev=high] b{color:var(--high)}.counts [data-sev=medium] b{color:var(--med)}.counts [data-sev=low] b{color:var(--low)}
.counts .zero b{color:var(--ink3)}
section{margin-top:56px}
h2{font-size:20px;letter-spacing:-.01em;padding-bottom:10px;margin-bottom:16px;border-bottom:1px solid var(--rule)}
.lead{color:var(--ink2);margin:-6px 0 16px;font-size:14px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:40px}
.grid2 section{margin-top:56px}
.key{list-style:none;padding:0;display:flex;flex-direction:column;gap:8px}
.key a{display:flex;gap:12px;align-items:baseline;padding:12px 14px;background:var(--card);border:1px solid var(--rule);text-decoration:none}
.key a:hover{border-color:var(--ink3)}
.sources{list-style:none;padding:0;display:flex;flex-direction:column;gap:8px}
.sources li{display:flex;flex-direction:column;padding:12px 14px;background:var(--card);border:1px solid var(--rule)}
.sources span{font-size:13px;color:var(--ink2)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--rule);font-size:14px}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--rule);vertical-align:baseline}
th{font-size:12px;font-weight:600;color:var(--ink2);background:#fafbfa}
tr:last-child td{border-bottom:0}td a{text-decoration:none}td a:hover{text-decoration:underline}
.num-cell{text-align:right;font-variant-numeric:tabular-nums}
.rules code{display:inline-block;margin:0 6px 2px 0;color:var(--ink2)}
.pill{display:inline-block;min-width:58px;text-align:center;font-size:11px;font-weight:700;letter-spacing:.02em;padding:2px 8px;border-radius:2px;white-space:nowrap}
[data-sev=critical].pill{background:var(--crit);color:#fff}[data-sev=high].pill{background:var(--high-bg);color:var(--high)}
[data-sev=medium].pill{background:var(--med-bg);color:var(--med)}[data-sev=low].pill{background:var(--low-bg);color:var(--low)}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.filters input{position:absolute;opacity:0;pointer-events:none}
.filters label{padding:6px 12px;border:1px solid var(--rule);background:var(--card);font-size:13px;cursor:pointer;user-select:none}
.filters label b{margin-left:4px;font-variant-numeric:tabular-nums}
.filters input:checked+label{background:var(--ink);border-color:var(--ink);color:#fff}
.filters input:focus-visible+label{outline:2px solid var(--low);outline-offset:2px}
${filterRules}
.finding{background:var(--card);border:1px solid var(--rule);border-top:3px solid var(--fc);padding:22px 24px;margin-bottom:14px}
.finding[data-sev=critical]{--fc:var(--crit)}.finding[data-sev=high]{--fc:var(--high)}.finding[data-sev=medium]{--fc:var(--med)}.finding[data-sev=low]{--fc:var(--low)}
.finding-head{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.finding h3{font-size:18px;letter-spacing:-.01em;display:flex;gap:10px;align-items:baseline}
.finding h3 .num{font:500 13px var(--mono);color:var(--ink3)}
.rule{margin-left:auto;color:var(--ink3)}
.finding-desc{margin-top:10px;font-size:15px}
.guide{display:grid;grid-template-columns:1fr 1.2fr;gap:24px;margin-top:16px;padding:16px 18px;background:var(--bg)}
.guide h4{font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--ink2);margin-bottom:6px}
.guide p,.guide li{font-size:14px}.guide ol{padding-left:18px}
.facts{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px 24px;margin-top:16px}
.facts .wide{grid-column:1/-1}.facts dt{font-size:12px;color:var(--ink2)}
.facts dd a{display:block;text-decoration:none;color:var(--low)}.facts dd a:hover{text-decoration:underline}
details{margin-top:16px;border-top:1px solid var(--rule);padding-top:12px}
summary{cursor:pointer;font-size:13px;font-weight:600;color:var(--ink2)}
summary:hover{color:var(--ink)}
pre{margin:10px 0 0;background:#14171a;color:#dfe3e0;padding:14px 16px;overflow-x:auto;font:12.5px/1.6 var(--mono);white-space:pre}
.empty{padding:20px;background:var(--card);border:1px solid var(--rule);color:var(--ink2)}
footer{margin-top:64px;padding-top:16px;border-top:1px solid var(--rule);font-size:13px;color:var(--ink3)}
@media (max-width:820px){.verdict,.grid2,.guide{grid-template-columns:1fr}.facts{grid-template-columns:1fr 1fr}.meta{text-align:left}.rule{margin-left:0}.counts{grid-template-columns:repeat(2,1fr)}}
@media print{body{background:#fff}.filters,nav.toc{display:none}.finding{break-inside:avoid}details{display:none}}
</style>
</head>
<body>
<main>
<header class="top">
  <div>
    <p class="brand">LogSentinel</p>
    <h1>Informe de análisis de logs</h1>
  </div>
  <p class="meta">
    Generado <b>${formatDate(report.generatedAt)}</b> UTC<br>
    ${report.period ? `Periodo analizado <b>${formatRange(report.period.from, report.period.to)}</b> UTC<br>` : ''}
    <b>${totals.events.toLocaleString('es-ES')}</b> eventos en ${report.sources.length} fichero(s)
  </p>
</header>
<nav class="toc"><a href="#resumen">Resumen</a><a href="#cronologia">Cronología</a><a href="#ips">IPs</a><a href="#hallazgos">Hallazgos</a></nav>

<div class="verdict" data-sev="${worst}" id="resumen">
  <div>
    <h2>${verdict.title}</h2>
    <p>${totals.findings === 0 ? verdict.text : `${totals.findings} hallazgo(s) en total. ${verdict.text}`}</p>
  </div>
  <div class="counts">
    ${SEVERITIES.map((s) => `<div data-sev="${s}" class="${totals.bySeverity[s] === 0 ? 'zero' : ''}"><b>${totals.bySeverity[s]}</b><span>${LABEL[s]}</span></div>`).join('')}
  </div>
</div>

<div class="grid2">
  <section>
    <h2>Lo más importante</h2>
    ${key ? `<ul class="key">${key}</ul>` : '<p class="empty">No hay hallazgos de gravedad alta o crítica.</p>'}
  </section>
  <section>
    <h2>Ficheros analizados</h2>
    <ul class="sources">${sources}</ul>
  </section>
</div>

<section id="cronologia">
  <h2>Cronología</h2>
  <p class="lead">Los hallazgos en el orden en que empezaron. Sirve para reconstruir la secuencia de un ataque.</p>
  ${timeline ? `<table><thead><tr><th>Hora (UTC)</th><th>Gravedad</th><th>Hallazgo</th><th>Origen</th></tr></thead><tbody>${timeline}</tbody></table>` : '<p class="empty">Sin hallazgos.</p>'}
</section>

<section id="ips">
  <h2>IPs con más riesgo</h2>
  <p class="lead">Puntuación según la gravedad de sus hallazgos (crítica 10, alta 7, media 3, baja 1). Las primeras son las que conviene bloquear antes.</p>
  ${ipRows ? `<table><thead><tr><th>IP</th><th>Peor gravedad</th><th class="num-cell">Puntos</th><th class="num-cell">Hallazgos</th><th>Reglas</th></tr></thead><tbody>${ipRows}</tbody></table>` : '<p class="empty">Sin IPs sospechosas.</p>'}
</section>

<section id="hallazgos">
  <h2>Hallazgos</h2>
  ${findings.length ? `<div class="filters" role="radiogroup" aria-label="Filtrar por gravedad">${filters}</div>${findings.map(renderFinding).join('')}` : '<p class="empty">No se han detectado actividades sospechosas.</p>'}
</section>

<footer>
  Generado por LogSentinel. Las detecciones se basan en firmas y umbrales: confirma cada hallazgo antes de actuar.
</footer>
</main>
</body>
</html>
`;
}
