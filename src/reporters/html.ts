import type { Report } from '../analyzer.ts';
import type { Finding, Severity } from '../types.ts';
import { SEVERITY_ORDER } from '../types.ts';
import { mitreUrl } from '../mitre.ts';
import { GUIDANCE } from '../guidance.ts';
import { formatClock, formatDateTime, formatDay, utcOffsetLabel } from '../time.ts';

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

const formatDate = formatDateTime;
const formatTime = (date: Date) => formatClock(date).slice(0, 5);

function formatRange(from: Date, to: Date): string {
    if (from.getTime() === to.getTime()) return formatDate(from);
    return formatDay(from) === formatDay(to) ? `${formatDate(from)} – ${formatClock(to)}` : `${formatDate(from)} – ${formatDate(to)}`;
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
    <div><dt>Cuándo</dt><dd>${formatRange(f.firstSeen, f.lastSeen)}</dd></div>
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
<title>Informe LogSentinel · ${formatDay(report.generatedAt)}</title>
<style>
:root{--paper:#fbede1;--paper-2:#f6e1d0;--ink:#1d1916;--ink2:#5b4e45;--ink3:#6f6157;--rule:#e2c9b5;--strong:#1d1916;--crit:#8f1d3f;--crit-tint:#f3d5d6;--high:#b54a14;--high-tint:#f7dcc8;--med:#8a6200;--med-tint:#f4e4bf;--low:#25657a;--low-tint:#d9e6e6;--ok:#2f6b5a;--mono:ui-monospace,"Cascadia Mono","SF Mono",Consolas,monospace;--sans:"Segoe UI Variable Text","Segoe UI",-apple-system,BlinkMacSystemFont,"Helvetica Neue",Arial,sans-serif}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:20px;background:var(--paper)}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.6 var(--sans);font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased}
::selection{background:var(--ink);color:var(--paper)}
main{max-width:1120px;margin:0 auto;padding:0 28px 96px}
a{color:inherit}code,.mono{font-family:var(--mono);font-size:.86em}
h1,h2,h3,h4,p,ol,ul,dl,dd{margin:0}
.top{display:grid;grid-template-columns:1fr auto;align-items:end;gap:24px;padding:28px 0 14px;border-bottom:3px solid var(--strong)}
h1{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;font-size:32px;line-height:1.1;letter-spacing:-.02em}
.brand{font-weight:800;letter-spacing:-.03em}
.brand span{color:var(--crit)}
h1 .surface{font-weight:400;color:var(--ink2)}
.meta{text-align:right;color:var(--ink2);font-size:13px;line-height:1.7}
.meta b{color:var(--ink);font-weight:600}
nav.toc{display:flex;gap:22px;flex-wrap:wrap;padding:10px 0;font-size:13px;font-weight:600;color:var(--ink2);border-bottom:1px solid var(--rule)}
nav.toc a{text-decoration:none}nav.toc a:hover{color:var(--ink)}
.verdict{display:grid;grid-template-columns:1.3fr 1fr;gap:40px;align-items:end;padding:28px 0 24px;border-bottom:1px solid var(--rule)}
.verdict[data-sev=critical]{--v:var(--crit)}.verdict[data-sev=high]{--v:var(--high)}.verdict[data-sev=medium]{--v:var(--med)}.verdict[data-sev=low]{--v:var(--low)}.verdict[data-sev=none]{--v:var(--ok)}
.verdict .kicker{font-size:11px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:var(--v);margin-bottom:6px}
.verdict h2{font-size:40px;line-height:1.05;letter-spacing:-.03em;border:0;padding:0;margin:0 0 10px}
.verdict p{color:var(--ink2);font-size:17px;max-width:52ch}
.counts{display:grid;grid-template-columns:repeat(4,1fr)}
.counts div{padding:0 0 0 16px;border-left:1px solid var(--rule)}
.counts b{display:block;font-size:34px;line-height:1.1;letter-spacing:-.02em}
.counts span{font-size:12px;font-weight:600;color:var(--ink2)}
.counts [data-sev=critical] b{color:var(--crit)}.counts [data-sev=high] b{color:var(--high)}.counts [data-sev=medium] b{color:var(--med)}.counts [data-sev=low] b{color:var(--low)}
.counts .zero b{color:var(--ink3)}
.explainer{display:grid;grid-template-columns:1fr 2fr;gap:40px;margin-top:28px;padding:20px 22px;background:var(--paper-2)}
.explainer h2{border:0;padding:0;margin:0 0 6px;font-size:17px}
.explainer>div>p{font-size:14px;color:var(--ink2)}
.explainer dl{display:grid;grid-template-columns:repeat(2,1fr);gap:14px 28px}
.explainer dt{font-weight:700;font-size:14px}
.explainer dd{font-size:13.5px;color:var(--ink2)}
section{margin-top:52px}
h2{font-size:19px;letter-spacing:-.01em;padding-bottom:8px;margin-bottom:14px;border-bottom:3px solid var(--strong)}
.lead{color:var(--ink2);margin:-4px 0 14px;font-size:14px}
.grid2{display:grid;grid-template-columns:1.4fr 1fr;gap:40px}
.key,.sources{list-style:none;padding:0}
.key a{display:grid;grid-template-columns:76px 1fr;gap:12px;align-items:baseline;padding:11px 0;border-bottom:1px solid var(--rule);text-decoration:none}
.key a:hover b{text-decoration:underline}
.sources li{display:flex;flex-direction:column;padding:11px 0;border-bottom:1px solid var(--rule)}
.sources span{font-size:13px;color:var(--ink2)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 12px 9px 0;border-bottom:1px solid var(--rule);vertical-align:baseline}
th{font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--ink2)}
td a{text-decoration:none}td a:hover{text-decoration:underline}
.num-cell{text-align:right}
.rules code{display:inline-block;margin:0 8px 2px 0;color:var(--ink2)}
.pill{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;white-space:nowrap}
[data-sev=critical].pill{color:var(--crit)}[data-sev=high].pill{color:var(--high)}[data-sev=medium].pill{color:var(--med)}[data-sev=low].pill{color:var(--low)}
.filters{display:flex;gap:0;flex-wrap:wrap;margin-bottom:6px;border:1px solid var(--ink);width:max-content;max-width:100%}
.filters input{position:absolute;opacity:0;pointer-events:none}
.filters label{padding:7px 14px;font-size:13px;font-weight:600;cursor:pointer;user-select:none}
.filters label+input+label{border-left:1px solid var(--ink)}
.filters label b{margin-left:4px}
.filters input:checked+label{background:var(--ink);color:var(--paper)}
.filters input:focus-visible+label{outline:2px solid var(--low);outline-offset:2px}
${filterRules}
.finding{padding:24px 0;border-bottom:1px solid var(--rule)}
.finding-head{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
.finding h3{font-size:21px;line-height:1.25;letter-spacing:-.015em;display:flex;gap:10px;align-items:baseline}
.finding[data-sev=critical] h3{font-size:24px}
.finding h3 .num{font-size:14px;font-weight:600;color:var(--ink3)}
.rule{margin-left:auto;color:var(--ink3)}
.finding-desc{margin-top:8px;font-size:16px;max-width:75ch}
.guide{display:grid;grid-template-columns:1fr 1.2fr;gap:28px;margin-top:16px;padding:16px 18px;background:var(--paper-2)}
.guide h4{font-size:11px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--ink2);margin-bottom:6px}
.guide p,.guide li{font-size:14px}.guide ol{padding-left:18px}.guide li+li{margin-top:3px}
.facts{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px 24px;margin-top:16px}
.facts .wide{grid-column:1/-1}.facts dt{font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--ink2)}
.facts dd a{display:block;text-decoration:none;color:var(--low)}.facts dd a:hover{text-decoration:underline}
details{margin-top:14px}
summary{cursor:pointer;font-size:13px;font-weight:700;color:var(--ink2)}
summary:hover{color:var(--ink)}
pre{margin:10px 0 0;background:#1d1916;color:#efe2d6;padding:14px 16px;overflow-x:auto;font:12.5px/1.6 var(--mono);white-space:pre}
.empty{padding:16px 0;color:var(--ink2)}
footer{margin-top:64px;padding-top:14px;border-top:3px solid var(--strong);font-size:13px;color:var(--ink2)}
@media (max-width:820px){.verdict,.grid2,.guide,.explainer,.top{grid-template-columns:1fr}.explainer dl{grid-template-columns:1fr}.facts{grid-template-columns:1fr 1fr}.meta{text-align:left}.rule{margin-left:0}.counts{grid-template-columns:repeat(2,1fr);row-gap:12px}.verdict h2{font-size:32px}}
@media print{body,html{background:#fff}.filters,nav.toc{display:none}.finding{break-inside:avoid}details{display:none}}
</style>
</head>
<body>
<main>
<header class="top">
  <div>
    <h1><span class="brand">Log<span>Sentinel</span></span><span class="surface">Informe de análisis de logs</span></h1>
  </div>
  <p class="meta">
    Generado <b>${formatDate(report.generatedAt)}</b><br>
    ${report.period ? `Periodo analizado <b>${formatRange(report.period.from, report.period.to)}</b><br>` : ''}
    <b>${totals.events.toLocaleString('es-ES')}</b> eventos en ${report.sources.length} fichero(s) · horas en ${utcOffsetLabel(report.generatedAt)}
  </p>
</header>
<nav class="toc"><a href="#resumen">Resumen</a><a href="#como-leer">Cómo leer</a><a href="#cronologia">Cronología</a><a href="#ips">IPs</a><a href="#hallazgos">Hallazgos</a></nav>

<div class="verdict" data-sev="${worst}" id="resumen">
  <div>
    <h2>${verdict.title}</h2>
    <p>${totals.findings === 0 ? verdict.text : `${totals.findings} hallazgo(s) en total. ${verdict.text}`}</p>
  </div>
  <div class="counts">
    ${SEVERITIES.map((s) => `<div data-sev="${s}" class="${totals.bySeverity[s] === 0 ? 'zero' : ''}"><b>${totals.bySeverity[s]}</b><span>${LABEL[s]}</span></div>`).join('')}
  </div>
</div>

<div class="explainer" id="como-leer">
  <div>
    <h2>Cómo leer este informe</h2>
    <p>LogSentinel ha leído los registros (logs) de un servidor, donde se anota cada visita e intento de acceso, y ha buscado en ellos las huellas de ataques conocidos. Cada hallazgo es algo que encaja con un ataque.</p>
  </div>
  <dl>
    <div><dt>Gravedad</dt><dd>Crítica: el ataque parece haber funcionado. Alta: ataque activo. Media: reconocimiento o escaneo. Baja: menor.</dd></div>
    <div><dt>IP</dt><dd>La dirección de internet desde la que llegó el ataque. Es lo que se bloquea.</dd></div>
    <div><dt>Qué significa y qué hacer</dt><dd>Cada hallazgo lo explica en lenguaje normal y propone pasos concretos.</dd></div>
    <div><dt>Evidencia y MITRE ATT&amp;CK</dt><dd>Las líneas exactas del log que lo prueban, y el código de la técnica de ataque en el catálogo público que usan los equipos de seguridad.</dd></div>
  </dl>
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
  ${timeline ? `<table><thead><tr><th>Hora</th><th>Gravedad</th><th>Hallazgo</th><th>Origen</th></tr></thead><tbody>${timeline}</tbody></table>` : '<p class="empty">Sin hallazgos.</p>'}
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
