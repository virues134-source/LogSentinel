import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseAuthLog } from '../src/parsers/auth-log.ts';
import { parseAccessLog } from '../src/parsers/access-log.ts';
import { buildReport, withFindings, filterBySeverity } from '../src/analyzer.ts';
import { escapeHtml, renderHtml } from '../src/reporters/html.ts';
import { parseArgs } from '../src/cli.ts';
import type { LogEvent } from '../src/types.ts';

test('el informe HTML escapa el contenido de los logs (anti-XSS)', () => {
    const events = parseAccessLog(
        '198.51.100.61 - - [27/Oct/2026:17:03:00 +0000] "GET /buscar?q=<script>alert(1)</script> HTTP/1.1" 200 10 "-" "<img src=x onerror=alert(2)>"',
        'access.log',
    ).events as LogEvent[];
    const html = renderHtml(buildReport(events, [{ file: 'access.log', type: 'web', events: 1, skipped: 0 }]));

    assert.ok(!html.includes('<script>alert(1)</script>'));
    assert.ok(!html.includes('<img src=x'));
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
});

test('escapeHtml cubre los cinco caracteres peligrosos', () => {
    assert.equal(escapeHtml(`<a href="x" onclick='y'>&</a>`), '&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
});

test('los logs de ejemplo producen los hallazgos esperados', () => {
    const authEvents = parseAuthLog(readFileSync('samples/auth.log', 'utf8'), 'auth.log', 2026).events;
    const webEvents = parseAccessLog(readFileSync('samples/access.log', 'utf8'), 'access.log').events;
    const report = buildReport([...authEvents, ...webEvents] as LogEvent[], []);
    const found = new Set(report.findings.map((f) => f.rule));

    for (const rule of [
        'ssh-brute-force', 'ssh-password-spray', 'ssh-success-after-failures', 'ssh-root-login',
        'sudo-suspicious-command', 'web-sql-injection', 'web-command-injection', 'web-xss',
        'web-path-traversal', 'web-sensitive-file-probe', 'web-scanner-user-agent', 'web-directory-bruteforce',
    ]) {
        assert.ok(found.has(rule), `falta ${rule}`);
    }

    // Las IPs internas legítimas no deben aparecer salvo el login como root
    const flaggedIps = new Set(report.findings.map((f) => f.ip));
    assert.ok(!flaggedIps.has('10.0.0.15'));
    assert.ok(!flaggedIps.has('10.0.0.22'));
    assert.equal(report.topIps[0].worst, 'critical');
});

test('withFindings recalcula totales al filtrar por gravedad', () => {
    const authEvents = parseAuthLog(readFileSync('samples/auth.log', 'utf8'), 'auth.log', 2026).events;
    const full = buildReport(authEvents as LogEvent[], []);
    const filtered = withFindings(full, filterBySeverity(full.findings, 'critical'));
    assert.equal(filtered.totals.findings, filtered.findings.length);
    assert.equal(filtered.totals.bySeverity.high, 0);
    assert.ok(filtered.topIps.every((ip) => ip.worst === 'critical'));
});

test('CLI: valida argumentos', () => {
    assert.equal(parseArgs([]), null);
    assert.deepEqual(parseArgs(['analyze', 'a.log', '--format', 'json'])?.files, ['a.log']);
    assert.throws(() => parseArgs(['analyze']), /al menos un fichero/);
    assert.throws(() => parseArgs(['analyze', 'a.log', '--format', 'pdf']), /--format no válido/);
    assert.throws(() => parseArgs(['analyze', 'a.log', '--min-severity', 'extreme']), /--min-severity no válido/);
    assert.throws(() => parseArgs(['borrar', 'a.log']), /Comando desconocido/);
});
