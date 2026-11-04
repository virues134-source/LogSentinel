import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseAuthLog } from '../src/parsers/auth-log.ts';
import { buildReport } from '../src/analyzer.ts';
import { filterUnsent, markSent, sendWebhook } from '../src/alerts.ts';
import { parseArgs } from '../src/cli.ts';
import { renderTerminal } from '../src/reporters/terminal.ts';
import { renderJson } from '../src/reporters/json.ts';

const { events, skipped } = parseAuthLog(readFileSync('samples/auth.log', 'utf8'), 'auth.log', 2026);
const report = buildReport(events, [{ file: 'auth.log', type: 'auth', events: events.length, skipped }]);

/** Imita un nodo Webhook de n8n: responde el código que decida `status` según las cabeceras. */
async function withWebhook(status: (headers: Record<string, unknown>) => number, run: (url: string, received: any[]) => Promise<void>) {
    const received: any[] = [];
    const server = createServer((req, res) => {
        let body = '';
        req.on('data', (chunk) => (body += chunk));
        req.on('end', () => {
            const code = status(req.headers);
            if (code === 200) received.push(JSON.parse(body));
            res.writeHead(code, code === 302 ? { location: 'https://otro.example/' } : {});
            res.end();
        });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
        await run(`http://127.0.0.1:${(server.address() as AddressInfo).port}/webhook/logsentinel`, received);
    } finally {
        server.close();
        server.closeAllConnections();
    }
}

const needsKey = (headers: Record<string, unknown>) => (headers['x-webhook-key'] === 'secreta' ? 200 : 403);
const auth = { header: 'X-Webhook-Key', key: 'secreta' };

test('webhook con Header Auth: acepta la clave correcta y el aviso dice qué hacer', async () => {
    await withWebhook(needsKey, async (url, received) => {
        await sendWebhook(url, report, report.findings, auth);
        assert.equal(received.length, 1);
        const brute = received[0].findings.find((f: any) => f.rule === 'ssh-brute-force');
        assert.ok(brute.description.length > 0);
        assert.ok(brute.meaning.length > 0);
        assert.ok(brute.actions.length > 0);
    });
});

test('webhook con Header Auth: sin clave o con clave errónea explica el 403', async () => {
    await withWebhook(needsKey, async (url, received) => {
        await assert.rejects(sendWebhook(url, report, report.findings), /LOGSENTINEL_WEBHOOK_KEY/);
        await assert.rejects(sendWebhook(url, report, report.findings, { ...auth, key: 'mala' }), /rechazó el envío \(403\)/);
        assert.equal(received.length, 0);
    });
});

test('webhook: no envía la clave sin cifrar a otra máquina', async () => {
    await assert.rejects(sendWebhook('http://n8n.example.com/webhook/x', report, report.findings, auth), /sin cifrar/);
});

test('webhook: no sigue redirecciones, para no filtrar la clave', async () => {
    await withWebhook(() => 302, async (url) => {
        await assert.rejects(sendWebhook(url, report, report.findings, auth), /respondió 302/);
    });
});

test('webhook: los errores no muestran la clave ni la contraseña de la URL', async () => {
    const hidden = (error: Error) => !/privada/.test(error.message);
    await withWebhook(() => 200, async (url) => {
        await assert.rejects(sendWebhook(url, report, report.findings, { ...auth, key: 'privada\nmal' }), hidden);
        await assert.rejects(sendWebhook(url, report, report.findings, { ...auth, key: 'contraseña-privada' }), hidden);
        await assert.rejects(sendWebhook(url.replace('http://', 'http://yo:privada@'), report, report.findings), hidden);
    });
});

test('webhook: explica si no puede conectar', async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    await new Promise((resolve) => server.close(resolve));
    await assert.rejects(sendWebhook(`http://127.0.0.1:${port}/x`, report, report.findings), /No se pudo conectar con el webhook \(ECONNREFUSED\)/);
    await assert.rejects(sendWebhook('nada', report, report.findings), /La URL del webhook no es válida/);
});

test('--webhook-state: crea la carpeta antes de enviar y rechaza un estado corrupto', () => {
    const dir = mkdtempSync(join(tmpdir(), 'logsentinel-'));
    const state = join(dir, 'sub', 'carpeta', 'enviados.json');
    assert.equal(filterUnsent(report.findings, state).length, report.findings.length);
    assert.deepEqual(JSON.parse(readFileSync(state, 'utf8')), []);
    const broken = join(dir, 'roto.json');
    writeFileSync(broken, '{roto');
    assert.throws(() => filterUnsent(report.findings, broken), /no es válido/);
});

test('--webhook-state: avisa una sola vez de cada hallazgo y otra vez si sube de gravedad', () => {
    const state = join(mkdtempSync(join(tmpdir(), 'logsentinel-')), 'enviados.json');
    const [first, ...rest] = report.findings;
    assert.equal(filterUnsent(report.findings, state).length, report.findings.length);
    markSent([first], state);
    assert.deepEqual(filterUnsent(report.findings, state), rest);
    markSent(rest, state);
    assert.equal(filterUnsent(report.findings, state).length, 0);
    const changed = { ...first, severity: first.severity === 'critical' ? 'high' as const : 'critical' as const };
    assert.equal(filterUnsent([changed], state).length, 1);
});

test('cada hallazgo dice qué hacer en terminal y en JSON', () => {
    assert.match(renderTerminal(report), /Qué hacer/);
    for (const f of JSON.parse(renderJson(report)).findings) assert.ok(f.actions.length > 0, f.rule);
});

test('la CLI acepta las opciones del webhook y valida la cabecera', () => {
    const options = parseArgs(['analyze', 'a.log', '--webhook', 'https://x/y', '--webhook-header', 'X-Clave', '--webhook-state', 'e.json']);
    assert.equal(options?.webhookHeader, 'X-Clave');
    assert.equal(options?.webhookState, 'e.json');
    assert.equal(parseArgs(['analyze', 'a.log'])?.webhookHeader, 'X-Webhook-Key');
    assert.throws(() => parseArgs(['analyze', 'a.log', '--webhook-header', 'mal: cabecera']));
    assert.throws(() => parseArgs(['analyze', 'a.log', '--webhook-state', 'e.json']), /necesitan --webhook/);
    assert.throws(() => parseArgs(['analyze', 'a.log', '--webhook-header', 'X-Clave']), /necesitan --webhook/);
});
