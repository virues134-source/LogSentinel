import { test } from 'node:test';
import assert from 'node:assert/strict';
import { appendFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createMonitor } from '../src/live/monitor.ts';
import { tailFile } from '../src/live/tail.ts';

const pad = (n: number) => String(n).padStart(2, '0');
const login = (i: number, status: number) =>
    `192.0.2.77 - - [27/Oct/2026:20:53:${pad(i)} +0000] "POST /login HTTP/1.1" ${status} 120 "-" "Mozilla/4.0 (Hydra)"`;

test('login web: fuerza bruta que acaba en acceso sube a crítica', () => {
    const monitor = createMonitor({ type: 'web', source: 'access.log' });

    const first = monitor.ingest(Array.from({ length: 12 }, (_, i) => login(i, 401)));
    const brute = first.changes.find((c) => c.finding.rule === 'web-login-bruteforce');
    assert.ok(brute, 'debe avisar de fuerza bruta');
    assert.equal(brute.kind, 'new');
    assert.equal(brute.finding.severity, 'high');

    const second = monitor.ingest([login(30, 302)]);
    const success = second.changes.find((c) => c.finding.rule === 'web-login-success-after-failures');
    assert.ok(success, 'debe avisar del acceso conseguido');
    assert.equal(success.finding.severity, 'critical');
    assert.ok(!second.findings.some((f) => f.rule === 'web-login-bruteforce'));
});

test('monitor: no repite alertas que ya ha notificado', () => {
    const monitor = createMonitor({ type: 'web', source: 'access.log' });
    monitor.ingest(Array.from({ length: 12 }, (_, i) => login(i, 401)));
    const again = monitor.ingest([login(20, 401)]);
    assert.equal(again.changes.length, 0);
});

test('tail: entrega solo las líneas nuevas y completas', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'logsentinel-'));
    const file = join(dir, 'access.log');
    writeFileSync(file, 'línea antigua\n');

    const received: string[] = [];
    const stop = tailFile(file, (lines) => received.push(...lines), { intervalMs: 50 });
    try {
        appendFileSync(file, 'nueva 1\nnueva 2\nincompl');
        await new Promise((r) => setTimeout(r, 400));
        appendFileSync(file, 'eta\n');
        await new Promise((r) => setTimeout(r, 400));
    } finally {
        stop();
        rmSync(dir, { recursive: true, force: true });
    }
    assert.deepEqual(received, ['nueva 1', 'nueva 2', 'incompleta']);
});
