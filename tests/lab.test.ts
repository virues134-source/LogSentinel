import { test } from 'node:test';
import assert from 'node:assert/strict';
import { accessLogLine, handleShopRequest } from '../lab/shop-core.ts';
import { httpTransport, PHASES, runAttackScenario } from '../lab/attacks.ts';
import { parseAccessLine } from '../src/parsers/access-log.ts';
import { createMonitor } from '../src/live/monitor.ts';

const visit = (url: string, method = 'GET', body?: string) =>
    handleShopRequest({ method, url, ip: '192.0.2.1', userAgent: 'test', body });

test('tienda: respuestas básicas', () => {
    assert.equal(visit('/').status, 200);
    assert.equal(visit('/productos?id=2').status, 200);
    assert.equal(visit('/productos?id=99').status, 404);
    assert.equal(visit('/no-existe').status, 404);
});

test('tienda: el fallo de parseInt deja pasar la inyección SQL con un 200', () => {
    assert.equal(visit(`/productos?id=${encodeURIComponent("1' OR '1'='1")}`).status, 200);
    assert.equal(visit('/productos?id=abc').status, 500);
});

test('tienda: el buscador escapa lo que recibe', () => {
    const page = visit(`/buscar?q=${encodeURIComponent('<script>alert(1)</script>')}`).body;
    assert.ok(!page.includes('<script>alert(1)</script>'));
    assert.ok(page.includes('&#60;script&#62;'));
});

test('tienda: descargas rechazan rutas con ../ y no leen ficheros', () => {
    assert.equal(visit('/descargas?file=../../etc/passwd').status, 403);
    assert.equal(visit('/descargas?file=catalogo.pdf').status, 404);
});

test('tienda: login', () => {
    assert.equal(visit('/login', 'POST', 'user=admin&password=mala').status, 401);
    const ok = visit('/login', 'POST', 'user=admin&password=nebula2026');
    assert.equal(ok.status, 302);
    assert.equal(ok.location, '/panel');
});

test('tienda: sus líneas de log las entiende el parser de LogSentinel', () => {
    const req = { method: 'GET', url: "/buscar?q=caf%C3%A9 \"x\"", ip: '198.51.100.7', userAgent: 'Mozilla/5.0 "raro"' };
    const line = accessLogLine(req, handleShopRequest(req), new Date(2026, 9, 27, 10, 0, 0));
    const event = parseAccessLine(line, 1, 'access.log');
    assert.ok(event, line);
    assert.equal(event.ip, '198.51.100.7');
    assert.equal(event.status, 200);
    assert.equal(event.userAgent, 'Mozilla/5.0 \\"raro\\"');
});

test('simulador: se niega a atacar algo que no sea este ordenador', () => {
    assert.throws(() => httpTransport('https://example.com'), /solo puede atacar al laboratorio local/);
    assert.doesNotThrow(() => httpTransport('http://127.0.0.1:8080'));
});

test('de extremo a extremo: la simulación completa dispara cada regla esperada', async () => {
    const monitor = createMonitor({ type: 'web', source: 'access.log' });
    const announced: string[] = [];

    await runAttackScenario(
        async (req) => {
            const shopReq = { method: req.method, url: req.path, ip: req.ip, userAgent: req.userAgent, body: req.body };
            monitor.ingest([accessLogLine(shopReq, handleShopRequest(shopReq))]);
        },
        (text) => announced.push(text),
        1000,
    );

    const rules = new Set(monitor.report().findings.map((f) => f.rule));
    for (const rule of [
        'web-scanner-user-agent', 'web-directory-bruteforce', 'web-sensitive-file-probe',
        'web-sql-injection', 'web-xss', 'web-path-traversal', 'web-command-injection',
        'web-login-success-after-failures',
    ]) {
        assert.ok(rules.has(rule), `falta ${rule}`);
    }
    // Las visitas normales (203.0.113.10-39) no deben generar alertas
    assert.ok(!monitor.report().findings.some((f) => f.ip?.startsWith('203.0.113.1') && f.ip !== '203.0.113.140'));
    assert.equal(announced.length, PHASES.length + 1);
});
