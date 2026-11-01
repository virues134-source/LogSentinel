import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAuthLog } from '../src/parsers/auth-log.ts';
import { parseAccessLog } from '../src/parsers/access-log.ts';
import { runDetectors } from '../src/analyzer.ts';
import { normalizePath } from '../src/detectors/web.ts';
import { DEFAULT_CONFIG } from '../src/types.ts';
import type { LogEvent } from '../src/types.ts';

const pad = (n: number) => String(n).padStart(2, '0');

function sshLines(count: number, build: (i: number, time: string) => string, startMinute = 0, stepSeconds = 2): string {
    return Array.from({ length: count }, (_, i) => {
        const total = startMinute * 60 + i * stepSeconds;
        const time = `${pad(Math.floor(total / 3600) + 2)}:${pad(Math.floor(total / 60) % 60)}:${pad(total % 60)}`;
        return build(i, time);
    }).join('\n');
}

const auth = (text: string) => parseAuthLog(text, 'auth.log', 2026).events as LogEvent[];
const web = (text: string) => parseAccessLog(text, 'access.log').events as LogEvent[];
const rules = (events: LogEvent[]) => runDetectors(events, DEFAULT_CONFIG).map((f) => f.rule);

test('fuerza bruta: se dispara al superar el umbral', () => {
    const events = auth(sshLines(12, (_, t) => `Oct 27 ${t} h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2`));
    const findings = runDetectors(events);
    assert.deepEqual(findings.map((f) => f.rule), ['ssh-brute-force']);
    assert.equal(findings[0].ip, '203.0.113.5');
    assert.equal(findings[0].count, 12);
});

test('fuerza bruta: no se dispara por debajo del umbral', () => {
    const events = auth(sshLines(9, (_, t) => `Oct 27 ${t} h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2`));
    assert.deepEqual(rules(events), []);
});

test('fuerza bruta: intentos muy espaciados no cuentan como ataque', () => {
    // 12 fallos, uno cada 2 minutos: nunca hay 10 dentro de 5 minutos
    const events = auth(sshLines(12, (_, t) => `Oct 27 ${t} h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2`, 0, 120));
    assert.deepEqual(rules(events), []);
});

test('password spraying: muchos usuarios distintos desde una IP, sin duplicar fuerza bruta', () => {
    const users = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l'];
    const events = auth(sshLines(users.length, (i, t) => [
        `Oct 27 ${t} h sshd[1]: Invalid user ${users[i]} from 198.51.100.23 port 1`,
        `Oct 27 ${t} h sshd[1]: Failed password for invalid user ${users[i]} from 198.51.100.23 port 1 ssh2`,
    ].join('\n')));
    const findings = runDetectors(events);
    assert.deepEqual(findings.map((f) => f.rule), ['ssh-password-spray']);
    // "Invalid user" + "Failed ... invalid user" es un único intento
    assert.equal(findings[0].count, 12);
});

test('login correcto tras fallos: alerta crítica', () => {
    const text = sshLines(6, (_, t) => `Oct 27 ${t} h sshd[1]: Failed password for deploy from 192.0.2.77 port 1 ssh2`) +
        '\nOct 27 02:05:00 h sshd[1]: Accepted password for deploy from 192.0.2.77 port 1 ssh2';
    const findings = runDetectors(auth(text));
    const hit = findings.find((f) => f.rule === 'ssh-success-after-failures');
    assert.ok(hit);
    assert.equal(hit.severity, 'critical');
    assert.equal(hit.user, 'deploy');
});

test('login correcto tras un único error de contraseña: no alerta', () => {
    const events = auth([
        'Oct 27 09:00:00 h sshd[1]: Failed password for bob from 10.0.0.22 port 1 ssh2',
        'Oct 27 09:00:05 h sshd[1]: Accepted password for bob from 10.0.0.22 port 1 ssh2',
    ].join('\n'));
    assert.deepEqual(rules(events), []);
});

test('sudo: agrupa por usuario y sube la gravedad con varios tipos de comando', () => {
    const findings = runDetectors(auth([
        'Oct 27 04:14:00 h sudo:   deploy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow',
        'Oct 27 04:15:00 h sudo:   deploy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/useradd x',
        'Oct 27 04:16:00 h sudo:   deploy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/history -c',
        'Oct 27 04:17:00 h sudo:   alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx',
    ].join('\n')));
    assert.equal(findings.length, 1);
    assert.equal(findings[0].user, 'deploy');
    assert.equal(findings[0].severity, 'high');
    assert.equal(findings[0].count, 3);
});

const req = (ip: string, path: string, status = 404, ua = 'Mozilla/5.0', time = '14:20:04') =>
    `${ip} - - [27/Oct/2026:${time} +0000] "GET ${path} HTTP/1.1" ${status} 100 "-" "${ua}"`;

test('normalizePath: decodifica doble codificación', () => {
    assert.equal(normalizePath('/f?x=%252e%252e%252fetc%252fpasswd'), '/f?x=../etc/passwd');
    assert.equal(normalizePath('/q?a=%ZZ'), '/q?a=%zz');
});

test('SQLi: detecta y marca como crítica si respondió 200', () => {
    const findings = runDetectors(web([
        req('203.0.113.99', "/p?id=1%27%20OR%20%271%27%3D%271", 200),
        req('203.0.113.99', '/p?id=1%20UNION%20SELECT%20password%20FROM%20users', 500),
    ].join('\n')));
    assert.equal(findings.length, 1);
    assert.equal(findings[0].rule, 'web-sql-injection');
    assert.equal(findings[0].severity, 'critical');
});

test('path traversal con doble codificación', () => {
    const findings = runDetectors(web(req('192.0.2.150', '/d?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd', 403)));
    assert.deepEqual(findings.map((f) => f.rule), ['web-path-traversal']);
    assert.equal(findings[0].severity, 'high');
});

test('una petición cuenta solo para la regla más específica', () => {
    const findings = runDetectors(web(req('203.0.113.140', '/ping?host=1.1.1.1%3Bcat%20%2Fetc%2Fpasswd', 500)));
    assert.deepEqual(findings.map((f) => f.rule), ['web-command-injection']);
});

test('XSS y ficheros sensibles', () => {
    assert.deepEqual(rules(web(req('198.51.100.61', '/s?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', 200))), ['web-xss']);
    assert.deepEqual(rules(web(req('198.51.100.70', '/.env'))), ['web-sensitive-file-probe']);
    assert.deepEqual(rules(web(req('198.51.100.70', '/.git/config'))), ['web-sensitive-file-probe']);
});

test('escáner por User-Agent', () => {
    const findings = runDetectors(web(req('198.51.100.200', '/', 200, 'Mozilla/5.00 (Nikto/2.5.0)')));
    assert.deepEqual(findings.map((f) => f.rule), ['web-scanner-user-agent']);
    assert.match(findings[0].description, /nikto/);
});

test('fuzzing de rutas: muchos 404 en poco tiempo', () => {
    const lines = Array.from({ length: 30 }, (_, i) => req('198.51.100.200', `/ruta-${i}`, 404, 'Mozilla/5.0', `13:02:${pad(i)}`));
    assert.deepEqual(rules(web(lines.join('\n'))), ['web-directory-bruteforce']);
});

test('tráfico normal: sin falsos positivos', () => {
    const lines = [
        req('203.0.113.10', '/', 200),
        req('203.0.113.10', '/productos?id=12', 200),
        req('203.0.113.11', '/blog/como-elegir-un-portatil', 200),
        req('203.0.113.12', '/buscar?q=zapatillas%20running', 200),
        req('203.0.113.12', "/buscar?q=l%27oreal", 200),
        req('203.0.113.13', '/favicon.ico', 404),
    ];
    assert.deepEqual(rules(web(lines.join('\n'))), []);
});
