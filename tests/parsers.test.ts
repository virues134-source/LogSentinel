import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAuthLine, parseAuthLog } from '../src/parsers/auth-log.ts';
import { parseAccessLine } from '../src/parsers/access-log.ts';

test('auth: intento fallido con usuario válido', () => {
    const e = parseAuthLine('Oct 27 02:10:02 web01 sshd[2145]: Failed password for root from 203.0.113.45 port 31424 ssh2', 1, 'auth.log', 2026);
    assert.ok(e);
    assert.equal(e.action, 'failed');
    assert.equal(e.user, 'root');
    assert.equal(e.ip, '203.0.113.45');
    assert.equal(e.method, 'password');
    // syslog no lleva zona horaria: se interpreta como hora local
    assert.equal(e.timestamp.getHours(), 2);
    assert.equal(e.timestamp.getMinutes(), 10);
    assert.equal(e.timestamp.getDate(), 27);
});

test('auth: intento fallido con usuario inexistente', () => {
    const e = parseAuthLine('Oct 27 02:10:00 web01 sshd[2144]: Failed password for invalid user admin from 203.0.113.45 port 51087 ssh2', 1, 'auth.log', 2026);
    assert.equal(e?.action, 'invalid_user');
    assert.equal(e?.user, 'admin');
    assert.equal(e?.method, 'password');
});

test('auth: login aceptado con clave pública', () => {
    const e = parseAuthLine('Oct  7 09:01:00 web01 sshd[99]: Accepted publickey for alice from 10.0.0.15 port 50000 ssh2: ED25519 SHA256:abc', 1, 'auth.log', 2026);
    assert.equal(e?.action, 'accepted');
    assert.equal(e?.user, 'alice');
    assert.equal(e?.method, 'publickey');
    assert.equal(e?.timestamp.getDate(), 7);
});

test('auth: formato RFC 3339 e IPv6', () => {
    const e = parseAuthLine('2026-10-27T02:10:02.123456+01:00 web01 sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2', 1, 'auth.log', 2026);
    assert.equal(e?.ip, '2001:db8::1');
    assert.equal(e?.timestamp.toISOString(), '2026-10-27T01:10:02.123Z');
});

test('auth: comando sudo', () => {
    const e = parseAuthLine('Oct 27 04:14:00 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow', 1, 'auth.log', 2026);
    assert.equal(e?.action, 'sudo');
    assert.equal(e?.user, 'deploy');
    assert.equal(e?.command, '/usr/bin/cat /etc/shadow');
});

test('auth: ignora líneas que no interesan y las cuenta', () => {
    const result = parseAuthLog(
        [
            'Oct 27 02:10:02 web01 CRON[5]: pam_unix(cron:session): session opened for user root',
            'basura sin formato',
            'Oct 27 02:10:02 web01 sshd[2145]: Failed password for root from 203.0.113.45 port 31424 ssh2',
            '',
        ].join('\n'),
        'auth.log',
        2026,
    );
    assert.equal(result.events.length, 1);
    assert.equal(result.skipped, 2);
});

test('web: línea en formato combined', () => {
    const e = parseAccessLine('203.0.113.99 - - [27/Oct/2026:14:20:04 +0000] "GET /productos?id=12 HTTP/1.1" 200 98000 "-" "sqlmap/1.8.4#stable"', 1, 'access.log');
    assert.ok(e);
    assert.equal(e.ip, '203.0.113.99');
    assert.equal(e.method, 'GET');
    assert.equal(e.path, '/productos?id=12');
    assert.equal(e.status, 200);
    assert.equal(e.bytes, 98000);
    assert.equal(e.userAgent, 'sqlmap/1.8.4#stable');
    assert.equal(e.timestamp.toISOString(), '2026-10-27T14:20:04.000Z');
});

test('web: zona horaria y tamaño "-"', () => {
    const e = parseAccessLine('192.0.2.1 - - [27/Oct/2026:16:20:04 +0200] "HEAD / HTTP/1.1" 304 - "-" "curl/8"', 1, 'access.log');
    assert.equal(e?.bytes, 0);
    assert.equal(e?.timestamp.toISOString(), '2026-10-27T14:20:04.000Z');
});

test('web: formato common sin referrer ni user agent', () => {
    const e = parseAccessLine('192.0.2.1 - frank [27/Oct/2026:13:55:36 +0000] "GET /a.gif HTTP/1.0" 200 2326', 1, 'access.log');
    assert.equal(e?.userAgent, '-');
});

test('web: rechaza líneas mal formadas', () => {
    assert.equal(parseAccessLine('esto no es un log', 1, 'access.log'), null);
});
