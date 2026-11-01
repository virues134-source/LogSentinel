/**
 * Simulador de ataques del laboratorio. Genera las mismas peticiones que harían
 * herramientas como Nikto, sqlmap o Hydra contra la tienda ficticia.
 *
 * No sabe nada de LogSentinel: solo envía peticiones a través de un "transporte".
 * - En el laboratorio con Node, el transporte hace peticiones HTTP reales, y solo a
 *   127.0.0.1 / localhost (ver httpTransport).
 * - En la demo web, el transporte entrega la petición a la tienda que corre dentro
 *   del navegador. No sale nada a internet.
 *
 * Para representar atacantes distintos se usan IPs de documentación (RFC 5737).
 */

export interface AttackRequest {
    method: 'GET' | 'POST';
    path: string;
    ip: string;
    userAgent: string;
    body?: string;
}

export type Transport = (request: AttackRequest) => Promise<void>;

const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Transporte HTTP real para el laboratorio con Node. Se niega a salir de este ordenador. */
export function httpTransport(target: string): Transport {
    const base = new URL(target);
    if (!['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname)) {
        throw new Error(`El simulador solo puede atacar al laboratorio local, no a ${base.hostname}.`);
    }
    return async (req) => {
        try {
            const response = await fetch(new URL(req.path, base), {
                method: req.method,
                redirect: 'manual',
                headers: {
                    'user-agent': req.userAgent,
                    'x-forwarded-for': req.ip,
                    ...(req.body ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
                },
                body: req.body,
            });
            await response.arrayBuffer();
        } catch {
            // Si la tienda no responde a una petición concreta, seguimos con la siguiente.
        }
    };
}

export const PHASES = [
    'Tráfico normal: clientes visitando la tienda',
    'Reconocimiento: escaneo con Nikto desde 198.51.100.200',
    'Inyección SQL con sqlmap desde 203.0.113.99',
    'Código en el buscador (XSS) desde 198.51.100.61',
    'Path traversal: intento de leer /etc/passwd desde 192.0.2.150',
    'Inyección de comandos desde 203.0.113.140',
    'Fuerza bruta contra el acceso de empleados desde 192.0.2.77',
];

export async function runAttackScenario(send: Transport, announce: (text: string) => void, speed = 1): Promise<void> {
    const wait = (ms: number) => sleep(ms / speed);
    const get = (path: string, ip: string, userAgent = BROWSER) => send({ method: 'GET', path, ip, userAgent });
    const phase = (n: number) => announce(`Fase ${n} de ${PHASES.length} · ${PHASES[n - 1]}`);

    async function normalTraffic(count: number, delay: number) {
        const pages = ['/', '/productos?id=1', '/productos?id=3', '/buscar?q=kenia', '/productos?id=2', '/css/main.css', '/buscar?q=cacao', '/favicon.ico'];
        for (let i = 0; i < count; i++) {
            await get(pages[i % pages.length], `203.0.113.${10 + ((i * 7) % 30)}`);
            await wait(delay);
        }
    }

    phase(1);
    await normalTraffic(14, 350);

    phase(2);
    const NIKTO = 'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:007153)';
    const words = ['admin', 'administrator', 'wp-admin', 'wp-login.php', 'old', 'test', 'dev', 'backup', 'backups', 'db', 'uploads',
        'private', 'config', 'install', 'setup.php', 'info.php', 'phpinfo.php', 'shell.php', 'upload.php', 'temp', 'logs', 'debug',
        'portal', 'cpanel', 'webadmin', 'console', 'api', 'staging', 'manager/html', 'server-info', 'readme.html'];
    for (const word of words) {
        await get(`/${word}`, '198.51.100.200', NIKTO);
        await wait(90);
    }
    for (const path of ['/.env', '/.git/config', '/backup.sql', '/phpmyadmin/']) {
        await get(path, '198.51.100.200', NIKTO);
        await wait(150);
    }

    phase(3);
    const SQLMAP = 'sqlmap/1.8.4#stable (https://sqlmap.org)';
    for (const payload of [
        "1'",
        "1' OR '1'='1",
        '1 UNION ALL SELECT NULL,NULL,version()-- -',
        '1 AND SLEEP(5)',
        '-1 UNION SELECT table_name FROM information_schema.tables',
    ]) {
        await get(`/productos?id=${encodeURIComponent(payload)}`, '203.0.113.99', SQLMAP);
        await wait(700);
    }
    await normalTraffic(4, 300);

    phase(4);
    for (const payload of ['<script>alert(document.cookie)</script>', '<img src=x onerror=alert(1)>']) {
        await get(`/buscar?q=${encodeURIComponent(payload)}`, '198.51.100.61');
        await wait(900);
    }

    phase(5);
    for (const file of ['../../../../etc/passwd', '..%2F..%2F..%2Fetc%2Fpasswd', 'php://filter/convert.base64-encode/resource=index.php']) {
        await get(`/descargas?file=${file.includes('%') ? file : encodeURIComponent(file)}`, '192.0.2.150');
        await wait(800);
    }

    phase(6);
    for (const payload of ['127.0.0.1;cat /etc/passwd', '127.0.0.1|whoami']) {
        await get(`/tools/ping?host=${encodeURIComponent(payload)}`, '203.0.113.140', 'curl/8.5.0');
        await wait(900);
    }
    await normalTraffic(4, 300);

    phase(7);
    const HYDRA = 'Mozilla/4.0 (Hydra)';
    const passwords = ['123456', 'password', 'admin', 'admin123', 'qwerty', 'cafe', 'nebula', 'nebula1', 'nebula123', 'tostadero',
        'Nebula2025', 'nebula2025', 'welcome1', 'letmein', 'nebula2026'];
    for (const password of passwords) {
        await send({
            method: 'POST',
            path: '/login',
            ip: '192.0.2.77',
            userAgent: HYDRA,
            body: new URLSearchParams({ user: 'admin', password }).toString(),
        });
        await wait(450);
    }
    await get('/panel', '192.0.2.77', HYDRA);

    announce('Simulación terminada. Pulsa «Ver informe» para ver el análisis completo.');
}
