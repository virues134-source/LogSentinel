/**
 * "Café Aurora": tienda online ficticia para el laboratorio.
 * Es un servidor web real que escribe un access log en formato combined, igual que nginx.
 * Solo escucha en 127.0.0.1.
 */
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { appendFileSync } from 'node:fs';

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = (n: number) => String(n).padStart(2, '0');

const PRODUCTS = [
    { id: 1, name: 'Etiopía Yirgacheffe', price: '14,90 €', notes: 'Floral, bergamota y té negro.' },
    { id: 2, name: 'Colombia Huila', price: '12,50 €', notes: 'Caramelo, manzana roja y cacao.' },
    { id: 3, name: 'Kenia Nyeri', price: '16,20 €', notes: 'Grosella negra, pomelo y vino.' },
    { id: 4, name: 'Brasil Cerrado', price: '10,90 €', notes: 'Chocolate con leche y avellana.' },
    { id: 5, name: 'Guatemala Antigua', price: '13,40 €', notes: 'Especias, cacao y naranja.' },
];

// Credenciales de la cuenta de administración de la tienda ficticia (solo para el laboratorio).
const ADMIN = { user: 'admin', password: 'aurora2026' };
const DOWNLOADS = new Set(['catalogo-2026.pdf', 'tarifas-hosteleria.pdf']);

/** Fecha en formato de nginx con la hora local y su desfase, p. ej. 01/Nov/2026:21:58:03 +0100. */
function clfDate(date: Date): string {
    const offset = -date.getTimezoneOffset();
    const zone = `${offset >= 0 ? '+' : '-'}${pad(Math.floor(Math.abs(offset) / 60))}${pad(Math.abs(offset) % 60)}`;
    return `${pad(date.getDate())}/${MONTHS[date.getMonth()]}/${date.getFullYear()}:${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())} ${zone}`;
}

function escape(value: string): string {
    return value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/**
 * IP del cliente. Si llega la cabecera X-Forwarded-For (como cuando hay un proxy o un
 * balanceador delante) se usa esa; el simulador la envía para representar atacantes
 * distintos aunque todo salga de tu propio ordenador.
 */
function clientIp(req: IncomingMessage): string {
    const forwarded = req.headers['x-forwarded-for'];
    const first = (Array.isArray(forwarded) ? forwarded[0] : forwarded)?.split(',')[0].trim();
    if (first && /^[0-9a-fA-F:.]+$/.test(first)) return first;
    return (req.socket.remoteAddress ?? '-').replace(/^::ffff:/, '');
}

function page(title: string, body: string): string {
    return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} · Café Aurora</title><link rel="stylesheet" href="/css/main.css"></head>
<body><header><a href="/" class="logo">Café Aurora</a><nav><a href="/">Cafés</a><a href="/buscar">Buscar</a><a href="/descargas?file=catalogo-2026.pdf">Catálogo</a><a href="/login">Acceso empleados</a></nav></header>
<main>${body}</main><footer>Café Aurora es una empresa ficticia creada para el laboratorio de LogSentinel.</footer></body></html>`;
}

const CSS = `body{margin:0;font:16px/1.6 Georgia,serif;background:#faf6f0;color:#2b1d14}
header{display:flex;justify-content:space-between;align-items:center;padding:18px 32px;background:#2b1d14;color:#faf6f0}
header a{color:inherit;text-decoration:none;margin-left:20px}.logo{font-size:22px;font-weight:bold;margin:0}
main{max-width:860px;margin:40px auto;padding:0 24px}h1{font-size:34px;margin:0 0 16px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px}
.card{background:#fff;border:1px solid #e6dccf;padding:18px}.card a{color:#8a3b12}
form{display:flex;flex-direction:column;gap:10px;max-width:320px}input,button{font:inherit;padding:10px}
button{background:#8a3b12;color:#fff;border:0;cursor:pointer}.error{color:#a3161a}
footer{text-align:center;color:#8a7a6c;font-size:13px;padding:40px}`;

function readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', (chunk) => {
            if (body.length < 10_000) body += chunk;
        });
        req.on('end', () => resolve(body));
    });
}

async function route(req: IncomingMessage, url: URL): Promise<{ status: number; body: string; type?: string; location?: string }> {
    const path = url.pathname;

    if (req.method === 'GET' && path === '/') {
        const cards = PRODUCTS.map((p) => `<div class="card"><h3>${p.name}</h3><p>${p.notes}</p><p><b>${p.price}</b> · <a href="/productos?id=${p.id}">Ver</a></p></div>`).join('');
        return { status: 200, body: page('Inicio', `<h1>Cafés de especialidad</h1><div class="grid">${cards}</div>`) };
    }

    if (req.method === 'GET' && path === '/css/main.css') {
        return { status: 200, body: CSS, type: 'text/css' };
    }

    if (req.method === 'GET' && path === '/productos') {
        // Fallo típico de una web mal programada: parseInt("1' OR '1'='1") devuelve 1,
        // así que el ataque obtiene un 200. LogSentinel lo marcará como posible éxito.
        const raw = url.searchParams.get('id') ?? '';
        const id = Number.parseInt(raw, 10);
        const product = PRODUCTS.find((p) => p.id === id);
        if (Number.isNaN(id)) return { status: 500, body: page('Error', '<h1>Error interno</h1><p>No se pudo completar la consulta.</p>') };
        if (!product) return { status: 404, body: page('No encontrado', '<h1>Producto no encontrado</h1>') };
        return { status: 200, body: page(product.name, `<h1>${product.name}</h1><p>${product.notes}</p><p><b>${product.price}</b> / 250 g</p>`) };
    }

    if (req.method === 'GET' && path === '/buscar') {
        const q = url.searchParams.get('q') ?? '';
        const results = PRODUCTS.filter((p) => q && p.name.toLowerCase().includes(q.toLowerCase()));
        return {
            status: 200,
            body: page('Buscar', `<h1>Buscar</h1><form><input name="q" value="${escape(q)}" placeholder="Etiopía, Kenia…"><button>Buscar</button></form>
${q ? `<p>${results.length} resultado(s) para «${escape(q)}»</p>` : ''}${results.map((p) => `<p><a href="/productos?id=${p.id}">${p.name}</a></p>`).join('')}`),
        };
    }

    if (req.method === 'GET' && path === '/descargas') {
        const file = url.searchParams.get('file') ?? '';
        if (DOWNLOADS.has(file)) return { status: 200, body: `%PDF-1.4 (documento de ejemplo: ${file})`, type: 'application/pdf' };
        if (file.includes('..') || file.includes('/')) return { status: 403, body: page('Prohibido', '<h1>Acceso denegado</h1>') };
        return { status: 404, body: page('No encontrado', '<h1>Fichero no encontrado</h1>') };
    }

    if (path === '/login') {
        const form = (error = '') => page('Acceso', `<h1>Acceso empleados</h1>${error}<form method="post"><input name="user" placeholder="Usuario"><input name="password" type="password" placeholder="Contraseña"><button>Entrar</button></form>`);
        if (req.method === 'GET') return { status: 200, body: form() };
        if (req.method === 'POST') {
            const params = new URLSearchParams(await readBody(req));
            if (params.get('user') === ADMIN.user && params.get('password') === ADMIN.password) {
                return { status: 302, body: '', location: '/panel' };
            }
            return { status: 401, body: form('<p class="error">Usuario o contraseña incorrectos.</p>') };
        }
    }

    if (req.method === 'GET' && path === '/panel') {
        return { status: 200, body: page('Panel', '<h1>Panel de administración</h1><p>Pedidos de hoy: 23 · Ingresos: 412,60 €</p>') };
    }

    return { status: 404, body: page('No encontrado', '<h1>Página no encontrada</h1>') };
}

export function startShop(port: number, logPath: string) {
    const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
        const url = new URL(req.url ?? '/', 'http://127.0.0.1');
        const result = await route(req, url);
        const body = Buffer.from(result.body, 'utf8');

        res.writeHead(result.status, {
            'content-type': `${result.type ?? 'text/html'}; charset=utf-8`,
            'content-length': body.length,
            ...(result.location ? { location: result.location } : {}),
        });
        res.end(body);

        const line = `${clientIp(req)} - - [${clfDate(new Date())}] "${req.method} ${(req.url ?? '/').replace(/"/g, '%22')} HTTP/${req.httpVersion}" ${result.status} ${body.length} "${req.headers.referer ?? '-'}" "${(req.headers['user-agent'] ?? '-').replace(/"/g, '\\"')}"`;
        appendFileSync(logPath, line + '\n');
    });

    server.listen(port, '127.0.0.1');
    return server;
}
