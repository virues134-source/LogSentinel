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
    { id: 1, origin: 'Etiopía', name: 'Yirgacheffe', price: '14,90 €', notes: 'Floral, bergamota y té negro.', region: 'Gedeo', altitude: '1.950 m', process: 'Lavado', roast: 'Claro' },
    { id: 2, origin: 'Colombia', name: 'Huila', price: '12,50 €', notes: 'Caramelo, manzana roja y cacao.', region: 'Pitalito', altitude: '1.700 m', process: 'Lavado', roast: 'Medio' },
    { id: 3, origin: 'Kenia', name: 'Nyeri', price: '16,20 €', notes: 'Grosella negra, pomelo y vino.', region: 'Mathira', altitude: '1.800 m', process: 'Lavado', roast: 'Claro' },
    { id: 4, origin: 'Brasil', name: 'Cerrado', price: '10,90 €', notes: 'Chocolate con leche y avellana.', region: 'Minas Gerais', altitude: '1.100 m', process: 'Natural', roast: 'Medio' },
    { id: 5, origin: 'Guatemala', name: 'Antigua', price: '13,40 €', notes: 'Especias, cacao y naranja.', region: 'Sacatepéquez', altitude: '1.550 m', process: 'Lavado', roast: 'Medio' },
];
type Product = (typeof PRODUCTS)[number];

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
<body>
<p class="lab-note"><b>Laboratorio de LogSentinel.</b> Café Aurora es una tienda ficticia: cada visita queda registrada en su log y LogSentinel la analiza en directo.</p>
<header class="top">
  <a href="/" class="logo">Café Aurora<span>Tostadores</span></a>
  <nav><a href="/">Cafés</a><a href="/buscar">Buscar</a><a href="/descargas?file=catalogo-2026.pdf">Catálogo</a><a href="/login">Empleados</a></nav>
</header>
<main>${body}</main>
<footer><span>Café Aurora · Empresa ficticia del laboratorio de LogSentinel</span><span>Tostamos los martes y los viernes</span></footer>
</body></html>`;
}

/** Ficha de producto con el formato de la etiqueta de una bolsa de café. */
function bagLabel(p: Product): string {
    return `<article class="bag">
  <p class="origin">${p.origin}</p>
  <h3>${p.name}</h3>
  <p class="notes">${p.notes}</p>
  <dl>
    <div><dt>Región</dt><dd>${p.region}</dd></div>
    <div><dt>Altitud</dt><dd>${p.altitude}</dd></div>
    <div><dt>Proceso</dt><dd>${p.process}</dd></div>
    <div><dt>Tueste</dt><dd>${p.roast}</dd></div>
  </dl>
  <p class="buy"><b>${p.price}</b><span>250 g</span><a href="/productos?id=${p.id}">Ver café</a></p>
</article>`;
}

const CSS = `:root{--stone:#f1efe9;--ink:#1d1a17;--ink2:#5d5650;--rule:#d9d3c9;--cherry:#9e2a1f;--leaf:#2f4b3b}
*{box-sizing:border-box}
body{margin:0;background:var(--stone);color:var(--ink);font:16px/1.55 "Segoe UI",-apple-system,"Helvetica Neue",Arial,sans-serif;font-variant-numeric:tabular-nums}
a{color:inherit}h1,h2,h3,p,dl,dd{margin:0}
::selection{background:var(--cherry);color:#fff}
.lab-note{background:var(--leaf);color:#dfe8e1;font-size:13px;padding:9px 32px}
.lab-note b{color:#fff}
.top{display:flex;justify-content:space-between;align-items:center;gap:24px;flex-wrap:wrap;padding:22px 32px;border-bottom:1.5px solid var(--ink)}
.logo{text-decoration:none;font-weight:800;font-size:24px;letter-spacing:-.03em;display:flex;align-items:baseline;gap:12px}
.logo span{font-weight:700;font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--ink2)}
nav{display:flex;gap:24px;font-size:15px;font-weight:600}
nav a{text-decoration:none;transition:color .15s ease}
nav a:hover{color:var(--cherry)}
main{max-width:1120px;margin:0 auto;padding:48px 32px 72px}
.hero{display:grid;grid-template-columns:1.25fr 1fr;gap:40px;align-items:end;padding-bottom:36px;margin-bottom:36px;border-bottom:1px solid var(--rule)}
h1{font-size:54px;line-height:1;letter-spacing:-.04em;font-weight:800;max-width:13ch}
.lead{font-size:17px;color:var(--ink2);max-width:42ch}
.shelf{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:20px}
.bag{background:#fff;border:1px solid var(--rule);padding:22px;display:flex;flex-direction:column;gap:10px}
.origin{font-size:12px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;color:var(--cherry)}
.bag h3{font-size:28px;line-height:1.05;letter-spacing:-.03em;font-weight:800}
.notes{color:var(--ink2);font-size:15px}
.bag dl{display:grid;grid-template-columns:1fr 1fr;column-gap:16px;border-top:1px solid var(--rule);margin-top:4px}
.bag dl div{padding:8px 0;border-bottom:1px solid var(--rule)}
.bag dt{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--ink2)}
.bag dd{font-size:14px;font-weight:600}
.buy{display:flex;align-items:baseline;gap:8px;margin-top:auto;padding-top:8px}
.buy b{font-size:20px}.buy span{font-size:13px;color:var(--ink2)}
.buy a{margin-left:auto;font-weight:700;font-size:14px;text-decoration:none;border-bottom:2px solid var(--cherry)}
.detail{display:grid;grid-template-columns:1fr 1fr;gap:48px;align-items:start}
.detail .lead{margin-top:18px}
.detail .bag{border-top:6px solid var(--cherry)}
form{display:flex;flex-direction:column;gap:10px;max-width:380px;margin-top:28px}
label{font-size:13px;font-weight:700;margin-top:6px}
input{font:inherit;padding:12px 14px;border:1px solid var(--rule);background:#fff;color:var(--ink)}
input:focus{outline:2px solid var(--leaf);outline-offset:1px}
button{font:700 15px/1 inherit;padding:14px 18px;margin-top:8px;background:var(--ink);color:#fff;border:0;cursor:pointer;transition:background-color .15s ease}
button:hover{background:var(--cherry)}
.search{flex-direction:row;max-width:560px}.search input{flex:1}.search button{margin-top:0}
.results{margin:28px 0 20px;color:var(--ink2)}
.error{color:var(--cherry);font-weight:600}
.figures{display:flex;gap:48px;margin-top:24px}.figures b{display:block;font-size:40px;letter-spacing:-.03em}
.message{max-width:46ch}.message p{margin-top:12px;color:var(--ink2)}.message a{font-weight:700}
footer{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:20px 32px;border-top:1px solid var(--rule);font-size:13px;color:var(--ink2)}
@media (max-width:760px){.hero,.detail{grid-template-columns:1fr}h1{font-size:38px}main{padding:32px 20px 56px}.top,.lab-note,footer{padding-left:20px;padding-right:20px}}`;

const message = (title: string, text: string) =>
    page(title, `<div class="message"><h1>${title}</h1><p>${text}</p><p><a href="/">Volver a la tienda</a></p></div>`);

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
        return {
            status: 200,
            body: page('Inicio', `<section class="hero"><h1>Café de especialidad, tostado esta semana.</h1><p class="lead">Cinco orígenes elegidos lote a lote. Tostamos en pequeñas cantidades y enviamos en 48 horas.</p></section>
<div class="shelf">${PRODUCTS.map(bagLabel).join('')}</div>`),
        };
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
        if (Number.isNaN(id)) return { status: 500, body: message('Error interno', 'No se pudo completar la consulta.') };
        if (!product) return { status: 404, body: message('Café no encontrado', 'Ese café no está en el catálogo.') };
        return {
            status: 200,
            body: page(`${product.origin} ${product.name}`, `<div class="detail"><div><p class="origin">${product.origin}</p><h1>${product.name}</h1><p class="lead">${product.notes} Bolsa de 250 g, en grano o molido.</p></div>${bagLabel(product)}</div>`),
        };
    }

    if (req.method === 'GET' && path === '/buscar') {
        const q = url.searchParams.get('q') ?? '';
        const term = q.toLowerCase();
        const results = PRODUCTS.filter((p) => term && `${p.origin} ${p.name} ${p.notes}`.toLowerCase().includes(term));
        return {
            status: 200,
            body: page('Buscar', `<h1>Buscar</h1>
<form class="search"><input name="q" value="${escape(q)}" placeholder="Etiopía, cacao, floral…" aria-label="Buscar café"><button>Buscar</button></form>
${q ? `<p class="results">${results.length} resultado(s) para «${escape(q)}»</p>` : ''}
${results.length ? `<div class="shelf">${results.map(bagLabel).join('')}</div>` : ''}`),
        };
    }

    if (req.method === 'GET' && path === '/descargas') {
        const file = url.searchParams.get('file') ?? '';
        if (DOWNLOADS.has(file)) return { status: 200, body: `%PDF-1.4 (documento de ejemplo: ${file})`, type: 'application/pdf' };
        if (file.includes('..') || file.includes('/')) return { status: 403, body: message('Acceso denegado', 'No tienes permiso para descargar ese fichero.') };
        return { status: 404, body: message('Fichero no encontrado', 'Ese documento no existe.') };
    }

    if (path === '/login') {
        const form = (error = '') => page('Acceso empleados', `<h1>Acceso empleados</h1>
<form method="post">${error}<label for="user">Usuario</label><input id="user" name="user" autocomplete="username"><label for="password">Contraseña</label><input id="password" name="password" type="password" autocomplete="current-password"><button>Entrar</button></form>`);
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
        return {
            status: 200,
            body: page('Panel', '<h1>Panel de administración</h1><div class="figures"><p><b>23</b>pedidos hoy</p><p><b>412,60 €</b>ingresos</p></div><p class="lead" style="margin-top:24px">Datos de ejemplo del laboratorio.</p>'),
        };
    }

    return { status: 404, body: message('Página no encontrada', 'La dirección que buscas no existe.') };
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
