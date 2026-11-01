/**
 * Lógica de la tienda ficticia "Cafetería Nébula", sin dependencias de Node.
 * La usan el servidor del laboratorio (lab/shop.ts) y la demo web, que la ejecuta
 * dentro del navegador. Así las dos generan exactamente las mismas respuestas y logs.
 */

export interface ShopRequest {
    method: string;
    /** Ruta con query string, tal como llega en la petición: /productos?id=1 */
    url: string;
    ip: string;
    userAgent: string;
    referrer?: string;
    body?: string;
}

export interface ShopResponse {
    status: number;
    body: string;
    type: string;
    location?: string;
}

export const SHOP_NAME = 'Cafetería Nébula';

const PRODUCTS = [
    { id: 1, origin: 'Etiopía', name: 'Yirgacheffe', price: '14,90 €', notes: 'Floral, bergamota y té negro.', region: 'Gedeo', altitude: '1.950 m', process: 'Lavado', roast: 'Claro', color: '#c9a227' },
    { id: 2, origin: 'Colombia', name: 'Huila', price: '12,50 €', notes: 'Caramelo, manzana roja y cacao.', region: 'Pitalito', altitude: '1.700 m', process: 'Lavado', roast: 'Medio', color: '#b5502b' },
    { id: 3, origin: 'Kenia', name: 'Nyeri', price: '16,20 €', notes: 'Grosella negra, pomelo y vino.', region: 'Mathira', altitude: '1.800 m', process: 'Lavado', roast: 'Claro', color: '#7d2a4a' },
    { id: 4, origin: 'Brasil', name: 'Cerrado', price: '10,90 €', notes: 'Chocolate con leche y avellana.', region: 'Minas Gerais', altitude: '1.100 m', process: 'Natural', roast: 'Medio', color: '#3f6b4e' },
    { id: 5, origin: 'Guatemala', name: 'Antigua', price: '13,40 €', notes: 'Especias, cacao y naranja.', region: 'Sacatepéquez', altitude: '1.550 m', process: 'Lavado', roast: 'Medio', color: '#2f5873' },
];
type Product = (typeof PRODUCTS)[number];

// Credenciales de la cuenta de empleados de la tienda ficticia (solo para el laboratorio).
const ADMIN = { user: 'admin', password: 'nebula2026' };

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = (n: number) => String(n).padStart(2, '0');

export function escapeHtml(value: string): string {
    return value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** Fecha en formato de nginx con la hora local y su desfase, p. ej. 01/Nov/2026:21:58:03 +0100. */
export function clfDate(date: Date): string {
    const offset = -date.getTimezoneOffset();
    const zone = `${offset >= 0 ? '+' : '-'}${pad(Math.floor(Math.abs(offset) / 60))}${pad(Math.abs(offset) % 60)}`;
    return `${pad(date.getDate())}/${MONTHS[date.getMonth()]}/${date.getFullYear()}:${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())} ${zone}`;
}

/** Línea de access log en formato combined, igual que la escribiría nginx. */
export function accessLogLine(req: ShopRequest, res: ShopResponse, date = new Date()): string {
    const bytes = new TextEncoder().encode(res.body).length;
    const url = req.url.replace(/"/g, '%22').replace(/\s/g, '%20');
    const ua = req.userAgent.replace(/"/g, '\\"');
    return `${req.ip} - - [${clfDate(date)}] "${req.method} ${url} HTTP/1.1" ${res.status} ${bytes} "${req.referrer ?? '-'}" "${ua}"`;
}

/** Ilustración de la bolsa de café, dibujada en SVG (sin imágenes externas). */
function bagIllustration(p: Product): string {
    return `<svg class="bag-art" viewBox="0 0 200 220" role="img" aria-label="Bolsa de café ${p.origin} ${p.name}">
  <rect x="0" y="0" width="200" height="220" fill="${p.color}" opacity=".12"/>
  <path d="M58 44 L142 44 L150 196 Q100 206 50 196 Z" fill="${p.color}"/>
  <path d="M58 44 L142 44 L144 60 L56 60 Z" fill="#000" opacity=".18"/>
  <path d="M62 30 L138 30 L142 44 L58 44 Z" fill="${p.color}"/>
  <path d="M62 30 L138 30 L139 34 L61 34 Z" fill="#fff" opacity=".25"/>
  <rect x="62" y="86" width="76" height="78" fill="#f7f4ee"/>
  <text x="100" y="104" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" font-size="8" font-weight="800" letter-spacing="1.5" fill="${p.color}">${p.origin.toUpperCase()}</text>
  <text x="100" y="124" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" font-size="${p.name.length > 9 ? 10.5 : 12}" font-weight="800" fill="#1d1a17">${p.name}</text>
  <line x1="76" y1="134" x2="124" y2="134" stroke="#1d1a17" stroke-width=".6"/>
  <text x="100" y="148" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" font-size="7" fill="#5d5650">NÉBULA · 250 g</text>
  <circle cx="100" cy="72" r="6" fill="none" stroke="#f7f4ee" stroke-width="1.6"/>
  <circle cx="100" cy="72" r="2" fill="#f7f4ee"/>
</svg>`;
}

function bagLabel(p: Product): string {
    return `<article class="bag">
  <a class="bag-media" href="/productos?id=${p.id}" tabindex="-1" aria-hidden="true">${bagIllustration(p)}</a>
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

export const SHOP_CSS = `:root{--stone:#f1efe9;--ink:#1d1a17;--ink2:#5d5650;--rule:#d9d3c9;--cherry:#9e2a1f;--leaf:#2f4b3b}
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
.shelf{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:20px}
.bag{background:#fff;border:1px solid var(--rule);padding:0 20px 20px;display:flex;flex-direction:column;gap:8px}
.bag-media{display:block;margin:0 -20px 8px}
.bag-art{display:block;width:100%;height:auto}
.origin{font-size:12px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;color:var(--cherry)}
.bag h3{font-size:26px;line-height:1.05;letter-spacing:-.03em;font-weight:800}
.notes{color:var(--ink2);font-size:15px}
.bag dl{display:grid;grid-template-columns:1fr 1fr;column-gap:16px;border-top:1px solid var(--rule);margin-top:4px}
.bag dl div{padding:7px 0;border-bottom:1px solid var(--rule)}
.bag dt{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--ink2)}
.bag dd{font-size:14px;font-weight:600}
.buy{display:flex;align-items:baseline;gap:8px;margin-top:auto;padding-top:8px}
.buy b{font-size:20px}.buy span{font-size:13px;color:var(--ink2)}
.buy a{margin-left:auto;font-weight:700;font-size:14px;text-decoration:none;border-bottom:2px solid var(--cherry)}
.detail{display:grid;grid-template-columns:1fr 1fr;gap:48px;align-items:start}
.detail .lead{margin-top:18px}
form{display:flex;flex-direction:column;gap:10px;max-width:380px;margin-top:28px}
label{font-size:13px;font-weight:700;margin-top:6px}
input{font:inherit;padding:12px 14px;border:1px solid var(--rule);background:#fff;color:var(--ink)}
input:focus{outline:2px solid var(--leaf);outline-offset:1px}
button{font:700 15px/1 inherit;padding:14px 18px;margin-top:8px;background:var(--ink);color:#fff;border:0;cursor:pointer;transition:background-color .15s ease}
button:hover{background:var(--cherry)}
.search{flex-direction:row;max-width:560px}.search input{flex:1}.search button{margin-top:0}
.results{margin:28px 0 20px;color:var(--ink2)}
.hint{margin-top:16px;font-size:13px;color:var(--ink2)}
.error{color:var(--cherry);font-weight:600}
.figures{display:flex;gap:48px;margin-top:24px}.figures b{display:block;font-size:40px;letter-spacing:-.03em}
.message{max-width:46ch}.message p{margin-top:12px;color:var(--ink2)}.message a{font-weight:700}
footer{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:20px 32px;border-top:1px solid var(--rule);font-size:13px;color:var(--ink2)}
@media (max-width:760px){.hero,.detail{grid-template-columns:1fr}h1{font-size:38px}main{padding:32px 20px 56px}.top,.lab-note,footer{padding-left:20px;padding-right:20px}}`;

/**
 * Página completa. Con inlineCss la hoja de estilos va dentro (para la demo web, que
 * pinta la tienda en un iframe sin servidor); si no, se enlaza /css/main.css.
 */
function page(title: string, body: string, inlineCss: boolean): string {
    const css = inlineCss ? `<style>${SHOP_CSS}</style>` : '<link rel="stylesheet" href="/css/main.css">';
    return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} · ${SHOP_NAME}</title>${css}</head>
<body>
<p class="lab-note"><b>Laboratorio de LogSentinel.</b> ${SHOP_NAME} es una tienda ficticia: cada visita queda registrada en su log y LogSentinel la analiza en directo.</p>
<header class="top">
  <a href="/" class="logo">${SHOP_NAME}<span>Café de especialidad</span></a>
  <nav><a href="/">Cafés</a><a href="/buscar">Buscar</a><a href="/login">Empleados</a></nav>
</header>
<main>${body}</main>
<footer><span>${SHOP_NAME} · Empresa ficticia del laboratorio de LogSentinel</span><span>Tostamos los martes y los viernes</span></footer>
</body></html>`;
}

/** Atiende una petición a la tienda. No toca disco ni red: solo calcula la respuesta. */
export function handleShopRequest(req: ShopRequest, options: { inlineCss?: boolean } = {}): ShopResponse {
    const inline = options.inlineCss ?? false;
    const html = (status: number, title: string, body: string): ShopResponse => ({ status, body: page(title, body, inline), type: 'text/html' });
    const message = (status: number, title: string, text: string) =>
        html(status, title, `<div class="message"><h1>${title}</h1><p>${text}</p><p><a href="/">Volver a la tienda</a></p></div>`);

    const url = new URL(req.url, 'http://tienda.local');
    const path = url.pathname;
    const method = req.method.toUpperCase();

    if (method === 'GET' && path === '/') {
        return html(200, 'Inicio', `<section class="hero"><h1>Café de especialidad, tostado esta semana.</h1><p class="lead">Cinco orígenes elegidos lote a lote. Tostamos en pequeñas cantidades y enviamos en 48 horas.</p></section>
<div class="shelf">${PRODUCTS.map(bagLabel).join('')}</div>`);
    }

    if (method === 'GET' && path === '/css/main.css') {
        return { status: 200, body: SHOP_CSS, type: 'text/css' };
    }

    if (method === 'GET' && path === '/productos') {
        // Fallo típico de una web mal programada: parseInt("1' OR '1'='1") devuelve 1,
        // así que el ataque obtiene un 200. LogSentinel lo marcará como posible éxito.
        const id = Number.parseInt(url.searchParams.get('id') ?? '', 10);
        const product = PRODUCTS.find((p) => p.id === id);
        if (Number.isNaN(id)) return message(500, 'Error interno', 'No se pudo completar la consulta.');
        if (!product) return message(404, 'Café no encontrado', 'Ese café no está en el catálogo.');
        return html(200, `${product.origin} ${product.name}`, `<div class="detail"><div><p class="origin">${product.origin}</p><h1>${product.name}</h1><p class="lead">${product.notes} Bolsa de 250 g, en grano o molido.</p></div>${bagLabel(product)}</div>`);
    }

    if (method === 'GET' && path === '/buscar') {
        const q = url.searchParams.get('q') ?? '';
        const term = q.toLowerCase();
        const results = PRODUCTS.filter((p) => term && `${p.origin} ${p.name} ${p.notes}`.toLowerCase().includes(term));
        return html(200, 'Buscar', `<h1>Buscar</h1>
<form class="search" action="/buscar"><input name="q" value="${escapeHtml(q)}" placeholder="Etiopía, cacao, floral…" aria-label="Buscar café"><button>Buscar</button></form>
${q ? `<p class="results">${results.length} resultado(s) para «${escapeHtml(q)}»</p>` : '<p class="hint">Prueba con un origen o una nota de cata.</p>'}
${results.length ? `<div class="shelf">${results.map(bagLabel).join('')}</div>` : ''}`);
    }

    // Descargas: la tienda no lee ficheros de verdad. La ruta existe porque es un
    // objetivo típico de path traversal y así se ve cómo responde.
    if (method === 'GET' && path === '/descargas') {
        const file = url.searchParams.get('file') ?? '';
        if (file.includes('..') || file.includes('/') || file.includes('\\')) return message(403, 'Acceso denegado', 'No tienes permiso para descargar ese fichero.');
        return message(404, 'Documento no disponible', 'Las descargas no están disponibles en esta tienda de demostración.');
    }

    if (path === '/login') {
        const form = (status: number, error = '') => html(status, 'Acceso empleados', `<h1>Acceso empleados</h1>
<form method="post" action="/login">${error}<label for="user">Usuario</label><input id="user" name="user" autocomplete="username"><label for="password">Contraseña</label><input id="password" name="password" type="password" autocomplete="current-password"><button>Entrar</button></form>`);
        if (method === 'GET') return form(200);
        if (method === 'POST') {
            const params = new URLSearchParams(req.body ?? '');
            if (params.get('user') === ADMIN.user && params.get('password') === ADMIN.password) {
                return { status: 302, body: '', type: 'text/html', location: '/panel' };
            }
            return form(401, '<p class="error">Usuario o contraseña incorrectos.</p>');
        }
    }

    if (method === 'GET' && path === '/panel') {
        return html(200, 'Panel', '<h1>Panel de empleados</h1><div class="figures"><p><b>23</b>pedidos hoy</p><p><b>412,60 €</b>ingresos</p></div><p class="lead" style="margin-top:24px">Datos de ejemplo del laboratorio.</p>');
    }

    return message(404, 'Página no encontrada', 'La dirección que buscas no existe.');
}
