// Demo web de LogSentinel. Todo ocurre en el navegador del visitante:
// - la tienda ficticia (lab/shop-core.ts) responde a cada petición y escribe su línea de log;
// - el motor de LogSentinel (el mismo código que la versión de terminal) analiza esas líneas;
// - el panel muestra el resultado.
// No hay servidor y no se envía nada a ningún sitio.
import { createDashboard } from './dashboard-ui.js';
import { createMonitor } from './engine/src/live/monitor.js';
import { renderHtml } from './engine/src/reporters/html.js';
import { GUIDANCE } from './engine/src/guidance.js';
import { accessLogLine, handleShopRequest } from './engine/lab/shop-core.js';
import { runAttackScenario } from './engine/lab/attacks.js';

const VISITOR_IP = '192.0.2.1';
const VISITOR_UA = navigator.userAgent;
const SOURCE = 'access.log de la tienda';

const monitor = createMonitor({ type: 'web', source: SOURCE });
let simulating = false;

const dashboard = createDashboard({
    onSimulate: simulate,
    openShopPath: (path) => {
        navigate(path);
        document.getElementById('shop-title').scrollIntoView({ behavior: 'smooth', block: 'start' });
    },
    onReport: openReport,
});

/** Una petición a la tienda: respuesta + línea de log + análisis. */
function request(req) {
    const response = handleShopRequest(req, { inlineCss: true });
    const update = monitor.ingest([accessLogLine(req, response)]);
    dashboard.handle({ type: 'update', ...update });
    return response;
}

/* ---------- Navegador de la tienda ---------- */

const frame = document.getElementById('shop-frame');
const address = document.getElementById('address');
const back = document.getElementById('back');
const history = [];
let currentPath = '/';

/** Convierte lo que se escribe en la barra en una ruta, codificada como lo haría un navegador. */
function toPath(input) {
    let value = input.trim().replace(/^https?:\/\//i, '').replace(/^cafeter[ií]a\.nebula/i, '');
    if (!value.startsWith('/')) value = `/${value}`;
    const url = new URL(value, 'http://cafeteria.nebula');
    return url.pathname + url.search;
}

function navigate(path, method = 'GET', body, { remember = true } = {}) {
    const target = toPath(path);
    const response = request({ method, url: target, ip: VISITOR_IP, userAgent: VISITOR_UA, referrer: '-', body });

    if (response.location) {
        navigate(response.location, 'GET', undefined, { remember });
        return;
    }
    if (remember && currentPath !== target) history.push(currentPath);
    currentPath = target;
    back.disabled = history.length === 0;
    // Se muestra decodificada, como en la barra de un navegador; si alguien escribe
    // una secuencia % inválida, se deja tal cual en lugar de romper la página.
    try {
        address.value = decodeURIComponent(target);
    } catch {
        address.value = target;
    }
    frame.srcdoc = response.body;
}

/**
 * El iframe está aislado (sandbox sin scripts), así que sus enlaces y formularios no
 * funcionan solos: la página los intercepta y los convierte en peticiones a la tienda.
 */
frame.addEventListener('load', () => {
    const doc = frame.contentDocument;
    if (!doc) return;

    doc.addEventListener('click', (event) => {
        const link = event.target.closest('a[href]');
        if (link) {
            event.preventDefault();
            const href = link.getAttribute('href');
            if (href.startsWith('/')) navigate(href);
            return;
        }
        const button = event.target.closest('button');
        const form = button?.closest('form');
        if (form) {
            event.preventDefault();
            submit(form);
        }
    });

    doc.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter') return;
        const form = event.target.closest?.('form');
        if (form && event.target.tagName === 'INPUT') {
            event.preventDefault();
            submit(form);
        }
    });
});

function submit(form) {
    const action = form.getAttribute('action') || currentPath.split('?')[0];
    const data = new URLSearchParams();
    for (const input of form.querySelectorAll('input[name]')) data.append(input.name, input.value);
    if ((form.getAttribute('method') || 'get').toLowerCase() === 'post') navigate(action, 'POST', data.toString());
    else navigate(`${action}?${data}`);
}

document.getElementById('address-form').addEventListener('submit', (event) => {
    event.preventDefault();
    navigate(address.value);
});

back.addEventListener('click', () => {
    const previous = history.pop();
    if (previous) navigate(previous, 'GET', undefined, { remember: false });
});

/* ---------- Simulación ---------- */

async function simulate() {
    if (simulating) return;
    simulating = true;
    dashboard.handle({ type: 'simulation', state: 'running' });
    try {
        await runAttackScenario(
            async (req) => {
                request({ method: req.method, url: req.path, ip: req.ip, userAgent: req.userAgent, body: req.body });
            },
            (text) => dashboard.handle({ type: 'phase', text }),
        );
    } finally {
        simulating = false;
        dashboard.handle({ type: 'simulation', state: 'done' });
        document.getElementById('restart').hidden = false;
    }
}

// Volver a empezar con la tienda y el log limpios (útil para repetir la demo o grabarla).
document.getElementById('restart').addEventListener('click', () => location.reload());

/* ---------- Informe ---------- */

function openReport() {
    const html = renderHtml(monitor.report());
    const url = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
    window.open(url, '_blank', 'noopener');
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

/* ---------- Aviso inicial (solo la primera visita) ---------- */

function showNotice() {
    const notice = document.getElementById('notice');
    let seen = false;
    try {
        seen = localStorage.getItem('ls-demo-notice') === 'ok';
    } catch {}
    if (seen || !notice.showModal) return;
    document.getElementById('notice-ok').addEventListener('click', () => notice.close());
    notice.addEventListener('close', () => {
        try {
            localStorage.setItem('ls-demo-notice', 'ok');
        } catch {}
    });
    notice.showModal();
}

/* ---------- Arranque ---------- */

dashboard.handle({
    type: 'snapshot',
    source: SOURCE,
    shopUrl: 'demo',
    canSimulate: true,
    guidance: GUIDANCE,
    simulating: false,
    phase: '',
    lines: [],
    findings: [],
    events: 0,
});
dashboard.setLive(true, 'En tu navegador');
navigate('/', 'GET', undefined, { remember: false });
showNotice();
