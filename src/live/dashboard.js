// Panel en directo de LogSentinel. Todo el texto que viene del log se pinta con
// textContent, nunca con innerHTML: las líneas de log las escribe el atacante.

const $ = (id) => document.getElementById(id);
const LABEL = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' };
const ORDER = { low: 1, medium: 2, high: 3, critical: 4 };
const MAX_ROWS = 400;
const WINDOW_MS = 5 * 60_000;

const tape = $('tape');
const panelAlerts = $('panel-alerts');
const alertIps = new Set();
const lineTimes = [];
let stories = new Map();
let guidance = {};
let latestFindings = [];

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

// Hora local del navegador (el log puede venir en otra zona horaria).
const clockFormat = new Intl.DateTimeFormat('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
const time = (iso) => (iso ? clockFormat.format(new Date(iso)) : '');
const keyOf = (f) => `${f.rule}|${f.ip || ''}|${f.user || ''}`;

/* ---------- Cinta de actividad ---------- */

function addLines(lines, fresh) {
    if (!lines.length) return;
    $('tape-empty').hidden = true;
    const wrap = $('tape-wrap');
    const atTop = wrap.scrollTop < 8;

    for (const line of lines) {
        lineTimes.push(Date.now());
        const tr = document.createElement('tr');
        tr.dataset.ip = line.ip || '';
        if (fresh) tr.classList.add('fresh');
        if (line.ip && alertIps.has(line.ip)) tr.classList.add('hot');

        const flag = el('td', 'flag');
        flag.append(el('i'));
        if (line.method) {
            const req = el('td', 'req');
            req.append(el('span', 'method', line.method), line.path);
            req.title = `${line.method} ${line.path}`;
            tr.append(flag, el('td', '', time(line.time)), el('td', '', line.ip), req,
                el('td', `status st-${String(line.status)[0]}`, String(line.status)));
        } else {
            const raw = el('td', 'raw', line.raw);
            raw.colSpan = 4;
            tr.append(flag, raw);
        }
        tape.prepend(tr);
    }
    while (tape.children.length > MAX_ROWS) tape.lastChild.remove();
    if (atTop) wrap.scrollTop = 0;
}

function markIp(ip) {
    if (!ip || alertIps.has(ip)) return;
    alertIps.add(ip);
    for (const tr of tape.querySelectorAll('tr')) {
        if (tr.dataset.ip === ip) tr.classList.add('hot');
    }
}

/* ---------- Alertas como noticias ---------- */

function renderStory(finding, kind) {
    const story = el('article', 'story');
    story.dataset.sev = finding.severity;

    const meta = el('div', 'story-meta');
    const sev = el('span', 'sev', LABEL[finding.severity]);
    sev.dataset.sev = finding.severity;
    meta.append(sev, el('span', '', time(finding.lastSeen)));
    if (kind === 'escalated') meta.append(el('span', 'stamp up', 'Sube de gravedad'));

    story.append(meta, el('h3', '', finding.title), el('p', 'standfirst', finding.description));
    const guide = guidance[finding.rule];
    if (guide) story.append(el('p', 'meaning', guide.meaning));
    const where = [finding.ip, finding.user ? `usuario ${finding.user}` : '', finding.mitre.map((m) => m.id).join(' · ')].filter(Boolean);
    story.append(el('p', 'source', where.join('   ')));
    return story;
}

function showChanges(changes) {
    if (!changes.length) return;
    $('alerts-empty').hidden = true;
    for (const { kind, finding } of changes) {
        const key = keyOf(finding);
        stories.get(key)?.remove();
        const story = renderStory(finding, kind);
        stories.set(key, story);
        panelAlerts.prepend(story);
        markIp(finding.ip);
    }
}

/** Una alerta que deja de existir se ha convertido en otra más grave: se queda, sellada. */
function stampSuperseded(findings) {
    const current = new Set(findings.map(keyOf));
    for (const [key, story] of stories) {
        if (current.has(key) || story.classList.contains('superseded')) continue;
        story.classList.add('superseded');
        story.querySelector('.story-meta').append(el('span', 'stamp', 'Superada'));
    }
    for (const f of findings) {
        const story = stories.get(keyOf(f));
        if (story) story.querySelector('.standfirst').textContent = f.description;
    }
}

/* ---------- IPs ---------- */

function renderIps(findings) {
    const byIp = new Map();
    const weight = { low: 1, medium: 3, high: 7, critical: 10 };
    for (const f of findings) {
        if (!f.ip) continue;
        const entry = byIp.get(f.ip) || { ip: f.ip, score: 0, worst: 'low', rules: new Set() };
        entry.score += weight[f.severity];
        if (ORDER[f.severity] > ORDER[entry.worst]) entry.worst = f.severity;
        entry.rules.add(f.title);
        byIp.set(f.ip, entry);
    }
    const rows = [...byIp.values()].sort((a, b) => b.score - a.score);
    const body = $('ips');
    body.replaceChildren(...rows.map((r) => {
        const tr = document.createElement('tr');
        const ip = el('td');
        ip.append(el('code', '', r.ip));
        const sev = el('td');
        const tag = el('span', 'sev', LABEL[r.worst]);
        tag.dataset.sev = r.worst;
        sev.append(tag);
        tr.append(ip, sev, el('td', 'num', String(r.score)), el('td', 'rules', [...r.rules].join(' · ')));
        return tr;
    }));
    $('ips-empty').hidden = rows.length > 0;
    $('n-ips').textContent = rows.length;
}

/* ---------- Índices ---------- */

function updateIndices(findings, events) {
    latestFindings = findings;
    $('c-events').textContent = events.toLocaleString('es-ES');
    $('c-alerts').textContent = findings.length;
    $('n-alerts').textContent = findings.length;
    for (const sev of ['critical', 'high', 'medium']) {
        $(`c-${sev}`).textContent = findings.filter((f) => f.severity === sev).length;
    }
    refreshDeltas();
}

function refreshDeltas() {
    const since = Date.now() - WINDOW_MS;
    while (lineTimes.length && lineTimes[0] < since) lineTimes.shift();
    const recentAlerts = latestFindings.filter((f) => new Date(f.firstSeen).getTime() >= since).length;
    setDelta('d-events', lineTimes.length, false);
    setDelta('d-alerts', recentAlerts, true);
}

function setDelta(id, value, alarming) {
    const node = $(id);
    node.textContent = value ? `+${value.toLocaleString('es-ES')} en 5 min` : '';
    node.classList.toggle('up', alarming && value > 0);
}

/* ---------- Simulación y estado ---------- */

function setPhase(text) {
    $('breaking-text').textContent = text;
    $('breaking').classList.toggle('show', Boolean(text));
}

function setSimulating(running) {
    const button = $('simulate');
    button.disabled = running;
    button.textContent = running ? 'Simulación en curso…' : 'Simular ataque';
    $('breaking').classList.toggle('done', !running);
    $('breaking-kicker').textContent = running ? 'Simulación' : 'Terminado';
}

function setLive(on, text) {
    $('live').classList.toggle('off', !on);
    $('live-text').textContent = text;
}

function setupTryIt(shopUrl) {
    const examples = [
        ['Inyección SQL en un producto', "/productos?id=1' OR '1'='1"],
        ['Código en el buscador (XSS)', '/buscar?q=<script>alert(1)</script>'],
        ['Leer ficheros del sistema', '/descargas?file=../../../etc/passwd'],
        ['Buscar el fichero de contraseñas', '/.env'],
    ];
    $('tryit-list').replaceChildren(...examples.map(([label, path]) => {
        const li = el('li');
        const link = el('a', '', path);
        link.href = shopUrl + path;
        link.target = '_blank';
        link.rel = 'noopener';
        li.append(el('span', '', label), link);
        return li;
    }));
    $('tryit').hidden = false;
}

/* ---------- Pestañas ---------- */

for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => {
        for (const other of document.querySelectorAll('.tab')) {
            const selected = other === tab;
            other.setAttribute('aria-selected', String(selected));
            $(other.getAttribute('aria-controls')).hidden = !selected;
        }
    });
}

/* ---------- Explicación: se recuerda si el usuario la cerró ---------- */

try {
    if (localStorage.getItem('ls-explainer') === 'closed') $('explainer').open = false;
    $('explainer').addEventListener('toggle', () => {
        try { localStorage.setItem('ls-explainer', $('explainer').open ? 'open' : 'closed'); } catch {}
    });
} catch {}

/* ---------- Reloj ---------- */

const fullClock = new Intl.DateTimeFormat('es-ES', { weekday: 'long', day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
function tick() {
    $('clock').textContent = fullClock.format(new Date());
    refreshDeltas();
}
tick();
setInterval(tick, 1000);

/* ---------- Conexión en directo ---------- */

function connect() {
    const source = new EventSource('/events');
    source.onopen = () => setLive(true, 'En directo');
    source.onerror = () => setLive(false, 'Reconectando');

    source.onmessage = (message) => {
        const data = JSON.parse(message.data);

        if (data.type === 'snapshot') {
            guidance = data.guidance || {};
            $('source').textContent = `Vigilando ${data.source}`;
            if (data.shopUrl) {
                $('shop').href = data.shopUrl;
                $('shop').hidden = false;
                setupTryIt(data.shopUrl);
            }
            $('simulate').hidden = !data.canSimulate;

            tape.replaceChildren();
            for (const story of stories.values()) story.remove();
            stories = new Map();
            alertIps.clear();
            data.findings.forEach((f) => f.ip && alertIps.add(f.ip));
            $('tape-empty').hidden = data.lines.length > 0;
            $('alerts-empty').hidden = data.findings.length > 0;

            addLines(data.lines, false);
            showChanges([...data.findings].reverse().map((finding) => ({ kind: 'new', finding })));
            updateIndices(data.findings, data.events);
            renderIps(data.findings);
            setSimulating(data.simulating);
            setPhase(data.phase);
        } else if (data.type === 'update') {
            addLines(data.lines, true);
            showChanges(data.changes);
            stampSuperseded(data.findings);
            updateIndices(data.findings, data.events);
            renderIps(data.findings);
        } else if (data.type === 'phase') {
            setPhase(data.text);
        } else if (data.type === 'simulation') {
            setSimulating(data.state === 'running');
        }
    };
}

$('simulate').addEventListener('click', async () => {
    setSimulating(true);
    const response = await fetch('/simulate', { method: 'POST' });
    if (!response.ok && response.status !== 409) setSimulating(false);
});

connect();
