// Interfaz del panel de LogSentinel. La usan el laboratorio (con datos que llegan del
// servidor) y la demo web (con datos generados en el propio navegador).
// Todo el texto que viene del log se pinta con textContent, nunca con innerHTML:
// las líneas de log las escribe el atacante.

const LABEL = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' };
const ORDER = { low: 1, medium: 2, high: 3, critical: 4 };
const WEIGHT = { low: 1, medium: 3, high: 7, critical: 10 };
const THREAT = {
    none: { level: 'Sin incidencias', why: 'El tráfico es normal. No hay alertas activas.' },
    low: { level: 'Bajo', why: 'Solo hay hallazgos menores.' },
    medium: { level: 'Moderado', why: 'Alguien está explorando la web en busca de puntos débiles.' },
    high: { level: 'Alto', why: 'Hay ataques activos contra la tienda.' },
    critical: { level: 'Crítico', why: 'Hay indicios de que un ataque ha tenido éxito. Revisa las alertas en rojo.' },
};
const MAX_ROWS = 400;
const WINDOW_MS = 5 * 60_000;

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

// Hora local del navegador (el log puede venir en otra zona horaria).
const clockFormat = new Intl.DateTimeFormat('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
const fullClock = new Intl.DateTimeFormat('es-ES', { weekday: 'long', day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
const time = (iso) => (iso ? clockFormat.format(new Date(iso)) : '');
const keyOf = (f) => `${f.rule}|${f.ip || ''}|${f.user || ''}`;

/**
 * @param {object} options
 * @param {() => Promise<void>} [options.onSimulate]  lanza la simulación (tras confirmar)
 * @param {(path: string) => void} [options.openShopPath]  abre una ruta de la tienda (demo web)
 * @param {() => void} [options.onReport]  abre el informe (demo web); si no, enlace /report
 */
export function createDashboard(options = {}) {
    const tape = $('tape');
    const panelAlerts = $('panel-alerts');
    const alertIps = new Set();
    const lineTimes = [];
    const baseTitle = document.title;
    let stories = new Map();
    let guidance = {};
    let latestFindings = [];
    let lastLevel = 'none';

    /* ---------- Actividad ---------- */

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

    /* ---------- Alertas ---------- */

    function renderStory(finding, kind, animate) {
        const story = el('article', 'story');
        story.dataset.sev = finding.severity;
        if (animate && finding.severity === 'critical') story.classList.add('alarm');

        const meta = el('div', 'story-meta');
        const sev = el('span', 'sev', LABEL[finding.severity]);
        sev.dataset.sev = finding.severity;
        meta.append(sev, el('span', '', time(finding.lastSeen)));
        if (kind === 'escalated') meta.append(el('span', 'stamp up', 'Sube de gravedad'));

        story.append(meta, el('h3', '', finding.title), el('p', 'standfirst', finding.description));
        const guide = guidance[finding.rule];
        if (guide) {
            const todo = el('ul', 'todo');
            todo.append(...guide.actions.map((action) => el('li', '', action)));
            story.append(el('p', 'meaning', guide.meaning), el('h4', 'todo-title', 'Qué hacer'), todo);
        }
        const where = [finding.ip, finding.user ? `usuario ${finding.user}` : '', finding.mitre.map((m) => m.id).join(' · ')].filter(Boolean);
        story.append(el('p', 'source', where.join('   ')));
        return story;
    }

    function showChanges(changes, animate) {
        if (!changes.length) return;
        $('alerts-empty').hidden = true;
        for (const { kind, finding } of changes) {
            const key = keyOf(finding);
            stories.get(key)?.remove();
            const story = renderStory(finding, kind, animate);
            stories.set(key, story);
            panelAlerts.prepend(story);
            markIp(finding.ip);
        }
        // Si llega algo grave y estás mirando las IPs, vuelve a las alertas.
        if (animate && changes.some((c) => ORDER[c.finding.severity] >= ORDER.high)) selectTab('tab-alerts');
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
        for (const f of findings) {
            if (!f.ip) continue;
            const entry = byIp.get(f.ip) || { ip: f.ip, score: 0, worst: 'low', rules: new Set() };
            entry.score += WEIGHT[f.severity];
            if (ORDER[f.severity] > ORDER[entry.worst]) entry.worst = f.severity;
            entry.rules.add(f.title);
            byIp.set(f.ip, entry);
        }
        const rows = [...byIp.values()].sort((a, b) => b.score - a.score);
        $('ips').replaceChildren(...rows.map((r) => {
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

    /* ---------- Nivel de amenaza ---------- */

    function updateThreat(findings) {
        const level = findings.reduce((acc, f) => (acc === 'none' || ORDER[f.severity] > ORDER[acc] ? f.severity : acc), 'none');
        const threat = $('threat');
        threat.dataset.level = level;
        $('threat-level').textContent = THREAT[level].level;
        $('threat-why').textContent = THREAT[level].why;
        const filled = level === 'none' ? 0 : ORDER[level];
        threat.querySelectorAll('.meter i').forEach((bar, i) => bar.classList.toggle('on', i < filled));
        if (level !== lastLevel && level !== 'none' && ORDER[level] > (ORDER[lastLevel] ?? 0)) {
            threat.classList.remove('flash');
            void threat.offsetWidth;
            threat.classList.add('flash');
        }
        lastLevel = level;

        // La pestaña del navegador avisa aunque estés mirando otra.
        const critical = findings.filter((f) => f.severity === 'critical').length;
        const high = findings.filter((f) => f.severity === 'high').length;
        document.title = critical ? `(${critical} crítica${critical > 1 ? 's' : ''}) ${baseTitle}`
            : high ? `(${high} alta${high > 1 ? 's' : ''}) ${baseTitle}` : baseTitle;
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
        updateThreat(findings);
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

    /* ---------- Simulación ---------- */

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

    const confirmDialog = $('confirm');
    $('simulate').addEventListener('click', () => {
        if (confirmDialog?.showModal) confirmDialog.showModal();
        else startSimulation();
    });
    $('confirm-cancel')?.addEventListener('click', () => confirmDialog.close());
    $('confirm-start')?.addEventListener('click', () => {
        confirmDialog.close();
        startSimulation();
    });

    async function startSimulation() {
        if (!options.onSimulate) return;
        setSimulating(true);
        // Durante la simulación lo importante es la acción: se pliega la explicación
        // y la página baja hasta las alertas.
        $('explainer').open = false;
        document.querySelector('.columns, .demo-grid')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        try {
            await options.onSimulate();
        } catch {
            setSimulating(false);
        }
    }

    /* ---------- Pruébalo tú ---------- */

    function setupTryIt(shopUrl) {
        const examples = [
            ['Inyección SQL en un producto', "/productos?id=1' OR '1'='1"],
            ['Código en el buscador (XSS)', '/buscar?q=<script>alert(1)</script>'],
            ['Leer ficheros del sistema', '/descargas?file=../../../etc/passwd'],
            ['Buscar el fichero de contraseñas', '/.env'],
        ];
        $('tryit-list').replaceChildren(...examples.map(([label, path]) => {
            const li = el('li');
            if (options.openShopPath) {
                const button = el('button', 'link', path);
                button.type = 'button';
                button.addEventListener('click', () => options.openShopPath(path));
                li.append(el('span', '', label), button);
            } else {
                const link = el('a', '', path);
                link.href = shopUrl + path;
                link.target = '_blank';
                link.rel = 'noopener';
                li.append(el('span', '', label), link);
            }
            return li;
        }));
        $('tryit').hidden = false;
    }

    /* ---------- Pestañas ---------- */

    function selectTab(id) {
        for (const tab of document.querySelectorAll('.tab')) {
            const selected = tab.id === id;
            tab.setAttribute('aria-selected', String(selected));
            $(tab.getAttribute('aria-controls')).hidden = !selected;
        }
    }
    for (const tab of document.querySelectorAll('.tab')) tab.addEventListener('click', () => selectTab(tab.id));

    /* ---------- Explicación: se recuerda si el usuario la cerró ---------- */

    try {
        if (localStorage.getItem('ls-explainer') === 'closed') $('explainer').open = false;
        $('explainer').addEventListener('toggle', () => {
            try { localStorage.setItem('ls-explainer', $('explainer').open ? 'open' : 'closed'); } catch {}
        });
    } catch {}

    /* ---------- Informe ---------- */

    if (options.onReport) {
        $('report').addEventListener('click', (event) => {
            event.preventDefault();
            options.onReport();
        });
    }

    /* ---------- Reloj ---------- */

    function tick() {
        $('clock').textContent = fullClock.format(new Date());
        refreshDeltas();
    }
    tick();
    setInterval(tick, 1000);

    /* ---------- Mensajes (mismo formato que el servidor por Server-Sent Events) ---------- */

    function handle(data) {
        if (data.type === 'snapshot') {
            guidance = data.guidance || {};
            $('source').textContent = data.source ? `Vigilando ${data.source}` : '';
            if (data.shopUrl) {
                const shop = $('shop');
                if (shop) {
                    shop.href = data.shopUrl;
                    shop.hidden = false;
                }
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
            showChanges([...data.findings].reverse().map((finding) => ({ kind: 'new', finding })), false);
            updateIndices(data.findings, data.events);
            renderIps(data.findings);
            setSimulating(data.simulating);
            setPhase(data.phase);
        } else if (data.type === 'update') {
            addLines(data.lines, true);
            showChanges(data.changes, true);
            stampSuperseded(data.findings);
            updateIndices(data.findings, data.events);
            renderIps(data.findings);
        } else if (data.type === 'phase') {
            setPhase(data.text);
        } else if (data.type === 'simulation') {
            setSimulating(data.state === 'running');
        }
    }

    function setLive(on, text) {
        $('live').classList.toggle('off', !on);
        $('live-text').textContent = text;
    }

    return { handle, setLive };
}
