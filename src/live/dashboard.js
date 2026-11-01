// Panel en directo de LogSentinel. Todo el texto que viene del log se pinta con
// textContent, nunca con innerHTML: las líneas de log las escribe el atacante.

const $ = (id) => document.getElementById(id);
const LABEL = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' };
const MAX_ROWS = 300;

const feed = $('feed');
const alerts = $('alerts');
const alertIps = new Set();
let shownAlerts = new Map();

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function time(iso) {
    return iso ? iso.slice(11, 19) : '';
}

function statusClass(status) {
    return status ? `s${String(status)[0]}` : '';
}

function addLines(lines, animate) {
    if (!lines.length) return;
    const empty = feed.querySelector('.empty');
    if (empty) empty.remove();

    const stick = feed.scrollTop < 8;
    for (const line of lines) {
        const row = el('div', 'row');
        if (animate) row.classList.add('new');
        if (line.ip && alertIps.has(line.ip)) row.classList.add('hot');
        row.dataset.ip = line.ip || '';
        if (line.method) {
            row.append(
                el('span', 't', time(line.time)),
                el('span', '', line.ip),
                el('span', 'path', `${line.method} ${line.path}`),
                el('span', statusClass(line.status), String(line.status)),
            );
        } else {
            const text = el('span', 'path', line.raw);
            text.style.gridColumn = '1 / -1';
            row.append(text);
        }
        feed.prepend(row);
    }
    while (feed.children.length > MAX_ROWS) feed.lastChild.remove();
    if (stick) feed.scrollTop = 0;
}

function renderAlert(finding, kind) {
    const card = el('article', 'alert');
    card.dataset.sev = finding.severity;
    const head = el('div', 'head');
    const pill = el('span', 'pill', LABEL[finding.severity]);
    pill.dataset.sev = finding.severity;
    head.append(pill, el('h3', '', finding.title));
    if (kind === 'escalated') head.append(el('span', 'tag', 'Ha subido de gravedad'));
    const where = [finding.ip, finding.user ? `usuario ${finding.user}` : ''].filter(Boolean).join(' · ');
    card.append(
        head,
        el('p', '', finding.description),
        el('div', 'meta', `${time(finding.lastSeen)} · ${where} · ${finding.mitre.map((m) => m.id).join(', ')}`),
    );
    return card;
}

const keyOf = (f) => `${f.rule}|${f.ip || ''}|${f.user || ''}`;

function showChanges(changes) {
    if (!changes.length) return;
    const empty = alerts.querySelector('.empty');
    if (empty) empty.remove();

    for (const { kind, finding } of changes) {
        const key = keyOf(finding);
        const old = shownAlerts.get(key);
        if (old) old.remove();
        const card = renderAlert(finding, kind);
        shownAlerts.set(key, card);
        alerts.prepend(card);
        if (finding.ip) markIp(finding.ip);
    }
}

function markIp(ip) {
    if (alertIps.has(ip)) return;
    alertIps.add(ip);
    for (const row of feed.querySelectorAll('.row')) {
        if (row.dataset.ip === ip) row.classList.add('hot');
    }
}

function updateCounts(findings, events) {
    $('c-events').textContent = events.toLocaleString('es-ES');
    $('c-alerts').textContent = findings.length;
    for (const sev of ['critical', 'high', 'medium']) {
        $(`c-${sev}`).textContent = findings.filter((f) => f.severity === sev).length;
    }
    // Actualiza en sitio las tarjetas existentes (el recuento de eventos crece)
    const current = new Set();
    for (const f of findings) {
        current.add(keyOf(f));
        const card = shownAlerts.get(keyOf(f));
        if (card) card.querySelector('p').textContent = f.description;
    }
    // Una alerta que ya no existe es porque se ha convertido en otra más grave
    // (p. ej. "fuerza bruta" → "acceso tras múltiples fallos").
    for (const [key, card] of shownAlerts) {
        if (current.has(key) || card.classList.contains('superseded')) continue;
        card.classList.add('superseded');
        card.querySelector('.head').append(el('span', 'tag muted', 'Superada por una alerta más grave'));
    }
}

function setPhase(text) {
    $('phase-text').textContent = text;
    $('phase').classList.toggle('show', Boolean(text));
}

function setSimulating(running) {
    const button = $('simulate');
    button.disabled = running;
    button.textContent = running ? 'Simulación en curso…' : 'Simular ataque';
    $('phase').classList.toggle('done', !running);
}

function setupTryIt(shopUrl) {
    if (!shopUrl) return;
    const examples = [
        ['Inyección SQL', "/productos?id=1' OR '1'='1"],
        ['XSS en el buscador', '/buscar?q=<script>alert(1)</script>'],
        ['Leer ficheros del sistema', '/descargas?file=../../../etc/passwd'],
        ['Buscar el fichero de contraseñas', '/.env'],
    ];
    const list = $('tryit-list');
    for (const [label, path] of examples) {
        const li = el('li');
        const link = el('a', '', path);
        link.href = shopUrl + path;
        link.target = '_blank';
        link.rel = 'noopener';
        li.append(`${label}: `, link);
        list.append(li);
    }
    $('tryit').hidden = false;
}

function connect() {
    const source = new EventSource('/events');

    source.onopen = () => {
        $('dot').classList.remove('off');
    };

    source.onmessage = (message) => {
        const data = JSON.parse(message.data);

        if (data.type === 'snapshot') {
            $('status').textContent = `Vigilando ${data.source}`;
            if (data.shopUrl) {
                $('shop').href = data.shopUrl;
                $('shop').hidden = false;
                setupTryIt(data.shopUrl);
            }
            $('simulate').hidden = !data.canSimulate;
            feed.replaceChildren();
            alerts.replaceChildren();
            shownAlerts = new Map();
            alertIps.clear();
            data.findings.forEach((f) => f.ip && alertIps.add(f.ip));
            addLines(data.lines, false);
            showChanges([...data.findings].reverse().map((finding) => ({ kind: 'new', finding })));
            if (!data.lines.length) feed.append(el('div', 'empty', 'Esperando tráfico. Abre la tienda o pulsa «Simular ataque».'));
            if (!data.findings.length) alerts.append(el('div', 'empty', 'Sin alertas todavía.'));
            updateCounts(data.findings, data.events);
            setSimulating(data.simulating);
            setPhase(data.phase);
        } else if (data.type === 'update') {
            addLines(data.lines, true);
            showChanges(data.changes);
            updateCounts(data.findings, data.events);
        } else if (data.type === 'phase') {
            setPhase(data.text);
        } else if (data.type === 'simulation') {
            setSimulating(data.state === 'running');
        }
    };

    source.onerror = () => {
        $('dot').classList.add('off');
        $('status').textContent = 'Conexión perdida, reintentando…';
    };
}

$('simulate').addEventListener('click', async () => {
    setSimulating(true);
    const response = await fetch('/simulate', { method: 'POST' });
    if (!response.ok && response.status !== 409) setSimulating(false);
});

connect();
