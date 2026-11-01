import { createServer } from 'node:http';
import type { ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { renderHtml } from '../reporters/html.ts';
import type { Report } from '../analyzer.ts';
import type { Finding } from '../types.ts';
import type { LiveLine, MonitorUpdate } from './monitor.ts';
import { GUIDANCE } from '../guidance.ts';

// Se leen en cada petición (son ficheros pequeños): así un cambio en el diseño
// se ve recargando la página, sin reiniciar el servidor.
const asset = (name: string) => readFileSync(fileURLToPath(new URL(`./${name}`, import.meta.url)), 'utf8');

const SECURITY_HEADERS = {
    'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
};

export interface DashboardOptions {
    port: number;
    source: string;
    report: () => Report;
    shopUrl?: string;
    onSimulate?: () => Promise<void>;
}

/**
 * Panel web en directo. El navegador se suscribe a /events (Server-Sent Events) y recibe
 * cada línea nueva del log y cada alerta en cuanto el monitor la detecta.
 * Solo escucha en 127.0.0.1: no es accesible desde otros equipos.
 */
export function startDashboard(options: DashboardOptions) {
    const clients = new Set<ServerResponse>();
    const recentLines: LiveLine[] = [];
    let findings: Finding[] = [];
    let events = 0;
    let phase = '';
    let simulating = false;

    const send = (res: ServerResponse, data: unknown) => res.write(`data: ${JSON.stringify(data)}\n\n`);
    const broadcast = (data: unknown) => {
        for (const res of clients) send(res, data);
    };

    const server = createServer((req, res) => {
        const url = new URL(req.url ?? '/', 'http://127.0.0.1');

        if (req.method === 'GET' && url.pathname === '/') {
            res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', ...SECURITY_HEADERS });
            res.end(asset('dashboard.html'));
            return;
        }
        if (req.method === 'GET' && url.pathname === '/dashboard.js') {
            res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8', ...SECURITY_HEADERS });
            res.end(asset('dashboard.js'));
            return;
        }
        if (req.method === 'GET' && url.pathname === '/events') {
            res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
            clients.add(res);
            send(res, {
                type: 'snapshot',
                source: options.source,
                shopUrl: options.shopUrl ?? null,
                canSimulate: Boolean(options.onSimulate),
                guidance: GUIDANCE,
                simulating,
                phase,
                lines: recentLines,
                findings,
                events,
            });
            req.on('close', () => clients.delete(res));
            return;
        }
        if (req.method === 'GET' && url.pathname === '/report') {
            res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
            res.end(renderHtml(options.report()));
            return;
        }
        if (req.method === 'POST' && url.pathname === '/simulate') {
            // Solo se acepta desde el propio panel: otra web abierta en el navegador
            // no puede lanzar la simulación (protección CSRF básica).
            const origin = req.headers.origin;
            if (origin && origin !== `http://127.0.0.1:${options.port}` && origin !== `http://localhost:${options.port}`) {
                res.writeHead(403).end();
                return;
            }
            if (!options.onSimulate || simulating) {
                res.writeHead(409).end();
                return;
            }
            simulating = true;
            broadcast({ type: 'simulation', state: 'running' });
            options.onSimulate()
                .catch((error) => setPhase(`La simulación falló: ${(error as Error).message}`))
                .finally(() => {
                    simulating = false;
                    broadcast({ type: 'simulation', state: 'done' });
                });
            res.writeHead(202).end();
            return;
        }
        res.writeHead(404).end();
    });

    // Mantiene viva la conexión SSE a través de proxies y antivirus que cortan conexiones inactivas.
    const keepAlive = setInterval(() => {
        for (const res of clients) res.write(': ping\n\n');
    }, 15_000);

    server.listen(options.port, '127.0.0.1');

    function push(update: MonitorUpdate) {
        findings = update.findings;
        events = update.events;
        recentLines.push(...update.lines);
        if (recentLines.length > 300) recentLines.splice(0, recentLines.length - 300);
        broadcast({ type: 'update', ...update });
    }

    function setPhase(text: string) {
        phase = text;
        broadcast({ type: 'phase', text });
    }

    function close() {
        clearInterval(keepAlive);
        for (const res of clients) res.end();
        server.close();
    }

    return { push, setPhase, close, server };
}
