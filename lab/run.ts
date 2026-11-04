/**
 * Laboratorio de LogSentinel: levanta la tienda ficticia, vigila su log en directo
 * y abre un panel web donde se ven el tráfico y las alertas en tiempo real.
 *
 *   npm run lab
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { startShop } from './shop.ts';
import { httpTransport, runAttackScenario } from './attacks.ts';
import { createMonitor } from '../src/live/monitor.ts';
import { startDashboard } from '../src/live/dashboard.ts';
import { tailFile } from '../src/live/tail.ts';
import { formatAlert } from '../src/live/console.ts';

const SHOP_PORT = Number(process.env.SHOP_PORT ?? 8080);
const PANEL_PORT = Number(process.env.PANEL_PORT ?? 8090);
const logDir = fileURLToPath(new URL('./logs/', import.meta.url));
const logPath = `${logDir}access.log`;

// Cada sesión del laboratorio empieza con un log limpio.
mkdirSync(logDir, { recursive: true });
writeFileSync(logPath, '');

const shopUrl = `http://127.0.0.1:${SHOP_PORT}`;
const shop = startShop(SHOP_PORT, logPath);
const monitor = createMonitor({ type: 'web', source: 'lab/logs/access.log' });
const dashboard = startDashboard({
    port: PANEL_PORT,
    source: 'lab/logs/access.log',
    report: monitor.report,
    shopUrl,
    onSimulate: () => runAttackScenario(httpTransport(shopUrl), (text) => {
        dashboard.setPhase(text);
        console.log(`\n» ${text}`);
    }),
});

const stopTail = tailFile(logPath, (lines) => {
    const update = monitor.ingest(lines);
    dashboard.push(update);
    for (const change of update.changes) console.log(formatAlert(change));
});

for (const server of [shop, dashboard.server]) {
    server.on('error', (error: NodeJS.ErrnoException & { port?: number }) => {
        console.error(error.code === 'EADDRINUSE'
            ? `El puerto ${error.port} ya está en uso. Cierra el otro programa o usa SHOP_PORT / PANEL_PORT.`
            : error.message);
        process.exit(1);
    });
}

console.log(`
LogSentinel · laboratorio en marcha

  Panel en directo   http://127.0.0.1:${PANEL_PORT}
  Tienda ficticia    ${shopUrl}
  Log que se vigila  lab/logs/access.log

Abre el panel, pulsa «Simular ataque» o ataca la tienda tú mismo.
Las alertas también aparecerán aquí. Ctrl+C para salir.
`);

process.on('SIGINT', () => {
    stopTail();
    dashboard.close();
    shop.close();
    process.exit(0);
});
