/**
 * Servidor web de la tienda ficticia para el laboratorio. Escribe un access log en
 * formato combined, igual que nginx. Solo escucha en 127.0.0.1.
 * La lógica de las páginas está en shop-core.ts (la comparte con la demo web).
 */
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { appendFileSync } from 'node:fs';
import { accessLogLine, handleShopRequest } from './shop-core.ts';

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

function readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', (chunk) => {
            if (body.length < 10_000) body += chunk;
        });
        req.on('end', () => resolve(body));
    });
}

export function startShop(port: number, logPath: string) {
    const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
        const request = {
            method: req.method ?? 'GET',
            url: req.url ?? '/',
            ip: clientIp(req),
            userAgent: req.headers['user-agent'] ?? '-',
            referrer: req.headers.referer,
            body: req.method === 'POST' ? await readBody(req) : undefined,
        };
        const result = handleShopRequest(request);
        const body = Buffer.from(result.body, 'utf8');

        res.writeHead(result.status, {
            'content-type': `${result.type}; charset=utf-8`,
            'content-length': body.length,
            'x-content-type-options': 'nosniff',
            'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'self'",
            ...(result.location ? { location: result.location } : {}),
        });
        res.end(body);
        appendFileSync(logPath, accessLogLine(request, result) + '\n');
    });

    server.listen(port, '127.0.0.1');
    return server;
}
