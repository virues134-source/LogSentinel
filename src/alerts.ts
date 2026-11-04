import { accessSync, constants, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Report } from './analyzer.ts';
import type { Finding } from './types.ts';
import { withGuidance } from './guidance.ts';
import type { FindingWithGuidance } from './guidance.ts';

export interface WebhookPayload {
    tool: 'logsentinel';
    generatedAt: string;
    totals: Report['totals'];
    topIps: Report['topIps'];
    findings: FindingWithGuidance[];
}

/** Cabecera y clave con las que se autentica el envío (Header Auth en n8n). */
export interface WebhookAuth {
    header: string;
    key: string;
}

const MAX_SENT = 5000;
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
const HEADER_VALUE = /^[\x21-\x7e]+$/;

/**
 * Envía los hallazgos a un webhook (por ejemplo, un nodo Webhook de n8n, que luego puede
 * reenviarlos a Telegram, correo o Slack). Solo se aceptan URLs http(s), y la clave nunca
 * viaja sin cifrar fuera del propio equipo ni se reenvía tras una redirección.
 */
export async function sendWebhook(url: string, report: Report, findings: Finding[], auth?: WebhookAuth): Promise<void> {
    if (!URL.canParse(url)) throw new Error('La URL del webhook no es válida.');
    const target = new URL(url);
    if (target.protocol !== 'https:' && target.protocol !== 'http:') {
        throw new Error(`Protocolo no permitido en el webhook: ${target.protocol}`);
    }
    // Estos errores no incluyen la URL ni la clave: la salida de cron puede acabar en un correo
    if (target.username || target.password) {
        throw new Error('La URL del webhook no debe llevar usuario ni contraseña: usa LOGSENTINEL_WEBHOOK_KEY.');
    }
    if (auth && target.protocol === 'http:' && !LOOPBACK.has(target.hostname)) {
        throw new Error('La clave del webhook viajaría sin cifrar: usa una URL https.');
    }
    if (auth && !HEADER_VALUE.test(auth.key)) {
        throw new Error('LOGSENTINEL_WEBHOOK_KEY tiene caracteres no válidos: usa solo letras, números y símbolos ASCII, sin espacios.');
    }

    const payload: WebhookPayload = {
        tool: 'logsentinel',
        generatedAt: report.generatedAt.toISOString(),
        totals: report.totals,
        topIps: report.topIps.slice(0, 10),
        findings: findings.map(withGuidance),
    };

    let response: Response;
    try {
        response = await fetch(target, {
            method: 'POST',
            headers: { 'content-type': 'application/json', ...(auth && { [auth.header]: auth.key }) },
            body: JSON.stringify(payload),
            redirect: 'manual',
            signal: AbortSignal.timeout(10_000),
        });
    } catch (error) {
        const err = error as Error & { cause?: { code?: string } };
        if (err.name === 'TimeoutError') throw new Error('El webhook no ha respondido en 10 segundos.');
        throw new Error(`No se pudo conectar con el webhook (${err.cause?.code ?? err.name}).`);
    }

    if (response.status === 401 || response.status === 403) {
        throw new Error(`El webhook rechazó el envío (${response.status}). Revisa la clave en LOGSENTINEL_WEBHOOK_KEY y el nombre de la cabecera.`);
    }
    if (!response.ok) {
        throw new Error(`El webhook respondió ${response.status} ${response.statusText}`);
    }
}

/** Identifica un hallazgo entre ejecuciones; si sube de gravedad, cuenta como nuevo. */
function fingerprint(f: Finding): string {
    return [f.rule, f.ip ?? '', f.user ?? '', f.firstSeen.toISOString(), f.severity].join('|');
}

function readSent(statePath: string): string[] {
    if (!existsSync(statePath)) return [];
    let sent: unknown;
    try {
        sent = JSON.parse(readFileSync(statePath, 'utf8'));
    } catch {
        throw new Error(`El fichero de estado no es válido: ${statePath}`);
    }
    if (!Array.isArray(sent)) throw new Error(`El fichero de estado no es válido: ${statePath}`);
    return sent as string[];
}

/**
 * Deja solo los hallazgos que aún no se han avisado, para que cron no repita alertas.
 * Comprueba antes de enviar que el estado se podrá guardar: si no, cada ejecución repetiría el aviso.
 */
export function filterUnsent(findings: Finding[], statePath: string): Finding[] {
    mkdirSync(dirname(statePath), { recursive: true });
    if (existsSync(statePath)) accessSync(statePath, constants.W_OK);
    else writeFileSync(statePath, '[]', 'utf8');
    const sent = new Set(readSent(statePath));
    return findings.filter((f) => !sent.has(fingerprint(f)));
}

/** Guarda lo avisado. Se llama solo si el envío ha ido bien, para reintentarlo si falla. */
export function markSent(findings: Finding[], statePath: string): void {
    const sent = [...readSent(statePath), ...findings.map(fingerprint)].slice(-MAX_SENT);
    // Se escribe aparte y se renombra para no dejar el fichero a medias si algo se interrumpe
    const temporary = `${statePath}.tmp`;
    writeFileSync(temporary, JSON.stringify(sent), 'utf8');
    renameSync(temporary, statePath);
}
