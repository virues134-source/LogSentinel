import type { Report } from './analyzer.ts';
import type { Finding } from './types.ts';

export interface WebhookPayload {
    tool: 'logsentinel';
    generatedAt: string;
    totals: Report['totals'];
    topIps: Report['topIps'];
    findings: Finding[];
}

/**
 * Envía los hallazgos a un webhook (por ejemplo, un nodo Webhook de n8n, que luego puede
 * reenviarlos a Telegram, correo o Slack). Solo se aceptan URLs http(s).
 */
export async function sendWebhook(url: string, report: Report, findings: Finding[]): Promise<void> {
    const target = new URL(url);
    if (target.protocol !== 'https:' && target.protocol !== 'http:') {
        throw new Error(`Protocolo no permitido en el webhook: ${target.protocol}`);
    }

    const payload: WebhookPayload = {
        tool: 'logsentinel',
        generatedAt: report.generatedAt.toISOString(),
        totals: report.totals,
        topIps: report.topIps.slice(0, 10),
        findings,
    };

    const response = await fetch(target, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
        throw new Error(`El webhook respondió ${response.status} ${response.statusText}`);
    }
}
