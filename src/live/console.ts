import type { AlertChange } from './monitor.ts';
import type { Severity } from '../types.ts';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string, text: string) => (useColor ? `\x1b[${code}m${text}\x1b[0m` : text);
const STYLE: Record<Severity, string> = { critical: '1;37;41', high: '1;31', medium: '33', low: '36' };

/** Línea de terminal para una alerta nueva o que ha subido de gravedad. */
export function formatAlert(change: AlertChange): string {
    const f = change.finding;
    const when = f.lastSeen.toISOString().slice(11, 19);
    const tag = change.kind === 'escalated' ? paint('1', ' ↑ sube de gravedad') : '';
    return `${paint('2', when)} ${paint(STYLE[f.severity], ` ${f.severity.toUpperCase()} `)} ${paint('1', f.title)}${tag}\n         ${f.description}`;
}
