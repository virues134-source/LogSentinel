import type { AlertChange } from './monitor.ts';
import type { Severity } from '../types.ts';
import { formatClock } from '../time.ts';
import { GUIDANCE } from '../guidance.ts';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string, text: string) => (useColor ? `\x1b[${code}m${text}\x1b[0m` : text);
const STYLE: Record<Severity, string> = { critical: '1;37;41', high: '1;31', medium: '33', low: '36' };

/** Línea de terminal para una alerta nueva o que ha subido de gravedad. */
export function formatAlert(change: AlertChange): string {
    const f = change.finding;
    const when = formatClock(f.lastSeen);
    const tag = change.kind === 'escalated' ? paint('1', ' ↑ sube de gravedad') : '';
    const action = GUIDANCE[f.rule]?.actions[0];
    const next = action ? `\n         ${paint('1', 'Qué hacer:')} ${action}` : '';
    return `${paint('2', when)} ${paint(STYLE[f.severity], ` ${f.severity.toUpperCase()} `)} ${paint('1', f.title)}${tag}\n         ${f.description}${next}`;
}
