import type { AuthEvent, ParseResult } from '../types.ts';

const MONTHS: Record<string, number> = {
    Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
    Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

// Cabecera syslog clásica ("Oct 28 03:14:07") o RFC 3339 ("2026-10-28T03:14:07.123+01:00"),
// seguida de host y programa con PID opcional.
const HEADER =
    /^(?:([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})|(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+(\S+)\s+([^\s:[]+)(?:\[\d+\])?:\s+(.*)$/;

const IP = '([0-9a-fA-F:.]+)';
const FAILED = new RegExp(`^Failed (\\S+) for (invalid user )?(\\S*) from ${IP} port \\d+`);
const ACCEPTED = new RegExp(`^Accepted (\\S+) for (\\S+) from ${IP} port \\d+`);
const INVALID = new RegExp(`^Invalid user (\\S*) from ${IP}(?: port \\d+)?`);
const SUDO = /^\s*(\S+) : .*?COMMAND=(.+)$/;

/**
 * Convierte la fecha de la cabecera a Date. El formato syslog clásico no incluye ni año
 * ni zona horaria: se usa el año indicado y la hora se toma tal cual (como UTC), para que
 * el informe muestre la misma hora que aparece en el log, se analice donde se analice.
 */
function parseTimestamp(match: RegExpMatchArray, year: number): Date | null {
    if (match[6]) {
        const date = new Date(match[6]);
        return Number.isNaN(date.getTime()) ? null : date;
    }
    const month = MONTHS[match[1]];
    if (month === undefined) return null;
    return new Date(Date.UTC(year, month, Number(match[2]), Number(match[3]), Number(match[4]), Number(match[5])));
}

export function parseAuthLine(raw: string, line: number, source: string, year: number): AuthEvent | null {
    const header = raw.match(HEADER);
    if (!header) return null;

    const timestamp = parseTimestamp(header, year);
    if (!timestamp) return null;

    const host = header[7];
    const program = header[8];
    const message = header[9];
    const base = { kind: 'auth' as const, timestamp, host, program, source, line, raw };

    if (program === 'sshd') {
        let m = message.match(FAILED);
        if (m) {
            return { ...base, action: m[2] ? 'invalid_user' : 'failed', method: m[1], user: m[3], ip: m[4] };
        }
        m = message.match(ACCEPTED);
        if (m) {
            return { ...base, action: 'accepted', method: m[1], user: m[2], ip: m[3] };
        }
        m = message.match(INVALID);
        if (m) {
            return { ...base, action: 'invalid_user', user: m[1], ip: m[2] };
        }
        return null;
    }

    if (program === 'sudo') {
        const m = message.match(SUDO);
        if (m) {
            return { ...base, action: 'sudo', user: m[1], command: m[2].trim() };
        }
    }

    return null;
}

export function parseAuthLog(content: string, source: string, year = new Date().getFullYear()): ParseResult {
    const events: AuthEvent[] = [];
    let skipped = 0;

    content.split(/\r?\n/).forEach((raw, index) => {
        if (!raw.trim()) return;
        const event = parseAuthLine(raw, index + 1, source, year);
        if (event) events.push(event);
        else skipped++;
    });

    return { events, skipped };
}

/** Indica si una línea tiene pinta de auth.log (para la detección automática de formato). */
export function looksLikeAuthLog(sample: string): boolean {
    return HEADER.test(sample);
}
