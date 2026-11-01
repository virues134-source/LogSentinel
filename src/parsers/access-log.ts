import type { ParseResult, WebEvent } from '../types.ts';

const MONTHS: Record<string, string> = {
    Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06',
    Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12',
};

// Formato "combined" de nginx y Apache:
// 203.0.113.7 - - [28/Oct/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"
const COMBINED =
    /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)(?: [^"]*)?" (\d{3}) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?/;

const CLF_DATE = /^(\d{2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/;

function parseClfDate(value: string): Date | null {
    const m = value.match(CLF_DATE);
    if (!m || !MONTHS[m[2]]) return null;
    const iso = `${m[3]}-${MONTHS[m[2]]}-${m[1]}T${m[4]}:${m[5]}:${m[6]}${m[7]}${m[8]}:${m[9]}`;
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? null : date;
}

export function parseAccessLine(raw: string, line: number, source: string): WebEvent | null {
    const m = raw.match(COMBINED);
    if (!m) return null;

    const timestamp = parseClfDate(m[2]);
    if (!timestamp) return null;

    return {
        kind: 'web',
        timestamp,
        ip: m[1],
        method: m[3],
        path: m[4],
        status: Number(m[5]),
        bytes: m[6] === '-' ? 0 : Number(m[6]),
        referrer: m[7] ?? '-',
        userAgent: m[8] ?? '-',
        source,
        line,
        raw,
    };
}

export function parseAccessLog(content: string, source: string): ParseResult {
    const events: WebEvent[] = [];
    let skipped = 0;

    content.split(/\r?\n/).forEach((raw, index) => {
        if (!raw.trim()) return;
        const event = parseAccessLine(raw, index + 1, source);
        if (event) events.push(event);
        else skipped++;
    });

    return { events, skipped };
}

export function looksLikeAccessLog(sample: string): boolean {
    return COMBINED.test(sample);
}
