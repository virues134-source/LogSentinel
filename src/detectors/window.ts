/**
 * Busca la ventana de tiempo con más eventos (ventana deslizante sobre eventos ordenados).
 * Devuelve el índice de inicio y fin de la mejor ventana.
 */
export function densestWindow<T extends { timestamp: Date }>(
    events: T[],
    windowMinutes: number,
): { start: number; end: number; size: number } {
    const windowMs = windowMinutes * 60_000;
    let best = { start: 0, end: -1, size: 0 };
    let start = 0;

    for (let end = 0; end < events.length; end++) {
        while (events[end].timestamp.getTime() - events[start].timestamp.getTime() > windowMs) {
            start++;
        }
        const size = end - start + 1;
        if (size > best.size) best = { start, end, size };
    }

    return best;
}

/** Agrupa una lista por clave, conservando el orden de aparición. */
export function groupBy<T>(items: T[], key: (item: T) => string | undefined): Map<string, T[]> {
    const groups = new Map<string, T[]>();
    for (const item of items) {
        const k = key(item);
        if (k === undefined) continue;
        const list = groups.get(k);
        if (list) list.push(item);
        else groups.set(k, [item]);
    }
    return groups;
}

export function byTime<T extends { timestamp: Date }>(a: T, b: T): number {
    return a.timestamp.getTime() - b.timestamp.getTime();
}
