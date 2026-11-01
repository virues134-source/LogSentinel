import { closeSync, existsSync, openSync, readSync, statSync, unwatchFile, watchFile, writeFileSync } from 'node:fs';

/**
 * Sigue un fichero de log como `tail -f`: cada vez que crece, lee solo los bytes nuevos
 * y entrega las líneas completas. Usa sondeo (watchFile) porque es fiable en Windows,
 * Linux y macOS. Si el fichero se trunca (logrotate), vuelve a empezar desde el principio.
 */
export function tailFile(
    path: string,
    onLines: (lines: string[]) => void,
    options: { fromStart?: boolean; intervalMs?: number } = {},
): () => void {
    if (!existsSync(path)) writeFileSync(path, '');

    let offset = options.fromStart ? 0 : statSync(path).size;
    let pending = '';

    const read = () => {
        const size = statSync(path).size;
        if (size < offset) {
            offset = 0;
            pending = '';
        }
        if (size === offset) return;

        const length = size - offset;
        const buffer = Buffer.alloc(length);
        const fd = openSync(path, 'r');
        try {
            readSync(fd, buffer, 0, length, offset);
        } finally {
            closeSync(fd);
        }
        offset = size;

        const text = pending + buffer.toString('utf8');
        const parts = text.split(/\r?\n/);
        pending = parts.pop() ?? '';
        const lines = parts.filter((l) => l.trim());
        if (lines.length > 0) onLines(lines);
    };

    if (options.fromStart) read();
    watchFile(path, { interval: options.intervalMs ?? 300 }, read);
    return () => unwatchFile(path, read);
}
