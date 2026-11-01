import { readFileSync, writeFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { basename } from 'node:path';
import type { DetectionConfig, LogEvent, Severity } from './types.ts';
import { DEFAULT_CONFIG, SEVERITY_ORDER } from './types.ts';
import { looksLikeAuthLog, parseAuthLog } from './parsers/auth-log.ts';
import { looksLikeAccessLog, parseAccessLog } from './parsers/access-log.ts';
import { buildReport, filterBySeverity, withFindings } from './analyzer.ts';
import type { Report } from './analyzer.ts';
import { renderTerminal } from './reporters/terminal.ts';
import { renderJson } from './reporters/json.ts';
import { renderHtml } from './reporters/html.ts';
import { sendWebhook } from './alerts.ts';

const HELP = `LogSentinel · detección de ataques en logs de SSH y servidores web

Uso:
  node src/cli.ts analyze <fichero...> [opciones]

Opciones:
  --type <auth|web|auto>      Formato de los ficheros (por defecto: auto)
  --format <table|json|html>  Formato del informe (por defecto: table)
  --out <fichero>             Guarda el informe en un fichero en lugar de mostrarlo
  --min-severity <nivel>      Muestra solo hallazgos de ese nivel o superior (low|medium|high|critical)
  --fail-on <nivel>           Sale con código 2 si hay hallazgos de ese nivel o superior (útil en CI/cron)
  --webhook <url>             Envía los hallazgos en JSON a un webhook (p. ej. n8n)
  --config <fichero.json>     Umbrales de detección personalizados
  --year <año>                Año para auth.log con fechas sin año (por defecto: el actual)
  -h, --help                  Muestra esta ayuda

Ejemplos:
  node src/cli.ts analyze /var/log/auth.log
  node src/cli.ts analyze samples/auth.log samples/access.log --format html --out report.html
  node src/cli.ts analyze access.log.gz --min-severity high --webhook https://n8n.example.com/webhook/logsentinel
`;

interface Options {
    files: string[];
    type: 'auth' | 'web' | 'auto';
    format: 'table' | 'json' | 'html';
    out?: string;
    minSeverity: Severity;
    failOn?: Severity;
    webhook?: string;
    config?: string;
    year: number;
}

class UsageError extends Error {}

function isSeverity(value: string): value is Severity {
    return value in SEVERITY_ORDER;
}

export function parseArgs(argv: string[]): Options | null {
    if (argv.length === 0 || argv.includes('-h') || argv.includes('--help')) return null;
    const [command, ...rest] = argv;
    if (command !== 'analyze') throw new UsageError(`Comando desconocido: ${command}`);

    const options: Options = { files: [], type: 'auto', format: 'table', minSeverity: 'low', year: new Date().getFullYear() };

    for (let i = 0; i < rest.length; i++) {
        const arg = rest[i];
        if (!arg.startsWith('--')) {
            options.files.push(arg);
            continue;
        }
        const value = rest[++i];
        if (value === undefined) throw new UsageError(`Falta el valor de ${arg}`);

        switch (arg) {
            case '--type':
                if (!['auth', 'web', 'auto'].includes(value)) throw new UsageError(`--type no válido: ${value}`);
                options.type = value as Options['type'];
                break;
            case '--format':
                if (!['table', 'json', 'html'].includes(value)) throw new UsageError(`--format no válido: ${value}`);
                options.format = value as Options['format'];
                break;
            case '--out':
                options.out = value;
                break;
            case '--min-severity':
                if (!isSeverity(value)) throw new UsageError(`--min-severity no válido: ${value}`);
                options.minSeverity = value;
                break;
            case '--fail-on':
                if (!isSeverity(value)) throw new UsageError(`--fail-on no válido: ${value}`);
                options.failOn = value;
                break;
            case '--webhook':
                options.webhook = value;
                break;
            case '--config':
                options.config = value;
                break;
            case '--year':
                if (!/^\d{4}$/.test(value)) throw new UsageError(`--year no válido: ${value}`);
                options.year = Number(value);
                break;
            default:
                throw new UsageError(`Opción desconocida: ${arg}`);
        }
    }

    if (options.files.length === 0) throw new UsageError('Indica al menos un fichero de log.');
    return options;
}

export function loadConfig(path?: string): DetectionConfig {
    if (!path) return DEFAULT_CONFIG;
    const custom = JSON.parse(readFileSync(path, 'utf8')) as Partial<DetectionConfig>;
    const merged: DetectionConfig = {
        bruteForce: { ...DEFAULT_CONFIG.bruteForce, ...custom.bruteForce },
        passwordSpray: { ...DEFAULT_CONFIG.passwordSpray, ...custom.passwordSpray },
        dirScan: { ...DEFAULT_CONFIG.dirScan, ...custom.dirScan },
        maxEvidence: custom.maxEvidence ?? DEFAULT_CONFIG.maxEvidence,
    };

    const numbers = [
        merged.bruteForce.threshold, merged.bruteForce.windowMinutes,
        merged.passwordSpray.distinctUsers, merged.passwordSpray.windowMinutes,
        merged.dirScan.notFoundThreshold, merged.dirScan.windowMinutes,
        merged.maxEvidence,
    ];
    if (numbers.some((n) => typeof n !== 'number' || !Number.isFinite(n) || n <= 0)) {
        throw new UsageError(`Configuración no válida en ${path}: todos los umbrales deben ser números positivos.`);
    }
    return merged;
}

function readLog(file: string): string {
    const buffer = readFileSync(file);
    return (file.endsWith('.gz') ? gunzipSync(buffer) : buffer).toString('utf8');
}

function detectType(content: string): 'auth' | 'web' | null {
    const sample = content.split(/\r?\n/).filter((l) => l.trim()).slice(0, 20);
    const web = sample.filter(looksLikeAccessLog).length;
    const auth = sample.filter(looksLikeAuthLog).length;
    if (web === 0 && auth === 0) return null;
    return web >= auth ? 'web' : 'auth';
}

export function loadEvents(options: Options): { events: LogEvent[]; sources: Report['sources'] } {
    const events: LogEvent[] = [];
    const sources: Report['sources'] = [];

    for (const file of options.files) {
        const content = readLog(file);
        const type = options.type === 'auto' ? detectType(content) : options.type;
        if (!type) throw new UsageError(`No se reconoce el formato de ${file}. Usa --type auth|web.`);

        const result = type === 'auth'
            ? parseAuthLog(content, basename(file), options.year)
            : parseAccessLog(content, basename(file));

        for (const event of result.events) events.push(event);
        sources.push({ file, type, events: result.events.length, skipped: result.skipped });
    }

    return { events, sources };
}

export async function main(argv: string[]): Promise<number> {
    let options: Options | null;
    try {
        options = parseArgs(argv);
    } catch (error) {
        console.error(`Error: ${(error as Error).message}\n`);
        console.error(HELP);
        return 1;
    }
    if (!options) {
        console.log(HELP);
        return 0;
    }

    try {
        const config = loadConfig(options.config);
        const { events, sources } = loadEvents(options);
        const full = buildReport(events, sources, config);
        const findings = filterBySeverity(full.findings, options.minSeverity);
        const report = withFindings(full, findings);

        const rendered =
            options.format === 'json' ? renderJson(report)
            : options.format === 'html' ? renderHtml(report)
            : renderTerminal(report);

        if (options.out) {
            writeFileSync(options.out, rendered, 'utf8');
            console.error(`Informe guardado en ${options.out} (${findings.length} hallazgos).`);
        } else {
            console.log(rendered);
        }

        if (options.webhook && findings.length > 0) {
            await sendWebhook(options.webhook, report, findings);
            console.error(`Alerta enviada al webhook (${findings.length} hallazgos).`);
        }

        if (options.failOn && filterBySeverity(findings, options.failOn).length > 0) return 2;
        return 0;
    } catch (error) {
        const err = error as NodeJS.ErrnoException;
        console.error(`Error: ${err.code === 'ENOENT' ? `no existe el fichero ${err.path}` : err.message}`);
        return 1;
    }
}

if (import.meta.main) {
    main(process.argv.slice(2)).then((code) => {
        process.exitCode = code;
    });
}
