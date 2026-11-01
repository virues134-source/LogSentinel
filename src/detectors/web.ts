import type { DetectionConfig, Finding, MitreTechnique, Severity, WebEvent } from '../types.ts';
import { MITRE } from '../mitre.ts';
import { byTime, densestWindow, groupBy } from './window.ts';

/**
 * Decodifica la URL varias veces: los atacantes suelen codificar dos veces
 * (%252e%252e) para saltarse filtros que solo decodifican una.
 */
export function normalizePath(path: string): string {
    let current = path.replace(/\+/g, ' ');
    for (let i = 0; i < 3; i++) {
        try {
            const decoded = decodeURIComponent(current);
            if (decoded === current) break;
            current = decoded;
        } catch {
            break;
        }
    }
    return current.toLowerCase();
}

interface PatternRule {
    rule: string;
    title: string;
    severity: Severity;
    mitre: MitreTechnique[];
    patterns: RegExp[];
    explain: string;
}

const PATTERN_RULES: PatternRule[] = [
    {
        rule: 'web-sql-injection',
        title: 'Intento de inyección SQL',
        severity: 'high',
        mitre: [MITRE.exploitPublicApp],
        explain: 'parámetros con sintaxis SQL',
        patterns: [
            /'\s*(or|and)\s+'?\d+'?\s*=\s*'?\d/,
            /\bunion(\s+all)?\s+select\b/,
            /\b(sleep|benchmark|pg_sleep)\s*\(/,
            /\bwaitfor\s+delay\b/,
            /;\s*(drop|delete|insert|update)\s+/,
            /\binformation_schema\b/,
            /'\s*--/,
        ],
    },
    {
        rule: 'web-command-injection',
        title: 'Intento de inyección de comandos',
        severity: 'high',
        mitre: [MITRE.exploitPublicApp],
        explain: 'comandos de shell encadenados en parámetros',
        patterns: [/[;|`]\s*(cat|id|whoami|uname|wget|curl|nc|bash|sh)\b/, /\$\(\s*(id|whoami|curl|wget)/, /\b(cmd|exec|command)=.*(whoami|\bid\b|uname)/],
    },
    {
        rule: 'web-xss',
        title: 'Intento de Cross-Site Scripting (XSS)',
        severity: 'medium',
        mitre: [MITRE.exploitPublicApp],
        explain: 'HTML o JavaScript inyectado en la URL',
        patterns: [/<\s*script\b/, /javascript\s*:/, /\bon(error|load|mouseover)\s*=/, /<\s*(img|svg|iframe)\b/, /document\.cookie/],
    },
    {
        rule: 'web-path-traversal',
        title: 'Path traversal / lectura de ficheros locales',
        severity: 'high',
        mitre: [MITRE.exploitPublicApp, MITRE.fileDiscovery],
        explain: 'secuencias ../ o rutas de sistema',
        patterns: [/\.\.[\/\\]/, /\/etc\/(passwd|shadow|hosts)/, /\b(c:|%systemroot%)\\windows\b/, /\bproc\/self\/environ\b/, /php:\/\/(filter|input)/],
    },
    {
        rule: 'web-sensitive-file-probe',
        title: 'Búsqueda de ficheros sensibles',
        severity: 'medium',
        mitre: [MITRE.wordlistScanning],
        explain: 'rutas típicas de configuración, backups o paneles',
        patterns: [
            /\/\.env\b/,
            /\/\.git\//,
            /\/\.(aws|ssh|docker)\b/,
            /wp-config\.php/,
            /\/(phpmyadmin|pma|adminer)\b/i,
            /\/server-status\b/,
            /\.(bak|old|sql|swp)(\?|$)/,
            /\/(backup|dump)\.(zip|tar|gz|sql)/,
        ],
    },
];

const SCANNER_AGENTS =
    /\b(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb|ffuf|feroxbuster|wpscan|nuclei|acunetix|nessus|openvas|whatweb|hydra)\b/i;

/**
 * Reglas basadas en firmas: cada petición se asigna a la primera regla que coincide (las más
 * específicas van antes) y se agrupa por IP. Si alguna devolvió 2xx, se sube la gravedad:
 * el ataque pudo funcionar.
 */
export function detectPatternAttacks(events: WebEvent[], config: DetectionConfig): Finding[] {
    const findings: Finding[] = [];
    const hitsByRule = new Map<PatternRule, WebEvent[]>();

    for (const event of events) {
        const target = normalizePath(event.path);
        const rule = PATTERN_RULES.find((r) => r.patterns.some((p) => p.test(target)));
        if (!rule) continue;
        const list = hitsByRule.get(rule);
        if (list) list.push(event);
        else hitsByRule.set(rule, [event]);
    }

    for (const rule of PATTERN_RULES) {
        const hits = hitsByRule.get(rule) ?? [];
        for (const [ip, list] of groupBy(hits.sort(byTime), (e) => e.ip)) {
            const succeeded = list.filter((e) => e.status >= 200 && e.status < 300);
            const severity: Severity = succeeded.length > 0 && rule.severity === 'high' ? 'critical' : rule.severity;
            const statusNote = succeeded.length > 0
                ? ` ${succeeded.length} respondieron con ${succeeded[0].status}: revisar si el ataque tuvo éxito.`
                : ' Ninguna respondió con éxito (2xx).';

            findings.push({
                rule: rule.rule,
                title: rule.title,
                severity,
                mitre: rule.mitre,
                ip,
                firstSeen: list[0].timestamp,
                lastSeen: list[list.length - 1].timestamp,
                count: list.length,
                description: `${list.length} petición(es) desde ${ip} con ${rule.explain}.${statusNote}`,
                evidence: [...succeeded, ...list.filter((e) => !succeeded.includes(e))]
                    .slice(0, config.maxEvidence)
                    .map((e) => e.raw),
            });
        }
    }

    return findings;
}

/** Herramientas de escaneo que se identifican en el User-Agent. */
export function detectScannerAgents(events: WebEvent[], config: DetectionConfig): Finding[] {
    const hits = events.filter((e) => SCANNER_AGENTS.test(e.userAgent)).sort(byTime);

    return [...groupBy(hits, (e) => e.ip)].map(([ip, list]) => {
        const tools = [...new Set(list.map((e) => e.userAgent.match(SCANNER_AGENTS)![1].toLowerCase()))];
        return {
            rule: 'web-scanner-user-agent',
            title: 'Escáner de vulnerabilidades detectado',
            severity: 'medium' as const,
            mitre: [MITRE.vulnScanning],
            ip,
            firstSeen: list[0].timestamp,
            lastSeen: list[list.length - 1].timestamp,
            count: list.length,
            description: `${list.length} petición(es) desde ${ip} con User-Agent de: ${tools.join(', ')}.`,
            evidence: list.slice(0, config.maxEvidence).map((e) => e.raw),
        };
    });
}

/** Muchas respuestas 404 en poco tiempo: fuzzing de rutas con diccionario. */
export function detectDirectoryBruteForce(events: WebEvent[], config: DetectionConfig): Finding[] {
    const { notFoundThreshold, windowMinutes } = config.dirScan;
    const findings: Finding[] = [];
    const notFound = events.filter((e) => e.status === 404).sort(byTime);

    for (const [ip, list] of groupBy(notFound, (e) => e.ip)) {
        const win = densestWindow(list, windowMinutes);
        if (win.size < notFoundThreshold) continue;

        const paths = new Set(list.map((e) => e.path));
        findings.push({
            rule: 'web-directory-bruteforce',
            title: 'Fuzzing de rutas (directory brute force)',
            severity: 'medium',
            mitre: [MITRE.wordlistScanning],
            ip,
            firstSeen: list[0].timestamp,
            lastSeen: list[list.length - 1].timestamp,
            count: list.length,
            description:
                `${list.length} respuestas 404 para ${ip} (${win.size} en ${windowMinutes} min, ` +
                `${paths.size} rutas distintas).`,
            evidence: list.slice(win.start, win.start + config.maxEvidence).map((e) => e.raw),
        });
    }

    return findings;
}

export const webDetectors = [detectPatternAttacks, detectScannerAgents, detectDirectoryBruteForce];
