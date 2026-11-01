import type { AuthEvent, DetectionConfig, Finding } from '../types.ts';
import { MITRE } from '../mitre.ts';
import { byTime, densestWindow, groupBy } from './window.ts';

const isFailure = (e: AuthEvent) => e.action === 'failed' || e.action === 'invalid_user';

/**
 * Lista de intentos fallidos sin duplicados. sshd suele escribir dos líneas por cada intento
 * con un usuario inexistente ("Invalid user X" y luego "Failed password for invalid user X"),
 * así que la línea "Invalid user" solo cuenta si no la sigue su "Failed" en 30 segundos.
 */
export function failedAttempts(events: AuthEvent[]): AuthEvent[] {
    const sorted = events.filter(isFailure).sort(byTime);
    return sorted.filter((event, i) => {
        if (event.action !== 'invalid_user' || event.method) return true;
        for (let j = i + 1; j < sorted.length; j++) {
            const next = sorted[j];
            if (next.timestamp.getTime() - event.timestamp.getTime() > 30_000) break;
            if (next.ip === event.ip && next.user === event.user && next.method) return false;
        }
        return true;
    });
}

/** Muchos intentos fallidos desde una misma IP en poco tiempo, contra pocos usuarios. */
export function detectBruteForce(events: AuthEvent[], config: DetectionConfig): Finding[] {
    const { threshold, windowMinutes } = config.bruteForce;
    const findings: Finding[] = [];
    const failuresByIp = groupBy(failedAttempts(events), (e) => e.ip);

    for (const [ip, failures] of failuresByIp) {
        const win = densestWindow(failures, windowMinutes);
        if (win.size < threshold) continue;

        // Si se prueban muchos usuarios distintos es password spraying, no fuerza bruta:
        // lo reporta detectPasswordSpray y así no se duplica la alerta.
        const users = new Set(failures.map((e) => e.user));
        if (users.size >= config.passwordSpray.distinctUsers) continue;
        findings.push({
            rule: 'ssh-brute-force',
            title: 'Fuerza bruta contra SSH',
            severity: win.size >= threshold * 5 ? 'critical' : 'high',
            mitre: [MITRE.passwordGuessing, MITRE.remoteSsh],
            ip,
            firstSeen: failures[0].timestamp,
            lastSeen: failures[failures.length - 1].timestamp,
            count: failures.length,
            description:
                `${failures.length} intentos fallidos de login por SSH desde ${ip} ` +
                `(${win.size} en ${windowMinutes} min) contra ${users.size} usuario(s).`,
            evidence: failures.slice(win.start, win.start + config.maxEvidence).map((e) => e.raw),
        });
    }

    return findings;
}

/** Una IP prueba muchos usuarios distintos (pocas contraseñas contra muchas cuentas). */
export function detectPasswordSpray(events: AuthEvent[], config: DetectionConfig): Finding[] {
    const { distinctUsers, windowMinutes } = config.passwordSpray;
    const windowMs = windowMinutes * 60_000;
    const findings: Finding[] = [];
    const failuresByIp = groupBy(failedAttempts(events), (e) => e.ip);

    for (const [ip, failures] of failuresByIp) {
        // Ventana deslizante que lleva la cuenta de usuarios distintos dentro de la ventana.
        const inWindow = new Map<string, number>();
        let start = 0;
        let bestRange = { start: 0, end: -1, users: 0 };

        for (let end = 0; end < failures.length; end++) {
            const user = failures[end].user ?? '';
            inWindow.set(user, (inWindow.get(user) ?? 0) + 1);

            while (failures[end].timestamp.getTime() - failures[start].timestamp.getTime() > windowMs) {
                const old = failures[start].user ?? '';
                const left = (inWindow.get(old) ?? 1) - 1;
                if (left === 0) inWindow.delete(old);
                else inWindow.set(old, left);
                start++;
            }

            if (inWindow.size > bestRange.users) bestRange = { start, end, users: inWindow.size };
        }

        const best = failures.slice(bestRange.start, bestRange.end + 1);
        const users = [...new Set(best.map((e) => e.user))];
        if (users.length < distinctUsers) continue;

        findings.push({
            rule: 'ssh-password-spray',
            title: 'Password spraying / enumeración de usuarios por SSH',
            severity: 'high',
            mitre: [MITRE.passwordSpraying, MITRE.remoteSsh],
            ip,
            firstSeen: best[0].timestamp,
            lastSeen: best[best.length - 1].timestamp,
            count: best.length,
            description:
                `${ip} probó ${users.length} usuarios distintos en ${windowMinutes} min: ` +
                `${users.slice(0, 8).join(', ')}${users.length > 8 ? '…' : ''}.`,
            evidence: best.slice(0, config.maxEvidence).map((e) => e.raw),
        });
    }

    return findings;
}

/**
 * Un login correcto desde una IP que antes acumuló fallos: indicio de que el ataque
 * de fuerza bruta ha tenido éxito. Es la alerta más importante del módulo SSH.
 */
export function detectSuccessAfterFailures(events: AuthEvent[], config: DetectionConfig): Finding[] {
    const findings: Finding[] = [];
    const relevant = [...failedAttempts(events), ...events.filter((e) => e.action === 'accepted')].sort(byTime);
    const byIp = groupBy(relevant, (e) => e.ip);
    const minFailures = Math.max(3, Math.floor(config.bruteForce.threshold / 2));

    for (const [ip, ipEvents] of byIp) {
        let failures: AuthEvent[] = [];
        for (const event of ipEvents) {
            if (isFailure(event)) {
                failures.push(event);
                continue;
            }
            if (event.action !== 'accepted') continue;
            if (failures.length >= minFailures) {
                findings.push({
                    rule: 'ssh-success-after-failures',
                    title: 'Acceso SSH correcto tras múltiples fallos',
                    severity: 'critical',
                    mitre: [MITRE.validAccounts, MITRE.passwordGuessing, MITRE.remoteSsh],
                    ip,
                    user: event.user,
                    firstSeen: failures[0].timestamp,
                    lastSeen: event.timestamp,
                    count: failures.length + 1,
                    description:
                        `${ip} inició sesión como "${event.user}" (${event.method}) después de ` +
                        `${failures.length} intentos fallidos. Posible cuenta comprometida.`,
                    evidence: [...failures.slice(-(config.maxEvidence - 1)).map((e) => e.raw), event.raw],
                });
            }
            failures = [];
        }
    }

    return findings;
}

/** Inicio de sesión directo como root por SSH. */
export function detectRootLogin(events: AuthEvent[], config: DetectionConfig): Finding[] {
    const logins = events.filter((e) => e.action === 'accepted' && e.user === 'root').sort(byTime);
    const byIp = groupBy(logins, (e) => e.ip);

    return [...byIp].map(([ip, list]) => ({
        rule: 'ssh-root-login',
        title: 'Login SSH directo como root',
        severity: 'high' as const,
        mitre: [MITRE.localAccounts, MITRE.remoteSsh],
        ip,
        user: 'root',
        firstSeen: list[0].timestamp,
        lastSeen: list[list.length - 1].timestamp,
        count: list.length,
        description:
            `${list.length} inicio(s) de sesión como root desde ${ip}. ` +
            'Buena práctica: PermitRootLogin no y usar sudo.',
        evidence: list.slice(0, config.maxEvidence).map((e) => e.raw),
    }));
}

const RISKY_SUDO: { pattern: RegExp; reason: string }[] = [
    { pattern: /\/etc\/(shadow|sudoers)/, reason: 'acceso a ficheros de credenciales o sudoers' },
    { pattern: /\b(useradd|adduser|usermod)\b/, reason: 'creación o modificación de usuarios' },
    { pattern: /\b(curl|wget)\b.*\|\s*(ba)?sh\b/, reason: 'descarga y ejecución directa de un script' },
    { pattern: /\bchmod\s+(-R\s+)?[0-7]?777\b/, reason: 'permisos 777' },
    { pattern: /\b(nc|ncat|netcat)\b.*\s-e\s/, reason: 'posible reverse shell con netcat' },
    { pattern: /base64\s+(-d|--decode)/, reason: 'decodificación de payload en base64' },
    { pattern: /\b(iptables\s+-F|ufw\s+disable|systemctl\s+stop\s+\S*(firewall|auditd))/, reason: 'desactivación de defensas' },
    { pattern: /\b(history\s+-c|shred|rm\s+-rf?\s+\/var\/log)\b/, reason: 'borrado de rastros' },
];

/**
 * Comandos ejecutados con sudo que suelen aparecer en post-explotación, agrupados por usuario.
 * Varios tipos distintos de comando sospechoso en la misma cuenta suben la gravedad.
 */
export function detectSuspiciousSudo(events: AuthEvent[], config: DetectionConfig): Finding[] {
    const hits = events
        .filter((e) => e.action === 'sudo' && e.command)
        .map((event) => ({ event, hit: RISKY_SUDO.find((r) => r.pattern.test(event.command!)) }))
        .filter((h): h is { event: AuthEvent; hit: (typeof RISKY_SUDO)[number] } => h.hit !== undefined)
        .sort((a, b) => byTime(a.event, b.event));

    return [...groupBy(hits, (h) => h.event.user)].map(([user, list]) => {
        const reasons = [...new Set(list.map((h) => h.hit.reason))];
        return {
            rule: 'sudo-suspicious-command',
            title: 'Comandos sospechosos ejecutados con sudo',
            severity: reasons.length >= 3 ? ('high' as const) : ('medium' as const),
            mitre: [MITRE.sudo],
            user,
            firstSeen: list[0].event.timestamp,
            lastSeen: list[list.length - 1].event.timestamp,
            count: list.length,
            description:
                `"${user}" ejecutó ${list.length} comando(s) sospechoso(s) como root: ${reasons.join('; ')}.`,
            evidence: list.slice(0, config.maxEvidence).map((h) => h.event.raw),
        };
    });
}

export const sshDetectors = [
    detectBruteForce,
    detectPasswordSpray,
    detectSuccessAfterFailures,
    detectRootLogin,
    detectSuspiciousSudo,
];
