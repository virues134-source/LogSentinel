export type Severity = 'low' | 'medium' | 'high' | 'critical';

export const SEVERITY_ORDER: Record<Severity, number> = {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
};

/** Evento de autenticación extraído de auth.log / secure (sshd, sudo). */
export interface AuthEvent {
    kind: 'auth';
    timestamp: Date;
    host: string;
    program: string;
    action: 'failed' | 'accepted' | 'invalid_user' | 'sudo';
    ip?: string;
    user?: string;
    method?: string;
    command?: string;
    source: string;
    line: number;
    raw: string;
}

/** Petición HTTP extraída de un access log en formato combined (nginx / Apache). */
export interface WebEvent {
    kind: 'web';
    timestamp: Date;
    ip: string;
    method: string;
    path: string;
    status: number;
    bytes: number;
    referrer: string;
    userAgent: string;
    source: string;
    line: number;
    raw: string;
}

export type LogEvent = AuthEvent | WebEvent;

export interface MitreTechnique {
    id: string;
    name: string;
}

export interface Finding {
    rule: string;
    title: string;
    severity: Severity;
    mitre: MitreTechnique[];
    ip?: string;
    user?: string;
    firstSeen: Date;
    lastSeen: Date;
    count: number;
    description: string;
    evidence: string[];
}

export interface DetectionConfig {
    bruteForce: { threshold: number; windowMinutes: number };
    passwordSpray: { distinctUsers: number; windowMinutes: number };
    dirScan: { notFoundThreshold: number; windowMinutes: number };
    maxEvidence: number;
}

export const DEFAULT_CONFIG: DetectionConfig = {
    bruteForce: { threshold: 10, windowMinutes: 5 },
    passwordSpray: { distinctUsers: 5, windowMinutes: 10 },
    dirScan: { notFoundThreshold: 25, windowMinutes: 5 },
    maxEvidence: 5,
};

export interface ParseResult {
    events: LogEvent[];
    skipped: number;
}
