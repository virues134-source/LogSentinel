import type { MitreTechnique } from './types.ts';

/** Técnicas de MITRE ATT&CK que usan las reglas. */
export const MITRE = {
    passwordGuessing: { id: 'T1110.001', name: 'Brute Force: Password Guessing' },
    passwordSpraying: { id: 'T1110.003', name: 'Brute Force: Password Spraying' },
    validAccounts: { id: 'T1078', name: 'Valid Accounts' },
    localAccounts: { id: 'T1078.003', name: 'Valid Accounts: Local Accounts' },
    remoteSsh: { id: 'T1021.004', name: 'Remote Services: SSH' },
    sudo: { id: 'T1548.003', name: 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching' },
    exploitPublicApp: { id: 'T1190', name: 'Exploit Public-Facing Application' },
    fileDiscovery: { id: 'T1083', name: 'File and Directory Discovery' },
    vulnScanning: { id: 'T1595.002', name: 'Active Scanning: Vulnerability Scanning' },
    wordlistScanning: { id: 'T1595.003', name: 'Active Scanning: Wordlist Scanning' },
} satisfies Record<string, MitreTechnique>;

export function mitreUrl(id: string): string {
    return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
}
