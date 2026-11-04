import type { Report } from '../analyzer.ts';
import { withGuidance } from '../guidance.ts';

export function renderJson(report: Report): string {
    return JSON.stringify({ ...report, findings: report.findings.map(withGuidance) }, null, 2);
}
