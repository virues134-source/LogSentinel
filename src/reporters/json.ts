import type { Report } from '../analyzer.ts';

export function renderJson(report: Report): string {
    return JSON.stringify(report, null, 2);
}
