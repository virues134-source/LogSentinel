/**
 * Las fechas se muestran en la hora local del equipo que hace el análisis, con su
 * desfase respecto a UTC, para que coincidan con el reloj de quien lee el informe.
 */
const pad = (n: number) => String(n).padStart(2, '0');

export function formatDateTime(date: Date): string {
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${formatClock(date)}`;
}

export function formatClock(date: Date): string {
    return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function formatDay(date: Date): string {
    return formatDateTime(date).slice(0, 10);
}

/** Desfase horario en formato "UTC+01:00" (el de la fecha indicada, por el horario de verano). */
export function utcOffsetLabel(date = new Date()): string {
    const minutes = -date.getTimezoneOffset();
    const sign = minutes >= 0 ? '+' : '-';
    const abs = Math.abs(minutes);
    return `UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
}
