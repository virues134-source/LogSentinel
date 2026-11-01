// Panel del laboratorio: recibe los datos del servidor por Server-Sent Events.
import { createDashboard } from './dashboard-ui.js';

const dashboard = createDashboard({
    onSimulate: async () => {
        const response = await fetch('/simulate', { method: 'POST' });
        if (!response.ok && response.status !== 409) throw new Error(`HTTP ${response.status}`);
    },
});

const source = new EventSource('/events');
source.onopen = () => dashboard.setLive(true, 'En directo');
source.onerror = () => dashboard.setLive(false, 'Reconectando');
source.onmessage = (message) => dashboard.handle(JSON.parse(message.data));
