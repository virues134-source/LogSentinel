# Seguridad

## Qué ejecuta este proyecto en tu equipo

- **No tiene dependencias** ni scripts de instalación (`preinstall`, `postinstall`…). No hace falta `npm install`: descargar el código no ejecuta nada.
- **No se conecta a internet por su cuenta.** Solo envía datos si tú le das una dirección con `--webhook`.
- El **laboratorio** (`npm run lab`) y el **panel en directo** solo escuchan en `127.0.0.1`: no son accesibles desde otros equipos.
- El **simulador de ataques** se niega a enviar peticiones a cualquier dirección que no sea tu propio equipo.
- La **demo web** se ejecuta entera en el navegador del visitante, sin cookies, analítica ni servidor.

## Uso responsable

LogSentinel es una herramienta defensiva y educativa. Analiza solo logs de sistemas que administres o para los que tengas autorización. La tienda del laboratorio tiene fallos a propósito: no la publiques en internet.

## Avisar de un problema

Si encuentras una vulnerabilidad en LogSentinel, por favor no abras un issue público. Usa **Security → Report a vulnerability** en este repositorio para avisar de forma privada.
