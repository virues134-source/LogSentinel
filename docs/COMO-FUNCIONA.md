# Cómo funciona LogSentinel

Guía para entender el proyecto de principio a fin. Si vas a hablar de él en una entrevista, con esto deberías poder explicar cada decisión.

## 1. El flujo completo

```
ficheros de log ──► parsers ──► eventos tipados ──► detectores ──► hallazgos ──► informe / webhook
```

1. **`cli.ts`** lee los argumentos, abre los ficheros (descomprime `.gz` si hace falta) y detecta si cada uno es un `auth.log` o un access log mirando las primeras 20 líneas.
2. **Los parsers** (`src/parsers/`) convierten cada línea de texto en un objeto con campos (`AuthEvent` o `WebEvent`). Lo que no reconocen se cuenta como "línea ignorada".
3. **Los detectores** (`src/detectors/`) reciben todos los eventos y devuelven hallazgos (`Finding`): qué pasó, desde qué IP, cuándo, con qué gravedad, qué técnica de MITRE es y qué líneas lo demuestran.
4. **`analyzer.ts`** ejecuta todas las reglas, ordena los hallazgos por gravedad y calcula una puntuación de riesgo por IP.
5. **Los reporters** (`src/reporters/`) pintan el resultado en terminal, JSON o HTML, y `alerts.ts` lo envía a un webhook.

## 2. Parsers: de texto a datos

Una línea de `auth.log` tiene esta forma:

```
Oct 27 02:10:02 web01 sshd[2145]: Failed password for root from 203.0.113.45 port 31424 ssh2
└─ fecha ─────┘ └host┘ └programa┘  └─ mensaje ─────────────────────────────────────────────┘
```

Primero una expresión regular separa la cabecera (fecha, host, programa) del mensaje. Después, según el programa, otras regex extraen los datos: usuario, IP, método (`password` o `publickey`) o el comando de sudo.

Detalle importante: el formato syslog **no incluye el año ni la zona horaria**. Por eso existe la opción `--year`, y la hora se toma tal cual aparece en el log.

Los access logs usan el formato *combined* de nginx/Apache:

```
203.0.113.99 - - [27/Oct/2026:14:20:04 +0000] "GET /productos?id=12 HTTP/1.1" 200 98000 "-" "sqlmap/1.8.4"
└── IP ────┘      └── fecha y zona ─────────┘ └── petición ────────────────┘ └st┘ └bytes┘ └ref┘ └user agent┘
```

## 3. Las reglas de detección

### Ventana deslizante (fuerza bruta, fuzzing)

No basta con contar fallos totales: 12 fallos en un día pueden ser un usuario despistado; 12 en un minuto es un ataque. `densestWindow()` recorre los eventos ordenados por tiempo con dos punteros (`start` y `end`) y encuentra el intervalo de N minutos con más eventos. Es O(n): cada evento entra y sale de la ventana una sola vez.

### Fuerza bruta frente a password spraying

- **Fuerza bruta**: muchas contraseñas contra **pocos usuarios** (normalmente `root` o `admin`).
- **Password spraying**: pocas contraseñas contra **muchos usuarios**, para no disparar bloqueos por cuenta.

Si una IP prueba 5 o más usuarios distintos, la regla de fuerza bruta se calla y la reporta solo la de spraying, para no duplicar alertas. La ventana del spraying usa un `Map` con el número de intentos por usuario dentro de la ventana, para saber en todo momento cuántos usuarios distintos hay sin recorrerla entera.

### Login correcto tras fallos

Es la alerta más importante del módulo SSH: indica que un ataque **ha funcionado**. Se recorren los eventos de cada IP en orden y, si aparece un `Accepted` después de varios fallos, se genera una alerta crítica. Para no confundirlo con alguien que se equivoca una vez al escribir la contraseña, hacen falta al menos 5 fallos previos.

### Dobles conteos

sshd escribe **dos líneas** por cada intento con un usuario que no existe:

```
Invalid user oracle from 198.51.100.23 port 32734
Failed password for invalid user oracle from 198.51.100.23 port 32735 ssh2
```

`failedAttempts()` descarta la primera si va seguida de la segunda en menos de 30 segundos, para contar un único intento.

### Reglas web por firmas

Cada petición se compara con listas de patrones (regex) de SQLi, inyección de comandos, XSS, path traversal y ficheros sensibles. Tres detalles:

1. **Decodificación múltiple**: los atacantes codifican dos veces (`%252e` → `%2e` → `.`) para saltarse filtros que solo decodifican una. `normalizePath()` decodifica hasta tres veces.
2. **Una petición, una regla**: `;cat /etc/passwd` encaja en inyección de comandos y en path traversal; se asigna solo a la primera regla de la lista (la más específica).
3. **El código de respuesta importa**: si un intento de SQLi devolvió `200` con muchos más bytes de lo normal, quizá funcionó. En ese caso la gravedad sube a crítica.

### Puntuación por IP

Cada hallazgo suma puntos a su IP (baja 1, media 3, alta 7, crítica 10). Así el informe empieza por las IPs que más conviene bloquear.

## 4. Seguridad del propio informe

Los logs los escribe el atacante. Si alguien hace `GET /<script>robarCookies()</script>` y el informe HTML pinta esa línea sin escapar, el script se ejecuta en el navegador de quien abre el informe. Es un **XSS almacenado a través de logs**, y es un fallo real que han tenido herramientas de monitorización.

Por eso `escapeHtml()` convierte `< > & " '` en entidades HTML, y además el informe lleva una **Content-Security-Policy** que prohíbe ejecutar cualquier script. Hay un test que lo comprueba.

## 5. Tests

`npm test` ejecuta 51 tests con el runner nativo de Node. No solo comprueban que las reglas detectan ataques; también que **no** alertan en casos legítimos (un usuario que falla una vez, búsquedas normales con apóstrofes como `l'oreal`, peticiones a `/favicon.ico`…). Los falsos positivos son el problema principal de cualquier sistema de detección. Además, una prueba de extremo a extremo lanza la simulación completa contra la tienda y comprueba que cada fase dispara su regla.

## 6. El laboratorio: cómo comprobar que no es inventado

`npm run lab` arranca tres piezas en un mismo proceso:

1. **La tienda Cafetería Nébula** (`lab/shop.ts`, con la lógica en `lab/shop-core.ts`): un servidor web de verdad. Cada petición que recibe la apunta en `lab/logs/access.log` con el mismo formato que nginx. Puedes abrir ese fichero mientras navegas y ver cómo crece.
2. **El monitor** (`src/live/`): sigue ese fichero como `tail -f`. Cada 300 ms mira si ha crecido, lee solo lo nuevo, lo convierte en eventos y vuelve a pasar las reglas. Comparando con la pasada anterior sabe qué alertas son nuevas y cuáles han subido de gravedad.
3. **El panel** (`http://127.0.0.1:8090`): recibe cada línea y cada alerta por *Server-Sent Events*, una conexión que el servidor mantiene abierta para enviar datos al navegador en cuanto los tiene.

Para comprobar por ti mismo que no hay nada preparado:

- Ataca la tienda a mano, con URLs que te inventes, y mira si salta la alerta.
- Abre `lab/logs/access.log` y comprueba que las líneas del panel están ahí.
- Navega normal por la tienda: no debería saltar nada.
- Lee `lab/attacks.ts`: el simulador solo envía peticiones; no habla con el monitor ni le dice qué detectar. LogSentinel se entera de todo únicamente por el log.

Un detalle: todas las peticiones salen de tu ordenador (127.0.0.1). Para representar atacantes distintos, el simulador envía la cabecera `X-Forwarded-For`, que es la que añaden los proxies y balanceadores con la IP original del cliente, y la tienda la usa al escribir el log. Si atacas a mano, verás tu propia IP, 127.0.0.1.

### La demo web

La versión publicada en GitHub Pages no tiene servidor: todo ocurre en el navegador del visitante, con **el mismo código**.

- `scripts/build-site.ts` toma los módulos del motor (parsers, reglas, informe, monitor) y la tienda, les quita los tipos de TypeScript con la función que trae Node (`module.stripTypeScriptTypes`) y genera JavaScript normal en `site/`.
- En la página, cada clic o dirección que escribes en la tienda pasa por `handleShopRequest()`, que devuelve la respuesta y genera su línea de log en formato nginx. Esa línea entra en el mismo monitor que usa el laboratorio.
- La tienda se pinta en un `iframe` aislado (`sandbox` sin scripts), así que aunque metas `<script>` en el buscador, no se ejecuta nada. Los enlaces y formularios los intercepta la página.
- No hay cookies, analítica ni peticiones a ningún servidor: no se recoge ningún dato de quien la visita.

¿Por qué así y no con un servidor público? Un servidor tendría que guardar y mostrar las IPs reales de los visitantes (un dato personal según el RGPD), todos compartirían el mismo panel y una tienda con fallos a propósito quedaría expuesta en internet.

## 7. Preguntas que te pueden hacer en una entrevista

**¿Por qué una ventana deslizante y no contar por hora fija?**
Con horas fijas, un ataque de 12:58 a 13:03 se parte en dos y ninguna mitad supera el umbral. La ventana deslizante no tiene ese punto ciego.

**¿Qué limitaciones tiene?**
Las firmas detectan ataques conocidos; un payload ofuscado de otra forma se escapa. Los access logs no guardan el cuerpo de los POST. El modo en directo vuelve a pasar todas las reglas con cada lote de líneas, lo que va bien para un servidor normal pero no para millones de eventos por minuto. Para producción se usaría un SIEM (Wazuh, Elastic) y reglas Sigma; esto sirve como herramienta ligera o para revisar logs concretos.

**¿Cómo lo usarías en un servidor real?**
Con cron cada hora, `--min-severity high` y `--webhook` hacia n8n, que reenvía la alerta a Telegram o correo. Con `--fail-on critical` también se puede integrar en un pipeline.

**¿Cómo evitas alertas falsas o repetidas en el webhook?**
El webhook de n8n lleva Header Auth: sin la clave responde 403, así que nadie puede colar alertas aunque conozca la URL. LogSentinel lee la clave de `LOGSENTINEL_WEBHOOK_KEY`, para que no quede en `ps` ni en el historial; se niega a enviarla por `http` a otra máquina, no sigue redirecciones y nunca la muestra en un error. Con `--webhook-state` guarda una huella de cada hallazgo avisado (regla, IP, usuario, inicio y gravedad), de modo que cron solo avisa de lo nuevo o de lo que ha subido de gravedad. La huella se guarda después de un envío correcto: si n8n está caído, se reintenta en la siguiente ejecución.

**¿Qué es MITRE ATT&CK y por qué mapearlo?**
Es un catálogo público de técnicas de ataque reales. Mapear cada alerta a una técnica permite hablar el mismo idioma que un SOC, comparar cobertura de detección y consultar mitigaciones conocidas.

**¿Cómo evitarías bloquear a un usuario legítimo?**
Los umbrales son configurables (`--config`), la regla de login tras fallos exige varios fallos previos y las IPs internas se pueden revisar aparte. El siguiente paso sería una lista blanca de IPs.

## 8. Ideas para seguir ampliándolo

Estas mejoras están en el README como próximos pasos. Hacer alguna tú mismo es la mejor forma de que el proyecto sea tuyo de verdad:

- **Lista blanca de IPs** en la configuración (fácil).
- **Reputación de IPs** con la API de AbuseIPDB (media; ojo con no subir la API key al repo).
- **Exportar reglas de bloqueo** para `iptables` o `fail2ban` (media).
- **Lista de IPs bloqueadas** que la tienda del laboratorio lea para rechazar al atacante en cuanto LogSentinel lo detecta (avanzada: convierte la detección en respuesta).
