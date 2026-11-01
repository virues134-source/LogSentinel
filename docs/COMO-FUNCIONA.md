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

`npm test` ejecuta 30 tests con el runner nativo de Node. No solo comprueban que las reglas detectan ataques; también que **no** alertan en casos legítimos (un usuario que falla una vez, búsquedas normales con apóstrofes como `l'oreal`, peticiones a `/favicon.ico`…). Los falsos positivos son el problema principal de cualquier sistema de detección.

## 6. Preguntas que te pueden hacer en una entrevista

**¿Por qué una ventana deslizante y no contar por hora fija?**
Con horas fijas, un ataque de 12:58 a 13:03 se parte en dos y ninguna mitad supera el umbral. La ventana deslizante no tiene ese punto ciego.

**¿Qué limitaciones tiene?**
Las firmas detectan ataques conocidos; un payload ofuscado de otra forma se escapa. Los access logs no guardan el cuerpo de los POST. Y es análisis por lotes, no en tiempo real. Para producción se usaría un SIEM (Wazuh, Elastic) y reglas Sigma; esto sirve como herramienta ligera o para revisar logs concretos.

**¿Cómo lo usarías en un servidor real?**
Con cron cada hora, `--min-severity high` y `--webhook` hacia n8n, que reenvía la alerta a Telegram o correo. Con `--fail-on critical` también se puede integrar en un pipeline.

**¿Qué es MITRE ATT&CK y por qué mapearlo?**
Es un catálogo público de técnicas de ataque reales. Mapear cada alerta a una técnica permite hablar el mismo idioma que un SOC, comparar cobertura de detección y consultar mitigaciones conocidas.

**¿Cómo evitarías bloquear a un usuario legítimo?**
Los umbrales son configurables (`--config`), la regla de login tras fallos exige varios fallos previos y las IPs internas se pueden revisar aparte. El siguiente paso sería una lista blanca de IPs.

## 7. Ideas para seguir ampliándolo

Estas mejoras están en el README como próximos pasos. Hacer alguna tú mismo es la mejor forma de que el proyecto sea tuyo de verdad:

- **Lista blanca de IPs** en la configuración (fácil).
- **Reputación de IPs** con la API de AbuseIPDB (media; ojo con no subir la API key al repo).
- **Exportar reglas de bloqueo** para `iptables` o `fail2ban` (media).
- **Modo `--follow`** que lea el log en tiempo real con `fs.watch` (avanzada).
