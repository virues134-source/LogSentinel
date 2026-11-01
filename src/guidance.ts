/**
 * Explicación en lenguaje claro y acciones recomendadas para cada regla.
 * Lo usa el informe HTML para que se entienda sin conocimientos de seguridad.
 */
export interface Guidance {
    meaning: string;
    actions: string[];
}

export const GUIDANCE: Record<string, Guidance> = {
    'ssh-brute-force': {
        meaning: 'Alguien está probando contraseñas una tras otra para entrar al servidor por SSH.',
        actions: [
            'Bloquear la IP en el firewall o con fail2ban.',
            'Desactivar el login por contraseña y usar solo claves SSH (PasswordAuthentication no).',
            'Comprobar que ninguna cuenta atacada tiene una contraseña débil.',
        ],
    },
    'ssh-password-spray': {
        meaning: 'Una misma IP prueba muchos nombres de usuario con pocas contraseñas, buscando cuentas que existan o tengan claves comunes.',
        actions: [
            'Bloquear la IP.',
            'Revisar qué usuarios probados existen realmente en el sistema.',
            'Limitar qué cuentas pueden entrar por SSH (AllowUsers en sshd_config).',
        ],
    },
    'ssh-success-after-failures': {
        meaning: 'Después de muchos intentos fallidos, la misma IP consiguió entrar. Lo más probable es que haya adivinado la contraseña.',
        actions: [
            'Tratarlo como un incidente: bloquear la cuenta y la IP de inmediato.',
            'Cerrar las sesiones abiertas de ese usuario y cambiar su contraseña.',
            'Revisar qué hizo después de entrar: comandos sudo, usuarios creados, ficheros modificados, tareas cron.',
        ],
    },
    'ssh-root-login': {
        meaning: 'Alguien ha entrado directamente como root, el usuario con control total. Aunque sea legítimo, es una mala práctica.',
        actions: [
            'Confirmar que el acceso fue legítimo.',
            'Desactivar el login de root por SSH (PermitRootLogin no) y usar sudo con cuentas personales.',
        ],
    },
    'sudo-suspicious-command': {
        meaning: 'Un usuario ejecutó como administrador comandos típicos de un atacante que ya está dentro: robar contraseñas, crear accesos o borrar rastros.',
        actions: [
            'Verificar con el dueño de la cuenta si fue él.',
            'Si no lo fue: tratarlo como cuenta comprometida y revisar usuarios nuevos, claves SSH y crontabs.',
            'Limitar en sudoers qué comandos puede ejecutar cada usuario.',
        ],
    },
    'web-sql-injection': {
        meaning: 'Se intentó manipular las consultas a la base de datos a través de la URL para leer o modificar datos.',
        actions: [
            'Si alguna petición respondió con éxito, revisar la aplicación y la base de datos: puede haber fuga de datos.',
            'Usar consultas parametrizadas en el código en lugar de concatenar texto.',
            'Bloquear la IP y valorar un WAF.',
        ],
    },
    'web-command-injection': {
        meaning: 'Se intentó que el servidor ejecutara comandos del sistema a través de un parámetro de la web.',
        actions: [
            'Revisar el endpoint afectado: nunca pasar datos del usuario a una shell.',
            'Si alguna petición tuvo éxito, tratar el servidor como comprometido.',
        ],
    },
    'web-xss': {
        meaning: 'Se intentó inyectar código JavaScript en la web para que se ejecute en el navegador de otros usuarios.',
        actions: [
            'Comprobar que la aplicación escapa los datos antes de mostrarlos.',
            'Añadir una cabecera Content-Security-Policy.',
        ],
    },
    'web-path-traversal': {
        meaning: 'Se intentó salir de la carpeta de la web para leer ficheros del sistema, como /etc/passwd.',
        actions: [
            'Revisar el parámetro afectado: validar y normalizar las rutas.',
            'Si alguna petición respondió con éxito, revisar qué ficheros pudieron leerse.',
        ],
    },
    'web-sensitive-file-probe': {
        meaning: 'Alguien buscó ficheros que no deberían ser públicos: configuración, contraseñas, backups o el repositorio git.',
        actions: [
            'Comprobar que esos ficheros no son accesibles desde fuera.',
            'Bloquear en el servidor web el acceso a ficheros ocultos (.env, .git).',
        ],
    },
    'web-scanner-user-agent': {
        meaning: 'Una herramienta automática de búsqueda de vulnerabilidades está analizando la web.',
        actions: [
            'Bloquear la IP si el escaneo no está autorizado.',
            'Revisar el resto de hallazgos de esa IP: suele ser el paso previo a un ataque.',
        ],
    },
    'web-directory-bruteforce': {
        meaning: 'Alguien está probando cientos de rutas para descubrir páginas o paneles ocultos.',
        actions: [
            'Bloquear la IP o limitar el número de peticiones por IP (rate limiting).',
            'Asegurarse de que los paneles de administración no son públicos.',
        ],
    },
};
