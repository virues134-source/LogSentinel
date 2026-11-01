/**
 * Construye la demo web en site/ para publicarla en GitHub Pages.
 *
 * El motor de LogSentinel está escrito en TypeScript; aquí se quitan los tipos con
 * la función que trae Node (module.stripTypeScriptTypes) y se cambian las rutas
 * .ts por .js. El resultado es JavaScript normal que el navegador ejecuta tal cual,
 * sin dependencias ni herramientas de compilación.
 */
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { stripTypeScriptTypes } from 'node:module';

const OUT = 'site';

// Módulos que necesita la demo (el resto, como la CLI o el servidor, usan Node).
const ENGINE = [
    'src/types.ts',
    'src/mitre.ts',
    'src/guidance.ts',
    'src/time.ts',
    'src/analyzer.ts',
    'src/parsers/auth-log.ts',
    'src/parsers/access-log.ts',
    'src/detectors/window.ts',
    'src/detectors/ssh.ts',
    'src/detectors/web.ts',
    'src/reporters/html.ts',
    'src/live/monitor.ts',
    'lab/shop-core.ts',
    'lab/attacks.ts',
];

const STATIC: Record<string, string> = {
    'web/index.html': 'index.html',
    'web/demo.js': 'demo.js',
    'web/demo.css': 'demo.css',
    'src/live/dashboard.css': 'dashboard.css',
    'src/live/dashboard-ui.js': 'dashboard-ui.js',
};

rmSync(OUT, { recursive: true, force: true });

for (const file of ENGINE) {
    const source = readFileSync(file, 'utf8');
    if (/from ['"]node:/.test(source)) throw new Error(`${file} usa módulos de Node y no puede ir al navegador`);
    const js = stripTypeScriptTypes(source).replace(/(from\s+['"]\.{1,2}\/[^'"]+)\.ts(['"])/g, '$1.js$2');
    const target = join(OUT, 'engine', file.replace(/\.ts$/, '.js'));
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, js);
}

for (const [from, to] of Object.entries(STATIC)) {
    const target = join(OUT, to);
    mkdirSync(dirname(target), { recursive: true });
    cpSync(from, target);
}

// GitHub Pages: sin Jekyll, para que sirva los ficheros tal cual.
writeFileSync(join(OUT, '.nojekyll'), '');

console.log(`Demo construida en ${OUT}/ (${ENGINE.length} módulos del motor).`);
