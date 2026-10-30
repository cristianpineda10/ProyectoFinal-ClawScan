# ClawScan Local Sandbox

Sandbox local para analizar carpetas de skills OpenClaw con el scanner estático integrado de [ClawScan](https://github.com/openclaw/clawscan).

## Alcance y compatibilidad

ClawScan es un analizador de skills y plugins, no un escáner de hosts. No recibe IP/CIDR, puertos, hilos ni timeout como parámetros de escaneo. Por eso este proyecto recibe `target` como una ruta relativa dentro de `targets/` y ejecuta el scanner `clawscan-static`. Si necesitas detección de servicios y puertos, se requiere integrar otra herramienta de descubrimiento de red; sus datos no serían resultados de ClawScan.

El `go.mod` oficial declara Go 1.27.1. Se usa `golang:1.27.3-alpine` para la compilación; `golang:1.22-alpine` no puede compilar la versión actual. La imagen se construye desde la rama `main` oficial. Para builds reproducibles, fija en el Dockerfile una etiqueta o commit revisado.

## Árbol

```text
sandbox-clawscan/
├── backend/
│   ├── Dockerfile
│   ├── package-lock.json
│   ├── package.json
│   └── server.js
├── frontend/
│   ├── Dockerfile
│   ├── astro.config.mjs
│   ├── package-lock.json
│   ├── package.json
│   ├── tailwind.config.mjs
│   └── src/
│       ├── layouts/BaseLayout.astro
│       ├── pages/
│       │   ├── api/[...path].js
│       │   ├── index.astro
│       │   └── reports/[id].astro
│       └── styles/global.css
├── reports/.gitkeep
├── scanner/Dockerfile
├── targets/.gitkeep
├── .codex/config.toml
├── .gitignore
├── docker-compose.yml
├── README.md
└── setup.sh
```

## Requisitos

- Docker Engine con Docker Compose v2 y Docker en ejecución.
- Bash. En Windows, ejecutar desde WSL con Docker Desktop integrado.

## Instalación y primer escaneo

1. Guarda el proyecto en una carpeta y abre una terminal Bash en ella.
2. Añade la skill que tienes autorización para analizar en una subcarpeta de `targets/`. Ejemplo: `targets/mi-skill/SKILL.md` y los archivos asociados.
3. Ejecuta `chmod +x setup.sh` (si aplica) y luego `./setup.sh`. El script construye ClawScan y las imágenes de la API y Astro, y levanta Compose en segundo plano.
4. Abre [http://localhost:4321](http://localhost:4321), introduce `mi-skill` y ejecuta el análisis.
5. Revisa el visor de hallazgos y el JSON completo. Los JSON se guardan en `reports/`.

La API también responde en `http://localhost:3001/api/health`. Para listar reportes usa `GET /api/reports`; para leer uno, `GET /api/reports/<uuid>.json`. `POST /api/scan` recibe `{ "target": "mi-skill" }` y devuelve `202` junto con un ID de seguimiento; consulta `GET /api/scans/<id>` hasta que el estado sea `completed` o `failed`.

## Configurar análisis

En el panel puedes elegir los scanners instalados, timeout (10–1800 s), memoria (256–4096 MB) y CPU (0.5–4 cores). Esta imagen trae `clawscan-static`; los demás scanners se muestran con sus requisitos y permanecen deshabilitados hasta instalar su runtime y configuración.

Cada reporte detalla el gate, la duración, métricas de archivos, hallazgos agrupados por severidad, estado/tiempo/comando por scanner, reglas, hashes, archivos omitidos, evidencia JSON original y el artefacto ClawScan completo.

## MCP para modelos

La API expone un servidor MCP Streamable HTTP en `http://localhost:3001/mcp`. El archivo `.codex/config.toml` registra el servidor para este proyecto cuando Codex lo abre como workspace de confianza. En Codex Desktop también puedes ir a Settings → MCP servers y agregar la URL como Streamable HTTP; la configuración de Codex se comparte con CLI y la extensión. [Documentación oficial de MCP para Codex](https://learn.chatgpt.com/docs/extend/mcp).

Los análisis/cancelaciones piden aprobación por la política `writes`; los listados y lecturas se declaran de solo lectura. Puedes agregar el servidor manualmente en CLI con `codex mcp add clawscan-local --url http://localhost:3001/mcp`.

Las herramientas disponibles son `clawscan_list_scanners`, `clawscan_list_targets`, `clawscan_start_scan`, `clawscan_get_scan`, `clawscan_cancel_scan`, `clawscan_list_reports`, `clawscan_get_report` y `clawscan_get_report_evidence`.

El modelo puede listar objetivos, elegir un scanner habilitado, iniciar y cancelar análisis, ajustar recursos dentro de límites y leer reportes/evidencia. Las herramientas validan rutas bajo `targets/`; no aceptan comandos arbitrarios. El endpoint solo se publica en `127.0.0.1`.

## Flujo Astro → Express

Las páginas SSR llaman a Express con `fetch` desde el servidor usando `API_BASE_URL=http://claw-backend:3001`. El navegador envía el formulario a una ruta proxy Astro (`/api/...`), que reenvía la petición al backend sin exponer el nombre DNS interno de Docker. Las páginas de reportes también obtienen el artefacto y cada evidencia con `fetch` server-side.

## Aislamiento local

El contenedor de análisis recibe el árbol `targets/` en solo lectura, `reports/` para escribir y `--network none`, elimina capacidades Linux, aplica límite de memoria/CPU/PID y se ejecuta como usuario no root. La API necesita acceso al socket Docker para crear ese contenedor; el socket concede control amplio sobre el daemon anfitrión, por lo que esta sandbox debe permanecer local y sus puertos están enlazados a `127.0.0.1`.
