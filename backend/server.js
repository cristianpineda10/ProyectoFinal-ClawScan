import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { toNodeHandler } from '@modelcontextprotocol/node';
import * as z from 'zod/v4';

const app = express();
const port = Number(process.env.PORT || 3001);
const reportsDir = path.resolve(process.env.REPORTS_DIR || './reports');
const targetsDir = path.resolve(process.env.TARGETS_DIR || './targets');
const scannerImage = process.env.SCANNER_IMAGE || 'clawscan-local:latest';
const scanTimeoutMs = Number(process.env.SCAN_TIMEOUT_MS || 600000);
const maxScanTimeoutSeconds = Number(process.env.MAX_SCAN_TIMEOUT_SECONDS || 1800);
const maxConcurrentScans = Number(process.env.MAX_CONCURRENT_SCANS || 2);
const allowedOrigin = process.env.ALLOWED_ORIGIN || 'http://localhost:4321';
const activeScans = new Map();
const scannerCatalog = [
  { id: 'clawscan-static', name: 'ClawScan Static', description: 'Análisis determinista de patrones de riesgo en skills y plugins.', available: true, reason: 'Incluido en la imagen.' },
  { id: 'skillspector', name: 'NVIDIA SkillSpector', description: 'Análisis de seguridad especializado en skills y plugins OpenClaw.', available: false, reason: 'Requiere instalar SkillSpector y su runtime.' },
  { id: 'cisco', name: 'Cisco AI Defense', description: 'Analizador local de skills con opciones de análisis upstream.', available: false, reason: 'Requiere instalar cisco-ai-skill-scanner y el runtime.' },
  { id: 'aig', name: 'Tencent AI-Infra-Guard', description: 'Analizador de skills con salida SARIF.', available: false, reason: 'Requiere instalar aig-skill-scan y configurar una clave LLM.' },
  { id: 'agentverus', name: 'AgentVerus', description: 'Análisis local de archivos y directorios de skills.', available: false, reason: 'Requiere instalar agentverus-scanner.' },
  { id: 'relyable', name: 'Relyable', description: 'Comprueba evidencias funcionales declaradas por la skill.', available: false, reason: 'Requiere el runtime Docker de ClawScan y Relyable.' },
  { id: 'snyk', name: 'Snyk Agent Scan', description: 'Escaneo de skills con Snyk.', available: false, reason: 'Requiere uvx y SNYK_TOKEN.' },
  { id: 'socket', name: 'Socket CLI', description: 'Análisis de manifiestos y dependencias de paquetes.', available: false, reason: 'Requiere instalar Socket CLI y configurar su token.' },
  { id: 'virustotal', name: 'VirusTotal', description: 'Consulta de hashes de archivos de skills.', available: false, reason: 'Requiere configurar VIRUSTOTAL_API_KEY.' }
];
const scannerById = new Map(scannerCatalog.map(scanner => [scanner.id, scanner]));

app.disable('x-powered-by');
app.use(cors({ origin: allowedOrigin, methods: ['GET', 'POST', 'DELETE'], allowedHeaders: ['Content-Type'] }));
app.use(express.json({ limit: '16kb' }));
app.use((_req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'no-referrer'); next(); });

function runDocker(args, timeoutMs, containerName) {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      const cleanup = spawn('docker', ['rm', '-f', containerName], { shell: false, stdio: 'ignore' });
      cleanup.unref();
    }, timeoutMs);
    child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => {
      clearTimeout(timer);
      if (timedOut) reject(new Error('El escaneo superó el timeout configurado.'));
      else if (code === 0) resolve();
      else reject(new Error((stderr.trim() || `docker exited with code ${code}`).slice(-4000)));
    });
  });
}

function safeTargetName(value) {
  if (typeof value !== 'string' || !value.trim() || value.length > 180) return null;
  const normalized = value.trim().replaceAll('\\', '/');
  if (path.posix.isAbsolute(normalized) || normalized.split('/').some(part => !part || part === '.' || part === '..')) return null;
  return /^[a-zA-Z0-9._/-]+$/.test(normalized) ? normalized : null;
}

const safeReportName = value => typeof value === 'string' && /^[a-f0-9-]{36}\.json$/.test(value);

function normalizeScanOptions(body = {}) {
  const scannerIds = body.scanners === undefined ? ['clawscan-static'] : body.scanners;
  if (!Array.isArray(scannerIds) || scannerIds.length < 1 || scannerIds.length > scannerCatalog.length) return { error: 'Selecciona entre 1 y 9 scanners.' };
  if (scannerIds.some(id => typeof id !== 'string' || !scannerById.has(id))) return { error: 'La selección contiene un scanner no reconocido.' };
  const unavailable = scannerIds.filter(id => !scannerById.get(id).available);
  if (unavailable.length) return { error: `Scanners todavía no instalados: ${unavailable.join(', ')}.` };
  if (new Set(scannerIds).size !== scannerIds.length) return { error: 'No repitas scanners en la misma ejecución.' };
  const timeoutSeconds = Number(body.timeoutSeconds ?? Math.min(600, maxScanTimeoutSeconds));
  const memoryMb = Number(body.memoryMb ?? 1024);
  const cpuLimit = Number(body.cpuLimit ?? 2);
  if (!Number.isInteger(timeoutSeconds) || timeoutSeconds < 10 || timeoutSeconds > maxScanTimeoutSeconds) return { error: `timeoutSeconds debe estar entre 10 y ${maxScanTimeoutSeconds}.` };
  if (!Number.isInteger(memoryMb) || memoryMb < 256 || memoryMb > 4096) return { error: 'memoryMb debe estar entre 256 y 4096.' };
  if (!Number.isFinite(cpuLimit) || cpuLimit < 0.5 || cpuLimit > 4) return { error: 'cpuLimit debe estar entre 0.5 y 4.' };
  return { options: { scanners: scannerIds, timeoutSeconds, memoryMb, cpuLimit } };
}

function runningScanCount() {
  return [...activeScans.values()].filter(scan => ['queued', 'running', 'cancelling'].includes(scan.status)).length;
}

async function performScan(id, target, options) {
  const reportFile = `${id}.json`;
  const targetRoot = await fs.realpath(targetsDir);
  const hostTarget = await fs.realpath(path.resolve(targetRoot, ...target.split('/'))).catch(() => null);
  if (!hostTarget || !hostTarget.startsWith(`${targetRoot}${path.sep}`)) throw new Error('Objetivo inexistente o fuera de ./targets.');
  const stat = await fs.stat(hostTarget);
  if (!stat.isDirectory()) throw new Error('El objetivo debe ser una carpeta dentro de ./targets.');
  const args = [
    'run', '--rm', '--network', 'none', '--read-only', '--cap-drop=ALL',
    '--security-opt=no-new-privileges:true', '--pids-limit=128', `--memory=${options.memoryMb}m`, `--cpus=${options.cpuLimit}`,
    '--name', `clawscan-${id}`,
    '--user', '1000:1000',
    '--mount', 'type=volume,source=claw_targets,target=/targets,readonly',
    '--mount', 'type=volume,source=claw_reports,target=/reports'
  ];
  args.push(scannerImage, `/targets/${target}`);
  for (const scanner of options.scanners) args.push('--scanner', scanner);
  args.push('--output', `/reports/${reportFile}`);
  try {
    await runDocker(args, Math.min(options.timeoutSeconds * 1000, scanTimeoutMs), `clawscan-${id}`);
    JSON.parse(await fs.readFile(path.join(reportsDir, reportFile), 'utf8'));
    return reportFile;
  } catch (error) {
    await fs.rm(path.join(reportsDir, reportFile), { force: true });
    throw error;
  }
}

function enqueueScan(target, options) {
  if (runningScanCount() >= maxConcurrentScans) return { error: 'Se alcanzó el máximo de escaneos simultáneos.' };
  const id = randomUUID();
  const state = { id, target, options, status: 'queued', createdAt: new Date().toISOString() };
  activeScans.set(id, state);
  state.status = 'running';
  performScan(id, target, options).then(report => {
    state.report = report;
    state.status = 'completed';
  }).catch(error => {
    state.status = state.cancelRequested ? 'cancelled' : 'failed';
    if (!state.cancelRequested) state.error = error.message;
  }).finally(() => {
    state.finishedAt = new Date().toISOString();
    setTimeout(() => activeScans.delete(id), 30 * 60 * 1000).unref();
  });
  return { state };
}

function scanContainerName(id) { return `clawscan-${id}`; }

async function cancelScan(id) {
  const state = activeScans.get(id);
  if (!state) return { error: 'Escaneo no encontrado o expirado.' };
  if (!['queued', 'running'].includes(state.status)) return { error: `El escaneo ya está ${state.status}.` };
  state.cancelRequested = true;
  state.status = 'cancelling';
  await new Promise(resolve => {
    const child = spawn('docker', ['rm', '-f', scanContainerName(id)], { shell: false, stdio: 'ignore' });
    child.on('error', resolve);
    child.on('close', resolve);
  });
  return { state };
}

async function discoverTargets(directory = targetsDir, prefix = '', depth = 0, found = []) {
  if (depth > 6 || found.length >= 500) return found;
  const entries = await fs.readdir(directory, { withFileTypes: true }).catch(() => []);
  const files = new Set(entries.filter(entry => entry.isFile()).map(entry => entry.name));
  if (prefix && (files.has('SKILL.md') || files.has('openclaw.plugin.json'))) {
    found.push({ target: prefix, kind: files.has('openclaw.plugin.json') ? 'plugin' : 'skill' });
  }
  for (const entry of entries) {
    if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
      await discoverTargets(path.join(directory, entry.name), prefix ? `${prefix}/${entry.name}` : entry.name, depth + 1, found);
    }
  }
  return found;
}

async function loadReport(filename) {
  if (!safeReportName(filename)) throw Object.assign(new Error('Nombre de reporte inválido.'), { status: 400 });
  const data = await fs.readFile(path.join(reportsDir, filename), 'utf8');
  return JSON.parse(data);
}

async function loadEvidence(filename, relativePath) {
  if (!safeReportName(filename)) throw Object.assign(new Error('Nombre de reporte inválido.'), { status: 400 });
  const reportRoot = path.resolve(reportsDir, filename.slice(0, -5));
  const relative = String(relativePath || '').replaceAll('\\', '/');
  if (!relative || relative.split('/').some(part => !part || part === '.' || part === '..')) throw Object.assign(new Error('Ruta de evidencia inválida.'), { status: 400 });
  const filePath = path.resolve(reportsDir, ...relative.split('/'));
  if (!filePath.startsWith(`${reportRoot}${path.sep}`)) throw Object.assign(new Error('Ruta de evidencia fuera del reporte.'), { status: 400 });
  return JSON.parse(await fs.readFile(filePath, 'utf8'));
}

async function listReports() {
  const entries = await fs.readdir(reportsDir, { withFileTypes: true });
  const reports = await Promise.all(entries.filter(item => item.isFile() && safeReportName(item.name)).map(async item => {
    const info = await fs.stat(path.join(reportsDir, item.name));
    return { filename: item.name, date: info.mtime.toISOString(), size: info.size };
  }));
  return reports.sort((a, b) => b.date.localeCompare(a.date));
}

app.get('/api/health', (_req, res) => res.json({ status: 'ok', activeScans: runningScanCount(), maxConcurrentScans }));
app.get('/api/scanners', (_req, res) => res.json(scannerCatalog));
app.get('/api/targets', async (_req, res, next) => {
  try { res.json(await discoverTargets()); } catch (error) { next(error); }
});
app.post('/api/scan', (req, res) => {
  const target = safeTargetName(req.body?.target);
  if (!target) return res.status(400).json({ error: 'target debe ser una ruta relativa válida dentro de ./targets.' });
  const normalized = normalizeScanOptions(req.body);
  if (normalized.error) return res.status(400).json({ error: normalized.error });
  const result = enqueueScan(target, normalized.options);
  if (result.error) return res.status(429).json({ error: result.error });
  res.status(202).json({ ...result.state, statusUrl: `/api/scans/${result.state.id}` });
});
app.get('/api/scans/:id', (req, res) => {
  const scan = activeScans.get(req.params.id);
  return scan ? res.json(scan) : res.status(404).json({ error: 'Escaneo no encontrado o expirado.' });
});
app.delete('/api/scans/:id', async (req, res, next) => {
  try {
    const result = await cancelScan(req.params.id);
    return result.error ? res.status(409).json(result) : res.json(result.state);
  } catch (error) { next(error); }
});
app.get('/api/reports', async (_req, res, next) => {
  try { res.json(await listReports()); } catch (error) { next(error); }
});
app.get('/api/reports/:filename', async (req, res, next) => {
  try { res.json(await loadReport(req.params.filename)); }
  catch (error) { if (error.code === 'ENOENT') return res.status(404).json({ error: 'Reporte no encontrado.' }); next(error); }
});
app.get('/api/reports/:filename/files/*', async (req, res, next) => {
  try { res.json(await loadEvidence(req.params.filename, req.params[0])); }
  catch (error) { if (error.code === 'ENOENT') return res.status(404).json({ error: 'Evidencia no encontrada.' }); next(error); }
});

const mcpHttpHandler = createMcpHandler(() => {
  const server = new McpServer({ name: 'clawscan-local-sandbox', version: '1.0.0' }, { capabilities: { tools: {} } });
  const toolResult = (value, isError = false) => ({ content: [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }], ...(isError ? { isError: true } : {}) });
  server.registerTool('clawscan_list_scanners', { description: 'Lista los scanners ClawScan y señala cuáles están instalados y listos para usarse.', inputSchema: z.object({}), annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } }, async () => toolResult(scannerCatalog));
  server.registerTool('clawscan_list_targets', { description: 'Lista skills y plugins reconocidos dentro de targets/. Solo devuelve rutas disponibles para análisis.', inputSchema: z.object({}), annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } }, async () => toolResult(await discoverTargets()));
  server.registerTool('clawscan_start_scan', {
    description: 'Inicia un análisis ClawScan de una skill o plugin local. Solo se permiten scanners marcados disponibles por clawscan_list_scanners. El contenedor no tiene red y lee targets/ en solo lectura.',
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    inputSchema: z.object({
      target: z.string().min(1).max(180),
      scanners: z.array(z.string()).min(1).max(9).optional(),
      timeoutSeconds: z.number().int().min(10).max(maxScanTimeoutSeconds).optional(),
      memoryMb: z.number().int().min(256).max(4096).optional(),
      cpuLimit: z.number().min(0.5).max(4).optional()
    })
  }, async input => {
    const target = safeTargetName(input.target);
    const normalized = normalizeScanOptions(input);
    if (!target || normalized.error) return toolResult(normalized.error || 'Ruta de target inválida.', true);
    const result = enqueueScan(target, normalized.options);
    return result.error ? toolResult(result.error, true) : toolResult({ id: result.state.id, target, status: result.state.status, options: result.state.options, statusUrl: `/api/scans/${result.state.id}` });
  });
  server.registerTool('clawscan_get_scan', { description: 'Consulta el estado y las opciones de un análisis ClawScan iniciado.', inputSchema: z.object({ id: z.string().uuid() }), annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } }, async ({ id }) => {
    const state = activeScans.get(id);
    return state ? toolResult(state) : toolResult('Escaneo no encontrado o expirado.', true);
  });
  server.registerTool('clawscan_cancel_scan', { description: 'Cancela un análisis que esté en curso.', inputSchema: z.object({ id: z.string().uuid() }), annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false } }, async ({ id }) => {
    const result = await cancelScan(id);
    return result.error ? toolResult(result.error, true) : toolResult(result.state);
  });
  server.registerTool('clawscan_list_reports', { description: 'Lista reportes guardados, ordenados del más reciente al más antiguo.', inputSchema: z.object({}), annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } }, async () => toolResult(await listReports()));
  server.registerTool('clawscan_get_report', { description: 'Devuelve el resultado ClawScan completo, con evidencia JSON por scanner.', inputSchema: z.object({ filename: z.string().regex(/^[a-f0-9-]{36}\.json$/) }), annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } }, async ({ filename }) => {
    try { return toolResult(await loadReport(filename)); } catch (error) { return toolResult(error.message, true); }
  });
  server.registerTool('clawscan_get_report_evidence', { description: 'Obtiene el JSON de evidencia original generado por un scanner para un reporte.', inputSchema: z.object({ filename: z.string().regex(/^[a-f0-9-]{36}\.json$/), scannerId: z.string().min(1).max(64) }), annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } }, async ({ filename, scannerId }) => {
    try {
      const report = await loadReport(filename);
      const evidencePath = report.scanners?.[scannerId]?.outputPath;
      if (!evidencePath) return toolResult(`El reporte no tiene evidencia para ${scannerId}.`, true);
      return toolResult(await loadEvidence(filename, evidencePath));
    } catch (error) { return toolResult(error.message, true); }
  });
  return server;
});
const mcpNodeHandler = toNodeHandler(mcpHttpHandler);
app.all('/mcp', (req, res) => { void mcpNodeHandler(req, res, req.body); });
app.use((error, _req, res, _next) => { console.error(error); res.status(500).json({ error: 'Error interno del servidor.' }); });
await fs.mkdir(reportsDir, { recursive: true });
await fs.mkdir(targetsDir, { recursive: true });
app.listen(port, '0.0.0.0', () => console.log(`ClawScan API escuchando en :${port}`));
