import { Process, Processor } from '@nestjs/bull';
import { Logger } from '@nestjs/common';
import { Job } from 'bull';
import { spawn } from 'child_process';
import * as path from 'path';

import { ScanService } from './scan.service';

const PYTHON = process.env.PYTHON_CMD || 'python';
const SCRIPT_TIMEOUT_MS = 120_000;
const SCAN_CONCURRENCY = parseInt(process.env.SCAN_CONCURRENCY || '6', 10);

async function runConcurrent<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const idx = next++;
      results[idx] = await fn(items[idx], idx);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, worker),
  );
  return results;
}

function runScript(
  scriptPath: string,
  args: string[] = [],
  stdin?: string,
  onProgress?: (line: string) => void,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON, [scriptPath, ...args], {
      env: { ...process.env },
      windowsHide: true,
    });

    let stdout = '';
    let stderrBuf = '';

    if (stdin !== undefined) {
      child.stdin.write(stdin);
      child.stdin.end();
    }

    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });

    child.stderr.on('data', (chunk: Buffer) => {
      const text = chunk.toString();
      stderrBuf += text;
      if (onProgress) {
        text.split('\n').forEach(line => {
          const trimmed = line.trim();
          if (trimmed.startsWith('PROGRESS:')) {
            onProgress(trimmed.slice('PROGRESS:'.length).trim());
          }
        });
      }
    });

    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`Script timed out after ${SCRIPT_TIMEOUT_MS}ms`));
    }, SCRIPT_TIMEOUT_MS);

    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(stderrBuf.trim() || `Script exited with code ${code}`));
      } else {
        resolve(stdout);
      }
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

@Processor('scanner')
export class ScanProcessor {
  private readonly logger = new Logger(ScanProcessor.name);

  constructor(private readonly scanService: ScanService) {}

  @Process('analyze-portfolio')
  async handleScan(job: Job) {
    const { repos, jobId, username } = job.data;
    this.logger.debug(`Processing job ${jobId} for ${username} (${repos.length} repos) — parallel`);

    const workersDir = path.resolve(process.cwd(), '..', 'workers');

    const scanRepo = async (repo: any) => {
      this.scanService.updateProgress(jobId, (p) => {
        const r = p.repos.find(r => r.id === repo.id);
        if (r) { r.status = 'scanning'; r.currentFile = 'iniciando...'; }
        p.logs.push(`[${repo.name}] Scan iniciado`);
      });

      try {
        const [secretsOutput, depsOutput, misconfigOutput] = await Promise.all([
          runScript(
            path.join(workersDir, 'secrets_scan.py'),
            [repo.clone_url],
            undefined,
            (file) => {
              this.scanService.updateProgress(jobId, (p) => {
                const r = p.repos.find(r => r.id === repo.id);
                if (r) r.currentFile = file;
              });
            },
          ),
          runScript(
            path.join(workersDir, 'deps_scan.py'),
            [repo.clone_url],
          ),
          runScript(
            path.join(workersDir, 'misconfig_scan.py'),
            [repo.clone_url],
          ),
        ]);

        const allFindings = [
          ...JSON.parse(secretsOutput),
          ...JSON.parse(depsOutput),
          ...JSON.parse(misconfigOutput),
        ];

        const scoreOutput = await runScript(
          path.join(workersDir, 'score.py'),
          [],
          JSON.stringify(allFindings),
        );
        const repoScore = parseInt(scoreOutput.trim(), 10) || 100;

        this.scanService.updateProgress(jobId, (p) => {
          const r = p.repos.find(r => r.id === repo.id);
          if (r) { r.status = 'done'; r.findingsCount = allFindings.length; delete r.currentFile; }
          p.scannedRepos++;
          const tag = allFindings.length > 0 ? `${allFindings.length} problema(s)` : 'sem problemas';
          p.logs.push(`[${repo.name}] Concluído — ${tag} — score ${repoScore}/100`);
        });

        return {
          id: repo.id,
          name: repo.name,
          language: repo.language,
          score: repoScore,
          findings: allFindings,
        };
      } catch (error) {
        this.logger.error(`Error scanning ${repo.name}: ${error.message}`);
        this.scanService.updateProgress(jobId, (p) => {
          const r = p.repos.find(r => r.id === repo.id);
          if (r) { r.status = 'error'; delete r.currentFile; }
          p.scannedRepos++;
          p.logs.push(`[${repo.name}] Erro durante o scan`);
        });
        return {
          id: repo.id,
          name: repo.name,
          language: repo.language,
          score: 50,
          findings: [{
            id: 'scan-error',
            type: 'system',
            severity: 'medium',
            message: 'Não foi possível completar o escaneamento deste repositório',
            file: 'N/A',
          }],
        };
      }
    };

    const results = await runConcurrent(repos, SCAN_CONCURRENCY, scanRepo);
    const overallScore = results.length > 0
      ? Math.round(results.reduce((sum, r) => sum + r.score, 0) / results.length)
      : 100;

    this.scanService.completeJob(jobId, {
      username,
      overallScore,
      scannedRepos: repos.length,
      repos: results,
    });

    this.logger.log(`Job ${jobId} done — score ${overallScore}/100`);
  }
}
