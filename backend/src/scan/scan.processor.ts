import { Process, Processor } from '@nestjs/bull';
import { Logger } from '@nestjs/common';
import { Job } from 'bull';
import { ScanService } from './scan.service';
import { execSync } from 'child_process';
import * as path from 'path';

@Processor('scanner')
export class ScanProcessor {
  private readonly logger = new Logger(ScanProcessor.name);

  constructor(private readonly scanService: ScanService) {}

  @Process('analyze-portfolio')
  async handleScan(job: Job) {
    this.logger.debug(`A processar job ${job.data.jobId} para ${job.data.username}...`);
    const { repos, jobId, username } = job.data;
    
    const finalReport = {
      username: username,
      overallScore: 0,
      scannedRepos: repos.length,
      repos: []
    };

    let totalScore = 0;

    for (const repo of repos) {
       this.logger.log(`A escanear repo: ${repo.name}`);
       
       try {
         const workersDir = path.join(process.cwd(), '..', 'workers');
         
         // 1. Scan de Segredos
         const secretsScript = path.join(workersDir, 'secrets_scan.py');
         const secretsOutput = execSync(`python "${secretsScript}" "${repo.clone_url}"`, { encoding: 'utf8' });
         const secretFindings = JSON.parse(secretsOutput);

         // 2. Scan de Dependências
         const depsScript = path.join(workersDir, 'deps_scan.py');
         const depsOutput = execSync(`python "${depsScript}" "${repo.clone_url}"`, { encoding: 'utf8' });
         const depsFindings = JSON.parse(depsOutput);

         const allFindings = [...secretFindings, ...depsFindings];

         // 3. Cálculo de Score
         const scoreScript = path.join(workersDir, 'score.py');
         const findingsStr = JSON.stringify(allFindings).replace(/"/g, '\\"');
         const scoreOutput = execSync(`python "${scoreScript}" "${findingsStr}"`, { encoding: 'utf8' });
         const repoScore = parseInt(scoreOutput.trim());

         totalScore += repoScore;

         finalReport.repos.push({
           id: repo.id,
           name: repo.name,
           language: repo.language,
           score: repoScore,
           findings: allFindings
         });
       } catch (error) {
         this.logger.error(`Erro ao escanear repo ${repo.name}: ${error.message}`);
         finalReport.repos.push({
            id: repo.id,
            name: repo.name,
            language: repo.language,
            score: 0,
            findings: [{ id: 'error', type: 'system', severity: 'high', message: 'Falha durante o escaneamento' }]
         });
       }
    }

    finalReport.overallScore = repos.length > 0 ? Math.round(totalScore / repos.length) : 100;

    this.scanService.saveJobResult(jobId, finalReport);
    this.logger.log(`Job ${jobId} concluído com sucesso para ${username}. Status final: ${finalReport.overallScore}/100`);
  }
}
