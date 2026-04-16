import { Injectable, Logger } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bull';
import { Queue } from 'bull';
import axios from 'axios';

@Injectable()
export class ScanService {
  private readonly logger = new Logger(ScanService.name);
  private resultsDb = new Map<string, any>();

  constructor(@InjectQueue('scanner') private scanQueue: Queue) {}

  async queuePortfolioScan(username: string): Promise<string> {
    this.logger.log(`A iniciar busca de repositórios para: ${username}`);
    const repos = await this.fetchGithubRepos(username);
    const jobId = `job_${Date.now()}_${username}`;

    await this.scanQueue.add('analyze-portfolio', { jobId, username, repos });
    this.logger.log(`Job ${jobId} adicionado à fila com ${repos.length} repositórios.`);
    return jobId;
  }

  async getJobResult(jobId: string): Promise<any> {
    return this.resultsDb.get(jobId) || null;
  }

  private async fetchGithubRepos(username: string) {
    try {
      const response = await axios.get(`https://api.github.com/users/${username}/repos?type=public`);
      return response.data.map(repo => ({
        id: repo.id, name: repo.name, clone_url: repo.clone_url, language: repo.language
      }));
    } catch (error) {
      this.logger.error(`Falha ao buscar repos de ${username}`, error);
      throw error;
    }
  }

  saveJobResult(jobId: string, finalReport: any) {
    this.resultsDb.set(jobId, finalReport);
  }
}
