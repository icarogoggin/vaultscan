import { Injectable, Logger } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bull';
import { Queue } from 'bull';
import axios from 'axios';

export interface RepoProgress {
  id: number;
  name: string;
  language: string | null;
  status: 'pending' | 'scanning' | 'done' | 'error';
  currentFile?: string;
  findingsCount: number;
}

export interface ScanProgress {
  username: string;
  totalRepos: number;
  scannedRepos: number;
  repos: RepoProgress[];
  logs: string[];
}

type Job = { status: 'processing' | 'completed'; data: any };

@Injectable()
export class ScanService {
  private readonly logger = new Logger(ScanService.name);
  private jobsDb = new Map<string, Job>();

  constructor(@InjectQueue('scanner') private scanQueue: Queue) {}

  async queuePortfolioScan(username: string): Promise<string> {
    this.logger.log(`Fetching repositories for: ${username}`);
    const repos = await this.fetchGithubRepos(username);
    const jobId = `job_${Date.now()}_${username}`;

    const initialProgress: ScanProgress = {
      username,
      totalRepos: repos.length,
      scannedRepos: 0,
      repos: repos.map(r => ({
        id: r.id,
        name: r.name,
        language: r.language,
        status: 'pending',
        findingsCount: 0,
      })),
      logs: [`${repos.length} repositório(s) encontrado(s). Iniciando scan paralelo...`],
    };

    this.jobsDb.set(jobId, { status: 'processing', data: initialProgress });
    await this.scanQueue.add('analyze-portfolio', { jobId, username, repos });
    this.logger.log(`Job ${jobId} queued with ${repos.length} repositories.`);
    return jobId;
  }

  getJob(jobId: string): Job | null {
    return this.jobsDb.get(jobId) || null;
  }

  updateProgress(jobId: string, updater: (p: ScanProgress) => void) {
    const job = this.jobsDb.get(jobId);
    if (job?.status === 'processing') {
      updater(job.data as ScanProgress);
    }
  }

  completeJob(jobId: string, finalReport: any) {
    this.jobsDb.set(jobId, { status: 'completed', data: finalReport });
  }

  private async fetchGithubRepos(username: string) {
    const headers: Record<string, string> = {
      Accept: 'application/vnd.github.v3+json',
    };
    if (process.env.GITHUB_TOKEN) {
      headers.Authorization = `token ${process.env.GITHUB_TOKEN}`;
    }

    const allRepos: any[] = [];
    let page = 1;

    try {
      while (true) {
        const response = await axios.get(
          `https://api.github.com/users/${username}/repos`,
          {
            headers,
            params: { type: 'public', per_page: 100, page, sort: 'pushed' },
            timeout: 15000,
          },
        );
        const batch: any[] = response.data;
        allRepos.push(...batch);
        if (batch.length < 100) break;
        page++;
      }
    } catch (error) {
      const status = error?.response?.status;
      if (status === 403 || status === 429) {
        this.logger.error('GitHub API rate limit exceeded. Add GITHUB_TOKEN to .env');
        throw new Error('GitHub API rate limit exceeded. Add a GITHUB_TOKEN to backend/.env and restart.');
      }
      if (status === 404) {
        throw new Error(`GitHub user "${username}" not found.`);
      }
      this.logger.error(`Failed to fetch repos for ${username}: ${error.message}`);
      throw error;
    }

    return allRepos.map(repo => ({
      id: repo.id,
      name: repo.name,
      clone_url: repo.clone_url,
      language: repo.language,
    }));
  }
}
