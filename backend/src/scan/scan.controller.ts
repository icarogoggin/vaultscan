import { Controller, Post, Get, Param, HttpException, HttpStatus } from '@nestjs/common';
import { ScanService } from './scan.service';

@Controller('api/scan')
export class ScanController {
  constructor(private readonly scanService: ScanService) {}

  @Post(':username')
  async startScan(@Param('username') username: string) {
    if (!username) {
      throw new HttpException('Username é obrigatório', HttpStatus.BAD_REQUEST);
    }
    try {
      const jobId = await this.scanService.queuePortfolioScan(username);
      return { message: 'Scan iniciado com sucesso', jobId, status: 'pending' };
    } catch (error) {
      throw new HttpException(
        error.message || 'Erro ao iniciar o scan. Verifique se o usuário existe.',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('result/:jobId')
  async getScanResult(@Param('jobId') jobId: string) {
    const job = this.scanService.getJob(jobId);
    if (!job) return { status: 'processing' };
    if (job.status === 'completed') return { status: 'completed', report: job.data };
    return { status: 'processing', progress: job.data };
  }
}
