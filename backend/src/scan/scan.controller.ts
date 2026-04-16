import { Controller, Post, Get, Param, HttpException, HttpStatus } from '@nestjs/common';
import { ScanService } from './scan.service';

@Controller('api/scan')
export class ScanController {
  constructor(private readonly scanService: ScanService) {}

  // 1. Frontend chama esta rota passando o username
  @Post(':username')
  async startScan(@Param('username') username: string) {
    if (!username) {
      throw new HttpException('Username é obrigatório', HttpStatus.BAD_REQUEST);
    }

    try {
      // O serviço vai no GitHub, pega os repos e joga na fila do Redis
      const jobId = await this.scanService.queuePortfolioScan(username);
      
      // Retorna imediatamente para o frontend não ficar travado
      return { 
        message: 'Scan iniciado com sucesso', 
        jobId, 
        status: 'pending' 
      };
    } catch (error) {
      throw new HttpException(
        'Erro ao iniciar o scan. Verifique se o usuário existe.',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  // 2. Frontend faz "polling" (chamadas a cada X segundos) nesta rota
  @Get('result/:jobId')
  async getScanResult(@Param('jobId') jobId: string) {
    const result = await this.scanService.getJobResult(jobId);
    
    if (!result) {
      // Se não tem resultado ainda, avisa que está processando
      return { status: 'processing' };
    }

    // Se acabou, devolve o relatório completo!
    return { 
      status: 'completed', 
      report: result 
    };
  }
}
