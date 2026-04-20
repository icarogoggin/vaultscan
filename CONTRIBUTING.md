# Guia de Contribuição

Obrigado pelo interesse em contribuir com o VaultScan! Este documento explica como participar do projeto de forma organizada.

---

## Código de conduta

Seja respeitoso. Críticas técnicas são bem-vindas; ataques pessoais não.

---

## Como reportar um bug

Use o template de **Bug report** nas [Issues](../../issues/new/choose). Inclua:

- Sistema operacional e versões do Node.js e Python
- Passos exatos para reproduzir
- O que você esperava e o que aconteceu
- Logs relevantes do terminal

---

## Como sugerir uma melhoria

Use o template de **Feature request** nas [Issues](../../issues/new/choose). Descreva o problema que a feature resolve, não apenas o que você quer. Propostas bem justificadas têm muito mais chance de serem aceitas.

---

## Fluxo para contribuir com código

```
1. Abra (ou comente em) uma issue antes de começar
2. Aguarde sinalização do mantenedor (evita trabalho duplicado)
3. Fork → branch → código → PR
```

### 1. Fork e clone

```bash
git clone https://github.com/SEU_USUARIO/vaultscan
cd vaultscan
git remote add upstream https://github.com/icarogoggin/vaultscan
```

### 2. Crie uma branch

Use prefixos descritivos:

| Tipo | Exemplo |
|------|---------|
| Nova funcionalidade | `feat/suporte-gitlab` |
| Correção de bug | `fix/timeout-no-scan` |
| Documentação | `docs/tutorial-docker` |
| Refatoração | `refactor/workers-async` |

```bash
git checkout -b feat/minha-feature
```

### 3. Desenvolva

- **Backend (NestJS/TypeScript):** mantenha os tipos corretos, sem `any` desnecessário
- **Workers (Python):** todo output de progresso vai para `stderr` (`print(..., file=sys.stderr)`); o `stdout` é reservado para JSON
- **Frontend (React):** componentes simples, sem bibliotecas novas sem aprovação prévia
- **Commits:** use [Conventional Commits](https://www.conventionalcommits.org/pt-br/): `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`

### 4. Abra o Pull Request

- Título claro e em português ou inglês
- Descreva **o que** foi feito e **por que**
- Se resolver uma issue, mencione: `Closes #42`
- PRs sem descrição podem ser fechados sem revisão

---

## Onde focar as contribuições

Veja o [Roadmap](README.md#%EF%B8%8F-roadmap) no README para as áreas mais prioritárias. Issues marcadas com `good first issue` são ideais para quem está começando.

---

## Estrutura do projeto

```
vaultscan/
├── backend/          # API NestJS + fila Bull
│   └── src/
│       └── scan/     # Controller, Service e Processor
├── frontend/         # React + Vite + Tailwind
│   └── src/
├── workers/          # Scripts Python invocados pelo Processor
│   ├── secrets_scan.py
│   ├── deps_scan.py
│   ├── misconfig_scan.py
│   └── score.py
├── docs/             # Imagens e assets para documentação
└── docker-compose.yml
```

---

## Propriedade e licença

Este projeto é de autoria de **Ícaro Goggin** e está licenciado sob a [MIT License](LICENSE).

Ao enviar uma contribuição (código, documentação, tradução etc.), você concorda que:

1. Sua contribuição é original e você tem o direito de licenciá-la
2. Ela passa a integrar este projeto sob os termos da licença MIT
3. A titularidade e autoria do projeto permanecem com o mantenedor original

Suas contribuições serão devidamente reconhecidas nos commits e no histórico do projeto.

---

## Dúvidas?

Abra uma [Discussion](../../discussions) ou uma issue com a tag `question`.
