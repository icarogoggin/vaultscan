import json
import os
import re
import sys

import requests

REQUEST_TIMEOUT = 10


def progress(msg):
    print(f'PROGRESS: {msg}', file=sys.stderr, flush=True)


def extract_owner_repo(repo_url):
    m = re.match(r'https://github\.com/([^/]+)/([^/\.]+?)(?:\.git)?$', repo_url)
    return (m.group(1), m.group(2)) if m else (None, None)


def get_headers(token=None):
    h = {'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'reposcope'}
    if token:
        h['Authorization'] = f'token {token}'
    return h


def fetch_text(url, headers):
    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        return resp.text if resp.status_code == 200 else None
    except Exception:
        return None


_UNTRUSTED_EXPRS = re.compile(
    r'\$\{\{\s*(?:'
    r'github\.event\.(?:pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)|'
    r'issue\.(?:title|body)|comment\.body|review\.body|review_comment\.body|'
    r'discussion\.title|discussion\.body|pages\[\d+\]\.page_name|commits\[\d+\]\.message|'
    r'head_commit\.message)|'
    r'github\.head_ref'
    r')\s*\}\}'
)


def scan_workflow(content, filepath):
    findings = []

    if _UNTRUSTED_EXPRS.search(content):
        match = _UNTRUSTED_EXPRS.search(content).group(0)
        findings.append({
            'id': 'GHA-SCRIPT-INJECTION',
            'type': 'misconfiguration',
            'severity': 'high',
            'message': f'GitHub Actions: input não confiável "{match}" interpolado em step run — risco de injeção de código',
            'file': filepath,
        })

    if re.search(r'permissions\s*:\s*write-all', content, re.IGNORECASE):
        findings.append({
            'id': 'GHA-WRITE-ALL',
            'type': 'misconfiguration',
            'severity': 'medium',
            'message': 'GitHub Actions: permissions: write-all concede escrita desnecessária a todos os scopes',
            'file': filepath,
        })

    if 'pull_request_target' in content and re.search(r'ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head', content):
        findings.append({
            'id': 'GHA-PULL-REQUEST-TARGET',
            'type': 'misconfiguration',
            'severity': 'critical',
            'message': 'GitHub Actions: pull_request_target com checkout do head do PR — permite execução de código de forks com permissões de repositório',
            'file': filepath,
        })

    if re.search(r'on\s*:\s*\[?pull_request\b', content) and re.search(r'\$\{\{\s*secrets\.', content):
        findings.append({
            'id': 'GHA-SECRETS-IN-PR',
            'type': 'misconfiguration',
            'severity': 'medium',
            'message': 'GitHub Actions: secrets referenciados em trigger pull_request — podem ser expostos em PRs de forks',
            'file': filepath,
        })

    return findings


def scan_dockerfile(content, filepath):
    findings = []
    lines = content.splitlines()

    has_user = any(re.match(r'^\s*USER\s+(?!root\b)', ln, re.IGNORECASE) for ln in lines)
    has_root = any(re.match(r'^\s*USER\s+root\b', ln, re.IGNORECASE) for ln in lines)
    has_from = any(ln.strip().upper().startswith('FROM ') for ln in lines)

    if has_from and not has_user:
        findings.append({
            'id': 'DOCKER-NO-USER',
            'type': 'misconfiguration',
            'severity': 'medium',
            'message': 'Dockerfile sem diretiva USER — container executa como root por padrão',
            'file': filepath,
        })
    elif has_root:
        findings.append({
            'id': 'DOCKER-ROOT-USER',
            'type': 'misconfiguration',
            'severity': 'medium',
            'message': 'Dockerfile define USER root explicitamente',
            'file': filepath,
        })

    for ln in lines:
        m = re.match(r'^\s*FROM\s+([^\s]+)\s*(?:AS\s+\w+)?$', ln, re.IGNORECASE)
        if m:
            image = m.group(1)
            if image.lower() not in ('scratch', 'busybox') and (':' not in image or image.endswith(':latest')):
                findings.append({
                    'id': 'DOCKER-LATEST-TAG',
                    'type': 'misconfiguration',
                    'severity': 'low',
                    'message': f'Dockerfile usa imagem não fixada "{image}" — builds não reproduzíveis',
                    'file': filepath,
                })
                break

    return findings


def scan_compose(content, filepath):
    findings = []

    if re.search(r'privileged\s*:\s*true', content, re.IGNORECASE):
        findings.append({
            'id': 'COMPOSE-PRIVILEGED',
            'type': 'misconfiguration',
            'severity': 'high',
            'message': 'docker-compose: serviço com modo privilegiado — acesso total ao kernel do host',
            'file': filepath,
        })

    for m in re.finditer(
        r'(?:POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|MONGO_INITDB_ROOT_PASSWORD)\s*[=:]\s*["\']?(\w+)',
        content, re.IGNORECASE
    ):
        pwd = m.group(1)
        if pwd.lower() in ('password', 'root', 'admin', 'secret', '1234', '12345', 'changeme', 'pass', 'test'):
            findings.append({
                'id': 'COMPOSE-WEAK-PASSWORD',
                'type': 'misconfiguration',
                'severity': 'medium',
                'message': f'docker-compose: senha de banco de dados padrão/fraca detectada ("{pwd}")',
                'file': filepath,
            })

    return findings


_DEBUG_PATTERNS = [
    (r'(?:^|[\s;,])DEBUG\s*=\s*(?:True|1|true|yes|on)\b', 'DEBUG mode ativo'),
    (r'(?:^|[\s;,])APP_DEBUG\s*=\s*(?:true|1|True|yes)', 'APP_DEBUG ativo'),
    (r'(?:^|[\s;,])FLASK_DEBUG\s*=\s*[1Tt]', 'FLASK_DEBUG ativo'),
    (r'(?:^|[\s;,])NODE_ENV\s*=\s*development', 'NODE_ENV=development em ficheiro de configuração'),
]

_CORS_STAR = re.compile(
    r'(?i)(?:cors|Access-Control-Allow-Origin)[^=\n]*[=:]\s*["\']?\*'
)

_BINDING_ALL = re.compile(
    r'(?i)(?:HOST|BIND|listen)\s*[=:]\s*["\']?0\.0\.0\.0'
)


def scan_config_file(content, filepath):
    findings = []
    fname = filepath.lower()

    if any(x in fname for x in ('.example', '.sample', '.template', '.dist')):
        return findings

    for pattern, label in _DEBUG_PATTERNS:
        if re.search(pattern, content, re.MULTILINE):
            findings.append({
                'id': 'CONFIG-DEBUG-MODE',
                'type': 'misconfiguration',
                'severity': 'medium',
                'message': f'Configuração de debug ativa em produção: {label}',
                'file': filepath,
            })
            break

    if _CORS_STAR.search(content):
        findings.append({
            'id': 'CONFIG-CORS-STAR',
            'type': 'misconfiguration',
            'severity': 'medium',
            'message': 'CORS configurado com "*" — permite requisições de qualquer origem',
            'file': filepath,
        })

    return findings


def scan_misconfigurations(repo_url, token=None):
    owner, repo = extract_owner_repo(repo_url)
    if not owner:
        return []

    headers = get_headers(token)
    findings = []

    progress('verificando GitHub Actions workflows...')
    try:
        resp = requests.get(
            f'https://api.github.com/repos/{owner}/{repo}/contents/.github/workflows',
            headers=headers, timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            workflows = [f for f in resp.json() if isinstance(f, dict)
                         and os.path.splitext(f.get('name', ''))[1] in ('.yml', '.yaml')]
            for wf in workflows[:15]:
                progress(f'workflow: {wf["name"]}')
                content = fetch_text(wf['download_url'], headers)
                if content:
                    findings += scan_workflow(content, f'.github/workflows/{wf["name"]}')
    except Exception:
        pass

    for branch in ('main', 'master'):
        for dockerfile in ('Dockerfile', 'docker/Dockerfile', 'app/Dockerfile'):
            progress(f'verificando {dockerfile}...')
            raw = f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{dockerfile}'
            content = fetch_text(raw, headers)
            if content:
                findings += scan_dockerfile(content, dockerfile)
                break
        else:
            continue
        break

    for branch in ('main', 'master'):
        for fname in ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml'):
            content = fetch_text(
                f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{fname}',
                headers,
            )
            if content:
                progress(f'verificando {fname}...')
                findings += scan_compose(content, fname)
                break
        else:
            continue
        break

    config_targets = [
        '.env', '.env.production', '.env.staging',
        'config/settings.py', 'settings.py', 'config.py',
        'app/config.py', 'src/config.ts', 'src/config.js',
        'config/application.rb', 'config/environments/production.rb',
    ]
    for branch in ('main', 'master'):
        for cfg in config_targets:
            content = fetch_text(
                f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{cfg}',
                headers,
            )
            if content:
                progress(f'config: {cfg}')
                findings += scan_config_file(content, cfg)
        break

    return findings


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps([]))
        sys.exit(0)
    token = os.environ.get('GITHUB_TOKEN')
    print(json.dumps(scan_misconfigurations(sys.argv[1], token)))
