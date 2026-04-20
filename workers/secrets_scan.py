import json
import os
import re
import subprocess
import sys

import requests

SECRET_PATTERNS = [
    (r'(?i)aws_access_key_id\s*[=:]\s*["\']?([A-Z0-9]{20})', 'AWS Access Key ID', 'critical'),
    (r'(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', 'AWS Secret Access Key', 'critical'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key (inline)', 'critical'),
    (r'"type"\s*:\s*"service_account"', 'GCP Service Account Key', 'critical'),
    (r'(?i)azure[_\-]?storage[_\-]?(?:account[_\-]?)?key\s*[=:]\s*["\']?([A-Za-z0-9+/=]{44,})', 'Azure Storage Key', 'critical'),
    (r'(?i)azure[_\-]?connection[_\-]?string\s*[=:]\s*["\']?DefaultEndpointsProtocol', 'Azure Connection String', 'critical'),

    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |)PRIVATE KEY', 'Private Key', 'critical'),
    (r'-----BEGIN CERTIFICATE-----', 'Certificate (possible private cert)', 'medium'),

    (r'ghp_[A-Za-z0-9]{36}', 'GitHub Personal Access Token', 'critical'),
    (r'gho_[A-Za-z0-9]{36}', 'GitHub OAuth Token', 'critical'),
    (r'ghs_[A-Za-z0-9]{36}', 'GitHub App Token', 'critical'),
    (r'github_pat_[A-Za-z0-9_]{82}', 'GitHub Fine-grained PAT', 'critical'),
    (r'sk_live_[A-Za-z0-9]{24,}', 'Stripe Live Secret Key', 'critical'),
    (r'rk_live_[A-Za-z0-9]{24,}', 'Stripe Restricted Key (live)', 'critical'),
    (r'sk_test_[A-Za-z0-9]{24,}', 'Stripe Test Secret Key', 'high'),
    (r'AC[a-z0-9]{32}\b', 'Twilio Account SID', 'high'),
    (r'SK[a-z0-9]{32}\b', 'Twilio API Key', 'critical'),
    (r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}', 'SendGrid API Key', 'critical'),
    (r'xox[baprs]-[A-Za-z0-9\-]{10,}', 'Slack Token', 'critical'),
    (r'hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+', 'Slack Webhook', 'high'),
    (r'discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+', 'Discord Webhook', 'high'),
    (r'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}', 'Firebase Cloud Messaging Key', 'high'),
    (r'AIza[0-9A-Za-z_\-]{35}', 'Google API Key', 'high'),
    (r'ya29\.[0-9A-Za-z_\-]+', 'Google OAuth Access Token', 'critical'),
    (r'(?i)mailgun[_\-]?(?:api[_\-]?)?key\s*[=:]\s*["\']?(key-[A-Za-z0-9]{32})', 'Mailgun API Key', 'critical'),
    (r'(?i)netlify[_\-]?(?:auth[_\-]?)?token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40,})', 'Netlify Token', 'critical'),
    (r'npat_[A-Za-z0-9]{36}', 'npm Access Token', 'critical'),
    (r'pypi-[A-Za-z0-9_\-]{40,}', 'PyPI Token', 'critical'),
    (r'(?i)vercel[_\-]?token\s*[=:]\s*["\']?([A-Za-z0-9]{24,})', 'Vercel Token', 'critical'),
    (r'(?i)heroku[_\-]?api[_\-]?key\s*[=:]\s*["\']?([a-f0-9\-]{36})', 'Heroku API Key', 'critical'),
    (r'(?i)digitalocean[_\-]?(?:access[_\-]?)?token\s*[=:]\s*["\']?([A-Za-z0-9]{64})', 'DigitalOcean Token', 'critical'),
    (r'(?i)datadog[_\-]?api[_\-]?key\s*[=:]\s*["\']?([a-f0-9]{32})', 'Datadog API Key', 'high'),
    (r'(?i)sentry[_\-]?(?:auth[_\-]?)?token\s*[=:]\s*["\']?([a-f0-9]{64})', 'Sentry Auth Token', 'high'),
    (r'xapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+', 'Slack App Token', 'critical'),

    (r'ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', 'JWT Token (hardcoded)', 'high'),

    (r'(?i)(?:db|database)[_\-]?(?:pass(?:word)?|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', 'Database Password', 'high'),
    (r'(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', 'API Key', 'high'),
    (r'(?i)(?:secret[_\-]?key|app[_\-]?secret)\s*[=:]\s*["\']([^"\']{8,})["\']', 'Application Secret', 'medium'),
    (r'(?i)(?:password|passwd)\s*[=:]\s*["\']([^"\'$%@]{8,})["\']', 'Hardcoded Password', 'high'),
    (r'(?i)(?:private[_\-]?key|priv[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9+/=]{32,})["\']', 'Private Key Value', 'critical'),
]

SCAN_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
    '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
    '.sh', '.bash', '.zsh', '.tf', '.tfvars',
    '.rb', '.php', '.java', '.go', '.cs', '.cpp', '.c',
    '.env', '.json', '.xml', '.properties',
}

HIGH_VALUE_FILENAMES = {
    '.env', '.env.local', '.env.production', '.env.development',
    'credentials', 'credentials.json', 'serviceaccount.json',
    'config.py', 'settings.py', 'secrets.py',
    'id_rsa', 'id_ed25519', 'id_dsa',
}

SKIP_DIRS = {'node_modules', 'vendor', '.git', '__pycache__', 'dist', 'build', '.next', 'coverage'}

MAX_FILE_SIZE = 120_000
MAX_FILES_SCANNED = 80


def progress(msg):
    print(f'PROGRESS: {msg}', file=sys.stderr, flush=True)


def extract_owner_repo(repo_url):
    match = re.match(r'https://github\.com/([^/]+)/([^/\.]+?)(?:\.git)?$', repo_url)
    if match:
        return match.group(1), match.group(2)
    return None, None


def should_scan(item):
    path = item['path']
    parts = path.split('/')
    if any(d in SKIP_DIRS for d in parts[:-1]):
        return False
    filename = parts[-1].lower()
    ext = os.path.splitext(filename)[1]
    return (
        ext in SCAN_EXTENSIONS
        or filename in HIGH_VALUE_FILENAMES
        or filename.startswith('.env')
    )


def scan_content(content, path):
    findings = []
    seen_labels = set()
    for pattern, label, severity in SECRET_PATTERNS:
        if label in seen_labels:
            continue
        if re.search(pattern, content):
            seen_labels.add(label)
            findings.append({
                'id': f'{label.upper().replace(" ", "_")}_{path}',
                'type': 'secret',
                'severity': severity,
                'message': f'{label} detectado',
                'file': path,
            })
    return findings


def scan_with_github_api(owner, repo, token=None):
    headers = {'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'reposcope'}
    if token:
        headers['Authorization'] = f'token {token}'

    try:
        repo_resp = requests.get(
            f'https://api.github.com/repos/{owner}/{repo}',
            headers=headers, timeout=10,
        )
        if repo_resp.status_code != 200:
            return []
        default_branch = repo_resp.json().get('default_branch', 'main')

        progress(f'obtendo árvore de ficheiros ({default_branch})...')
        tree_resp = requests.get(
            f'https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1',
            headers=headers, timeout=10,
        )
        if tree_resp.status_code != 200:
            return []

        tree = tree_resp.json().get('tree', [])
        scannable = [
            item for item in tree
            if item['type'] == 'blob'
            and item.get('size', 0) <= MAX_FILE_SIZE
            and should_scan(item)
        ]

        limit = min(len(scannable), MAX_FILES_SCANNED)
        progress(f'{limit}/{len(scannable)} ficheiro(s) elegíveis a analisar...')

        findings = []
        for i, item in enumerate(scannable[:limit]):
            path_str = item['path']
            progress(f'[{i+1}/{limit}] {path_str}')
            try:
                raw_url = (
                    f'https://raw.githubusercontent.com/{owner}/{repo}'
                    f'/{default_branch}/{path_str}'
                )
                resp = requests.get(raw_url, headers=headers, timeout=8)
                if resp.status_code == 200:
                    findings.extend(scan_content(resp.text, path_str))
            except Exception:
                continue

        return findings

    except Exception:
        return []


def run_trufflehog(repo_url):
    try:
        progress('executando TruffleHog...')
        result = subprocess.run(
            ['trufflehog', 'git', repo_url, '--json', '--only-verified'],
            capture_output=True, text=True, timeout=120,
        )
        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                f = json.loads(line)
                findings.append({
                    'id': f.get('DetectorName', 'unknown'),
                    'type': 'secret',
                    'severity': 'critical',
                    'message': f"{f.get('DetectorName', 'Secret')} detectado",
                    'file': (
                        f.get('SourceMetadata', {})
                        .get('Data', {}).get('Git', {}).get('file', 'N/A')
                    ),
                })
            except json.JSONDecodeError:
                continue
        return findings
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return []


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps([]))
        sys.exit(0)

    repo_url = sys.argv[1]
    token = os.environ.get('GITHUB_TOKEN')

    findings = run_trufflehog(repo_url)
    if findings is None:
        progress('TruffleHog não instalado — usando scanner por padrões...')
        owner, repo = extract_owner_repo(repo_url)
        findings = scan_with_github_api(owner, repo, token) if owner else []

    print(json.dumps(findings))
