import json
import subprocess
import sys

def run_trufflehog(repo_url):
    print(f"[*] A iniciar scan de segredos para: {repo_url}")
    try:
        result = subprocess.run(['trufflehog', 'git', repo_url, '--json', '--only-verified'], capture_output=True, text=True)
        findings = []
        for line in result.stdout.split('\n'):
            if line.strip():
                try:
                    finding = json.loads(line)
                    findings.append({
                        "id": finding.get('DetectorName'),
                        "type": "secret",
                        "severity": "critical",
                        "message": f"{finding.get('DetectorName')} encontrado",
                        "file": finding.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('file', 'N/A')
                    })
                except json.JSONDecodeError:
                    continue
        return findings
    except FileNotFoundError:
        print("[!] TruffleHog não encontrado. A retornar dados de MOCK.")
        return [{"id": "mock_1", "type": "secret", "severity": "critical", "message": "AWS_ACCESS_KEY_ID exposta"}]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python secrets_scan.py <repo_url>")
        sys.exit(1)
    print(json.dumps(run_trufflehog(sys.argv[1])))
