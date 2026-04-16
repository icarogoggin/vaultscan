import json
import sys
import requests
import re

def scan_dependencies(repo_url):
    # Converter clone_url para raw github URL (ex: https://github.com/user/repo -> https://raw.githubusercontent.com/user/repo/main/package.json)
    # Nota: Assumindo branch 'main' ou 'master' para simplificar
    raw_url_base = repo_url.replace("github.com", "raw.githubusercontent.com").replace(".git", "")
    
    findings = []
    
    for branch in ["main", "master"]:
        try:
            package_url = f"{raw_url_base}/{branch}/package.json"
            response = requests.get(package_url, timeout=5)
            if response.status_code == 200:
                package_data = response.json()
                deps = {**package_data.get("dependencies", {}), **package_data.get("devDependencies", {})}
                
                # Mock de vulnerabilidades conhecidas para demonstração
                vulnerable_pkgs = {
                    "jsonwebtoken": "8.5.1",
                    "lodash": "4.17.20",
                    "axios": "0.21.1"
                }
                
                for pkg, version in deps.items():
                    if pkg in vulnerable_pkgs:
                        findings.append({
                            "id": f"CVE-{pkg}",
                            "type": "cve",
                            "severity": "high",
                            "message": f"Versão vulnerável de {pkg} encontrada ({version})",
                            "file": "package.json"
                        })
                break # Encontrou o package.json, para de procurar em outras branches
        except Exception:
            continue
            
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    print(json.dumps(scan_dependencies(sys.argv[1])))
