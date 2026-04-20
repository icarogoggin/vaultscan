import json
import re
import sys

import requests

OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
REQUEST_TIMEOUT = 15


def progress(msg):
    print(f'PROGRESS: {msg}', file=sys.stderr, flush=True)


def parse_npm(content):
    try:
        data = json.loads(content)
        deps = {}
        for key in ('dependencies', 'devDependencies', 'peerDependencies'):
            deps.update(data.get(key, {}))
        return {
            name: re.sub(r'^[^\d]*', '', ver)
            for name, ver in deps.items()
            if re.sub(r'^[^\d]*', '', ver)
        }
    except Exception:
        return {}


def parse_requirements_txt(content):
    deps = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '-', '[')):
            continue
        m = re.match(r'^([A-Za-z0-9_\-\.]+)==([0-9][^\s;,]*)', line)
        if m:
            deps[m.group(1)] = m.group(2)
    return deps


def parse_go_mod(content):
    deps = {}
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith('require ('):
            in_require = True
            continue
        if in_require and line == ')':
            in_require = False
            continue
        if in_require or line.startswith('require '):
            clean = line.replace('require ', '').strip()
            m = re.match(r'^([\w\.\-/]+)\s+v?([0-9][^\s]+)', clean)
            if m:
                deps[m.group(1)] = m.group(2)
    return deps


def parse_gemfile_lock(content):
    deps = {}
    in_specs = False
    for line in content.splitlines():
        if line.strip() == 'specs:':
            in_specs = True
            continue
        if in_specs:
            m = re.match(r'^\s{4}([A-Za-z0-9_\-]+)\s+\(([0-9][^\)]*)\)', line)
            if m:
                deps[m.group(1)] = m.group(2)
            elif line.strip() == '' or (line and not line.startswith(' ')):
                in_specs = False
    return deps


def parse_cargo_toml(content):
    deps = {}
    in_deps = False
    for line in content.splitlines():
        line_s = line.strip()
        if line_s in ('[dependencies]', '[dev-dependencies]', '[build-dependencies]'):
            in_deps = True
            continue
        if line_s.startswith('[') and in_deps:
            in_deps = False
            continue
        if in_deps:
            m = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*"([0-9][^"]*)"', line_s)
            if m:
                deps[m.group(1)] = m.group(2)
            else:
                m2 = re.search(r'version\s*=\s*"([0-9][^"]*)"', line_s)
                name = re.match(r'^([A-Za-z0-9_\-]+)\s*=', line_s)
                if m2 and name:
                    deps[name.group(1)] = m2.group(1)
    return deps


def parse_composer_json(content):
    try:
        data = json.loads(content)
        deps = {}
        for key in ('require', 'require-dev'):
            for name, ver in data.get(key, {}).items():
                if name == 'php':
                    continue
                clean = re.sub(r'^[^\d]*', '', ver)
                if clean:
                    deps[name] = clean
        return deps
    except Exception:
        return {}


def query_osv(packages, ecosystem):
    if not packages:
        return {}
    pkg_names = list(packages.keys())
    queries = [
        {'package': {'name': name, 'ecosystem': ecosystem}, 'version': packages[name]}
        for name in pkg_names
    ]
    try:
        resp = requests.post(OSV_BATCH_URL, json={'queries': queries}, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return {}
        results = resp.json().get('results', [])
        return {
            pkg_names[i]: result.get('vulns', [])
            for i, result in enumerate(results)
            if result.get('vulns')
        }
    except Exception:
        return {}


def severity_from_vuln(vuln):
    for sev in vuln.get('severity', []):
        try:
            score = float(sev.get('score', ''))
            if score >= 9.0: return 'critical'
            if score >= 7.0: return 'high'
            if score >= 4.0: return 'medium'
            return 'low'
        except (ValueError, TypeError):
            pass
    for affected in vuln.get('affected', []):
        cvss = affected.get('database_specific', {}).get('cvss_score')
        if cvss:
            try:
                score = float(cvss)
                if score >= 9.0: return 'critical'
                if score >= 7.0: return 'high'
                if score >= 4.0: return 'medium'
                return 'low'
            except (ValueError, TypeError):
                pass
    return 'high'


def build_findings(pkg_name, version, vulns, filename):
    findings = []
    for vuln in vulns[:3]:
        aliases = vuln.get('aliases', [])
        cve_id = next((a for a in aliases if a.startswith('CVE-')), vuln.get('id', 'N/A'))
        findings.append({
            'id': cve_id,
            'type': 'cve',
            'severity': severity_from_vuln(vuln),
            'message': f'{pkg_name}@{version} — {vuln.get("summary", cve_id)}',
            'file': filename,
        })
    return findings


SCAN_TARGETS = [
    ('package.json',    ('main', 'master'), 'npm',       parse_npm),
    ('requirements.txt',('main', 'master'), 'PyPI',      parse_requirements_txt),
    ('go.mod',          ('main', 'master'), 'Go',        parse_go_mod),
    ('Gemfile.lock',    ('main', 'master'), 'RubyGems',  parse_gemfile_lock),
    ('Cargo.toml',      ('main', 'master'), 'crates.io', parse_cargo_toml),
    ('composer.json',   ('main', 'master'), 'Packagist', parse_composer_json),
]


def scan_dependencies(repo_url):
    raw_base = (
        repo_url
        .replace('github.com', 'raw.githubusercontent.com')
        .replace('.git', '')
    )

    findings = []

    for filename, branches, ecosystem, parser in SCAN_TARGETS:
        for branch in branches:
            try:
                progress(f'buscando {filename} ({branch})...')
                resp = requests.get(f'{raw_base}/{branch}/{filename}', timeout=8)
                if resp.status_code != 200:
                    continue

                packages = parser(resp.text)
                if not packages:
                    break

                progress(f'{filename}: {len(packages)} dep(s) | consultando OSV ({ecosystem})...')
                vuln_map = query_osv(packages, ecosystem)

                if vuln_map:
                    progress(f'{len(vuln_map)} pacote(s) vulnerável(is) em {filename}')

                for pkg, vulns in vuln_map.items():
                    findings.extend(build_findings(pkg, packages[pkg], vulns, filename))
                break
            except Exception:
                continue

    return findings


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps([]))
        sys.exit(0)
    print(json.dumps(scan_dependencies(sys.argv[1])))
