import json
import sys

SEVERITY_WEIGHTS = {
    'critical': 25,
    'high': 15,
    'medium': 5,
    'low': 2,
}


def calculate_score(findings):
    score = 100
    for finding in findings:
        severity = finding.get('severity', 'low').lower()
        score -= SEVERITY_WEIGHTS.get(severity, 0)
    return max(0, score)


if __name__ == '__main__':
    try:
        data = sys.stdin.read().strip()
        findings = json.loads(data)
        print(calculate_score(findings))
    except Exception:
        print(100)
