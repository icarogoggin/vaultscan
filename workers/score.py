import sys
import json

def calculate_score(findings_json):
    findings = json.loads(findings_json)
    base_score = 100
    
    for finding in findings:
        severity = finding.get('severity', 'low').lower()
        if severity == 'critical':
            base_score -= 25
        elif severity == 'high':
            base_score -= 15
        elif severity == 'medium':
            base_score -= 5
        elif severity == 'low':
            base_score -= 2
            
    return max(0, base_score)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    print(calculate_score(sys.argv[1]))
