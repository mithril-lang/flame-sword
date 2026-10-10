"""Network-free adapter for Flame Sword's original rule-based analyst."""
import json
import re
from FastAnalyst import FastSecurityAnalyst


def analyze_json(raw):
    if len(raw.encode('utf-8')) > 1024 * 1024:
        raise ValueError('Import must be smaller than 1 MiB.')
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError('Expected a Flame Sword JSON object.')
    domain = data.get('domain', '')
    if not isinstance(domain, str) or len(domain) > 253 or not re.fullmatch(
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}', domain
    ):
        raise ValueError('Enter a valid domain in the imported report.')
    domain = domain.lower()
    rows = data.get('subdomains')
    if not isinstance(rows, list) or len(rows) > 500:
        raise ValueError('Expected at most 500 subdomain observations.')
    clean = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Each observation must be an object.')
        host = row.get('subdomain', '')
        if not isinstance(host, str) or len(host) > 253 or not re.fullmatch(
            r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}', host
        ) or not (host.lower() == domain or host.lower().endswith('.' + domain)):
            raise ValueError('Every observed hostname must belong to the report domain.')
        item = {'subdomain': host.lower()}
        for field in ('http_status', 'https_status'):
            status = row.get(field)
            if status is not None and (type(status) is not int or not 100 <= status <= 599):
                raise ValueError('HTTP status must be an integer between 100 and 599, or null.')
            item[field] = status
        clean.append(item)
    result = FastSecurityAnalyst().analyze_subdomains(domain, clean)
    return json.dumps({
        'domain': domain, 'subdomains': clean, 'security_analysis': result,
        'execution': 'browser-pyodide', 'evidence': 'user-supplied observations',
        'limitations': [
            'No network scan was performed by this analysis.',
            'Hostname patterns and HTTP statuses are triage indicators, not verified vulnerabilities.',
            'DNS, port scans, origin discovery and TLS handshakes require the local Python tools.',
        ],
    })
