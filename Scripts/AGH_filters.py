import requests, re

from regex import REGEX, LIST_WHITELIST, DOMAIN_LIST, SUBDOMAIN_PATTERNS

output_file = r'/home/runner/work/AGH_Host/AGH_Host/Filters/AGH_Host.txt'

l1n3 = ['#', '!', '-', '*', '/', '.', '&', '%', '~', '?', '[', ']', '^', ':', '@', '<', 'fe80::', 'ff00::', 'ff02::']

def download_file(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text.splitlines()
    except requests.exceptions.RequestException as e:
        print(f"Error downloading from '{url}': {e}")
        return []

def clean_line(line):
    line = line.strip()
    line = re.sub(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+', '', line)
    line = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '', line)
    line = re.sub(r'##.*', '', line)
    line = re.sub(r'#.*', '', line)
    line = re.sub(r'www\.', '', line)
    line = re.sub(r'\$.*$', '', line)
    line = line.replace('http://', '').replace('https://', '').replace('||', '').replace('|', '').replace('^', '')
    return line

def filter_lines(lines):
    normal_domains = set()
    for line in lines:
        line = clean_line(line)
        if line.startswith(tuple(l1n3)) or not line:
            continue
        if line.endswith("r2.dev"):
            normal_domains.add("*.r2.dev")
            continue
        if line.endswith("dweb.link"):
            normal_domains.add("dweb.link")
            continue
        if line.endswith("aomg5bzv7.com"):
            normal_domains.add("aomg5bzv7.com")
            continue
        for subdomain, pattern in SUBDOMAIN_PATTERNS.items():
            if line.startswith(subdomain):
                normal_domains.add(f"{subdomain}{pattern}")
                break
        else:
            normal_domains.add(line.strip())
    return normal_domains

unified_content = set()

urls = [
    'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/light.txt',
    'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
    'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext',
    'https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt',
    'https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt',
    'https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/oisd_small.txt',
    'https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts'
]

for url in urls:
    print(f"Downloading from '{url}'...")
    lines = download_file(url)
    filtered_domains = filter_lines(lines)
    unified_content.update(filtered_domains)

with open(output_file, 'w', encoding='utf-8') as f:
    for domain in sorted(unified_content):
        if any(pattern.search(domain) for pattern in REGEX) or not domain:
            continue
        if domain.endswith(tuple(LIST_WHITELIST)) or not domain:
            continue
        if domain.endswith(tuple(DOMAIN_LIST)) and not domain.startswith(tuple(DOMAIN_LIST)) or not domain:
            continue
        if not domain.startswith(('||', '@@', '|', '<')) and not domain.endswith('^'):
            domain = f'||{domain}^'
        f.write(f"{domain}\n")

print(f"File '{output_file}' generated successfully.")
