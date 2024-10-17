import requests, re

from regex import REGEX, LIST_WHITELIST, DOMAIN_LIST, SUBDOMAIN_DUPLICATE, SUBDOMAIN_DUPLICATE2, SUBDOMAIN_DUPLICATE3, SUBDOMAIN_DUPLICATE4, SUBDOMAIN_DUPLICATE5

output_file = r'hosts.txt'
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
        if line.startswith(f"{SUBDOMAIN_DUPLICATE}"):
            normal_domains.add(f"{SUBDOMAIN_DUPLICATE}*.*")
            continue
        if line.endswith(f"{SUBDOMAIN_DUPLICATE2}"):
            normal_domains.add(f"*.{SUBDOMAIN_DUPLICATE2}")
            continue
        if line.startswith(f"{SUBDOMAIN_DUPLICATE3}"):
            normal_domains.add(f"{SUBDOMAIN_DUPLICATE3}*.eu")
            continue
        if line.endswith(f"{SUBDOMAIN_DUPLICATE4}"):
            normal_domains.add(f"{SUBDOMAIN_DUPLICATE4}")
            continue
        if line.startswith(f"{SUBDOMAIN_DUPLICATE5}"):
            normal_domains.add(f"{SUBDOMAIN_DUPLICATE5}*")
            continue
        normal_domains.add(line.strip())
    return normal_domains

unified_content = set()

file_exceptions = r"/home/runner/work/AGH_Host/AGH_Host/AGH/filters/whitelist/whitelist.txt"
print(f"Reading from exception file: {file_exceptions}...\n")
with open(file_exceptions, 'r', encoding='utf-8') as file:
    exceptions = [line.strip() for line in file]

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
        if domain.startswith('@@'):
            domain = f'{domain}^'.replace('|^', '^|')
        if not domain.startswith('||') and not domain.startswith('@@') and not domain.startswith('|') and not domain.startswith('<'):
            domain = f'||{domain}'
        if not domain.endswith('^') and not domain.endswith('^|') and not domain.endswith('^$important') and not domain.startswith('<'):
            domain = f'{domain}^'.replace('$important^', '^$important')
        f.write(f"{domain}\n")

print(f"File '{output_file}' generated successfully.")
