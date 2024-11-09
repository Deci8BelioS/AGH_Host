import requests, re

from regex import DOMAIN_WHITELIST, DOMAIN_WHITELIST2, DOMAIN_WHITELIST3

urls = [
    'https://raw.githubusercontent.com/celenityy/BadBlock/pages/wildcards-no-star/whitelist.txt',
    'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt'
]

unfiltered_urls = [
    'https://raw.githubusercontent.com/swetoast/adguardhome-lists/refs/heads/main/whitelist.txt'
]

output_file = r'/home/runner/work/AGH_Host/AGH_Host/AGH/filters/whitelist/whitelist.txt'

l1n3 = ['#', '!']
l1n3_2 = ['apple.com', 's3.amazonaws.com', 'wp.com', 'amazonaws.com']

def download_file(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text.splitlines()
    except requests.exceptions.RequestException as e:
        print(f"Error downloading '{url}': {e}")
        return []

def clean_line(line):
    line = line.strip()
    line = re.sub(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+', '', line)
    line = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '', line)
    line = re.sub(r'##.*', '', line)
    line = re.sub(r'#.*', '', line)
    line = re.sub(r'www\.', '', line)
    line = re.sub(r'\$.*$', '', line)
    line = line.replace('http://', '').replace('https://', '').replace('@@||', '').replace('^', '').replace('@@|', '')
    return line

def line_filter(lines):
    valid_domains = set()
    for line in lines:
        line = clean_line(line)
        if line.startswith(tuple(l1n3)) or not line:
            continue
        if line.startswith(tuple(l1n3_2)) or not line:
            continue
        valid_domains.add(line.strip())
    return valid_domains

def unfiltered_lines(lines):
    valid_domains = set()
    for line in lines:
        if line.startswith(tuple(l1n3)) or not line:
            continue
        line = line.strip()
        valid_domains.add(line.strip())
    return valid_domains

unified_content = set()

for url in urls:
    print(f"Downloading from '{url}'...")
    lines = download_file(url)
    filtered_domains = line_filter(lines)
    unified_content.update(filtered_domains)

for url in unfiltered_urls:
    print(f"Downloading from '{url}'...")
    lines = download_file(url)
    unfiltered_domains = unfiltered_lines(lines)
    unified_content.update(unfiltered_domains)

with open(output_file, 'w', encoding='utf-8') as f:
    for domain in sorted(unified_content):
        if domain.startswith(DOMAIN_WHITELIST3):
            continue
        if domain.endswith(tuple(DOMAIN_WHITELIST)) and not domain.startswith(tuple(DOMAIN_WHITELIST)) or not domain:
            continue
        if domain.endswith(tuple(DOMAIN_WHITELIST2)) and not domain.startswith(tuple(DOMAIN_WHITELIST2)) or not domain:
            continue
        if not domain.startswith(('||', '@@', '|', '@@/', '/')) and not domain.endswith('$important'):
            domain = f'@@||{domain}^$important'
        f.write(domain + '\n')

print(f"File '{output_file}' generated successfully.")
