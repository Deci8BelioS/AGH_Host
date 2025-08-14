import requests, re

from regex import LIST_WHITELIST, DOMAIN_LIST

output_file = r'/home/runner/work/AGH_Host/AGH_Host/Filters/dnsmasq_lite.txt'

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
    line = line.replace('http://', '').replace('https://', '').replace('||', '').replace('|', '').replace('^', '').replace('local=', '').replace('/', '')
    return line

def filter_lines(lines):
    normal_domains = set()
    allowed_suffixes = {
        "r2.dev", "dweb.link", "aomg5bzv7.com", "startpage.com",
        "dbankedge.cn", "teemill.com", "ply.gg", "myportfolio.com",
        "webflow.io", "zapto.org"
    }
    for raw_line in lines:
        line = clean_line(raw_line)
        if not line or line.startswith(tuple(l1n3)):
            continue
        if "*" in line or ".." in line or "." not in line or line.endswith("."):
            continue
        for suffix in allowed_suffixes:
            if line.endswith(suffix):
                normal_domains.add(suffix)
                break
        else:
            normal_domains.add(line.strip())
    return normal_domains

def filter_domains_with_subdomains(domains_set):
    domain_pattern = re.compile(r'^([a-zA-Z0-9-]+\.[a-zA-Z]{2,8})$')
    subdomain_pattern = re.compile(r'^([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,8})$')
    main_domains = set()
    domains_with_subdomains = set()
    for domain in domains_set:
        domain = domain.strip()
        match_domain = domain_pattern.match(domain)
        match_subdomain = subdomain_pattern.match(domain)
        if match_domain:
            main_domain = match_domain.group(1)
            main_domains.add(main_domain)
        elif match_subdomain:
            subdomain = match_subdomain.group(1)
            main_domain = ".".join(subdomain.split(".")[-2:])
            domains_with_subdomains.add(main_domain)
    return main_domains.intersection(domains_with_subdomains)

unified_content = set()

urls = [
    'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext',
    'https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt',
    'https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/dnsmasq2_big.txt',
    'https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts'
]

for url in urls:
    print(f"Downloading from '{url}'...")
    lines = download_file(url)
    filtered_domains = filter_lines(lines)
    unified_content.update(filtered_domains)

domains_with_subdomains = filter_domains_with_subdomains(unified_content)

with open(output_file, 'w', encoding='utf-8') as f:
    for domain in sorted(unified_content):
        if domain.endswith(tuple(LIST_WHITELIST)) or not domain:
            continue
        if domain.endswith(tuple(DOMAIN_LIST)) and not domain.startswith(tuple(DOMAIN_LIST)) or not domain:
            continue
        if domain.endswith(tuple(domains_with_subdomains)) and not domain.startswith(tuple(domains_with_subdomains)) or not domain:
            continue
        if not domain.startswith(('||', '@@', '|', '<')) and not domain.endswith('^'):
            domain = f'{domain}'
        f.write(f"{domain}\n")

print(f"File '{output_file}' generated successfully.")
