import requests, re
from regex import LIST_WHITELIST, DOMAIN_LIST

l1n3 = ['#', '!', '-', '*', '/', '.', '&', '%', '~', '?', '[', ']', '^', ':', '@', '<', 'fe80::', 'ff00::', 'ff02::']

FILTER_CONFIGS = {
    'dnsmasq': {
        'output_file': r'/home/runner/work/AGH_Host/AGH_Host/Filters/dnsmasq.txt',
        'urls': [
            'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/light.txt',
            'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
            'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext',
            'https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt',
            'https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt',
            'https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/dnsmasq2_big.txt',
            'https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts',
            'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware',
            'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt',
            'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/hoster.txt',
            'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-vpn-proxy-bypass.txt',
            'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt',
            'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt'
        ]
    },
    'dnsmasq_small': {
        'output_file': r'/home/runner/work/AGH_Host/AGH_Host/Filters/dnsmasq_small.txt',
        'urls': [
            'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/light.txt',
            'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
            'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext',
            'https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt',
            'https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt',
            'https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/dnsmasq2_small.txt',
            'https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts',
            'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt',
            'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/hoster.txt',
            'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-vpn-proxy-bypass.txt',
            'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt',
            'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt'
        ]
    },
    'dnsmasq_lite': {
        'output_file': r'/home/runner/work/AGH_Host/AGH_Host/Filters/dnsmasq_lite.txt',
        'urls': [
            'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext',
            'https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt',
            'https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/dnsmasq2_small.txt',
            'https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts'
        ]
    }
}

download_cache = {}
processed_domains_cache = {}

def download_file(url):
    if url in download_cache:
        print(f"  ✓ Using cached version of '{url.split('/')[-1]}'")
        return download_cache[url]
    try:
        print(f"  ↓ Downloading '{url.split('/')[-1]}'...")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        lines = response.text.splitlines()
        download_cache[url] = lines
        return lines
    except requests.exceptions.RequestException as e:
        print(f"  ✗ Error downloading from '{url}': {e}")
        download_cache[url] = []
        return []

def is_valid_domain(domain):
    regex_chars = ['\\', '{', '}', '(', ')', '[', ']', '+', '?', '$']
    if any(char in domain for char in regex_chars):
        return False
    domain_pattern = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    return bool(domain_pattern.match(domain))

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
        if not is_valid_domain(line):
            continue
        for suffix in allowed_suffixes:
            if line.endswith(suffix):
                normal_domains.add(suffix)
                break
        else:
            normal_domains.add(line.strip())
    return normal_domains

def get_processed_domains(url):
    if url in processed_domains_cache:
        return processed_domains_cache[url]

    lines = download_file(url)
    domains = filter_lines(lines)
    processed_domains_cache[url] = domains
    return domains

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

def process_filter(filter_name, config):
    print(f"\n{'='*60}")
    print(f"Processing {filter_name}...")
    print(f"{'='*60}")
    unified_content = set()
    for url in config['urls']:
        domains = get_processed_domains(url)
        unified_content.update(domains)
    domains_with_subdomains = filter_domains_with_subdomains(unified_content)
    with open(config['output_file'], 'w', encoding='utf-8') as f:
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
    print(f"✓ File '{config['output_file']}' generated with {len(unified_content)} domains.")

def main():
    print("Starting unified dnsmasq filter generation with caching...")
    print(f"Total filter types to process: {len(FILTER_CONFIGS)}")
    all_urls = set()
    total_urls = 0
    for config in FILTER_CONFIGS.values():
        total_urls += len(config['urls'])
        all_urls.update(config['urls'])
    print(f"Total URLs to download (without cache): {total_urls}")
    print(f"Unique URLs (with cache): {len(all_urls)}")
    print(f"Cache efficiency: {(total_urls - len(all_urls))/total_urls*100:.1f}% reduction")
    for filter_name, config in FILTER_CONFIGS.items():
        process_filter(filter_name, config)
    print(f"\n{'='*60}")
    print(f"All filters generated successfully!")
    print(f"Downloads made: {len(download_cache)}")
    print(f"Downloads saved by cache: {total_urls - len(download_cache)}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
