import requests, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from regex import REGEX, LIST_WHITELIST, DOMAIN_LIST, SUBDOMAIN_PATTERNS, REGEX_WHITELIST

l1n3 = tuple(['#', '!', '-', '*', '/', '.', '&', '%', '~', '?', '[', ']', '^', ':', '@', '<', 'fe80::', 'ff00::', 'ff02::'])

FILTER_CONFIGS = {
    'AGH_Host_Plus': {
        'output_file': r'/home/runner/work/AGH_Host/AGH_Host/Filters/AGH_Host+.txt',
        'urls': [
            'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/light.txt',
            'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
            'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext',
            'https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt',
            'https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt',
            'https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/oisd_big.txt',
            'https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts',
            'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware',
            'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt',
            'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt',
            'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-vpn-proxy-bypass.txt',
            'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds.txt',
            'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt',
            'https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt'
        ]
    },
    'AGH_Host': {
        'output_file': r'/home/runner/work/AGH_Host/AGH_Host/Filters/AGH_Host.txt',
        'urls': [
            'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/light.txt',
            'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
            'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext',
            'https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt',
            'https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt',
            'https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/oisd_small.txt',
            'https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts'
        ]
    }
}

download_cache = {}
processed_domains_cache = {}

IP_PATTERN = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+')
IP_REMOVE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
COMMENT_HASH = re.compile(r'##.*')
COMMENT = re.compile(r'#.*')
WWW = re.compile(r'www\.')
DOLLAR = re.compile(r'\$.*$')

REGEX_WHITELIST_TUPLE = tuple(REGEX_WHITELIST)
LIST_WHITELIST_TUPLE = tuple(LIST_WHITELIST)
DOMAIN_LIST_TUPLE = tuple(DOMAIN_LIST)
SUBDOMAIN_ITEMS = list(SUBDOMAIN_PATTERNS.items())

# =========================
# DOWNLOAD
# =========================

def download_file(url):
    if url in download_cache:
        print(f"  ✓ Using cached '{url.split('/')[-1]}'")
        return download_cache[url]
    try:
        print(f"  ↓ Downloading '{url.split('/')[-1]}'...", flush=True)
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        lines = response.text.splitlines()
        download_cache[url] = lines
        return lines
    except requests.exceptions.RequestException as e:
        print(f"  ✗ Error downloading '{url}': {e}")
        download_cache[url] = []
        return []


# =========================
# CLEAN LINE
# =========================

def clean_line(line):
    line = line.strip().lower()
    line = IP_PATTERN.sub('', line)
    line = IP_REMOVE.sub('', line)
    line = COMMENT_HASH.sub('', line)
    line = COMMENT.sub('', line)
    line = WWW.sub('', line)
    line = DOLLAR.sub('', line)
    line = line.replace('http://', '').replace('https://', '').replace('||', '').replace('|', '').replace('^', '')
    return line.strip()


# =========================
# FILTER LINES
# =========================

def filter_lines(lines):
    normal_domains = set()
    for raw_line in lines:
        if '@@' in raw_line:
            continue
        line = clean_line(raw_line)
        if not line or line.startswith(l1n3):
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
        for subdomain, pattern in SUBDOMAIN_ITEMS:
            if line.startswith(subdomain):
                normal_domains.add(f"{subdomain}{pattern}")
                break
        else:
            normal_domains.add(line)
    return normal_domains

def download_and_process(url):
    lines = download_file(url)
    return filter_lines(lines)


# =========================
# PARALLEL
# =========================

def get_processed_domains_parallel(urls, max_workers=5):
    all_domains = set()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(download_and_process, url): url
            for url in urls
        }
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                domains = future.result()
                all_domains.update(domains)
                processed_domains_cache[url] = domains
            except Exception as exc:
                print(f'  ✗ {url} exception: {exc}')
    return all_domains


# =========================
# REMOVE REDUNDANT SUBDOMAINS (OPTIMIZED)
# =========================

def remove_redundant_subdomains(domains_set):
    domains = set(d.strip() for d in domains_set if d.strip())
    redundant = set()
    for domain in domains:
        parent = domain
        while True:
            dot = parent.find('.')
            if dot == -1:
                break
            parent = parent[dot + 1:]
            if parent in domains:
                redundant.add(domain)
                break
    return domains - redundant

# =========================
# PROCESS FILTER
# =========================

def process_filter(filter_name, config):
    print(f"\n{'='*60}")
    print(f"Processing {filter_name}...")
    print(f"{'='*60}")
    unified_content = get_processed_domains_parallel(config['urls'])
    print(f" ✓ Total domains before dedup: {len(unified_content)}")
    unified_content = remove_redundant_subdomains(unified_content)
    print(f" ✓ After dedup: {len(unified_content)}")
    filtered_count = 0
    valid_domains = []
    for domain in sorted(unified_content):
        if not domain:
            filtered_count += 1
            continue
        if any(pattern.search(domain) for pattern in REGEX):
            filtered_count += 1
            continue
        if domain.endswith(REGEX_WHITELIST_TUPLE):
            filtered_count += 1
            continue
        if domain.endswith(LIST_WHITELIST_TUPLE):
            filtered_count += 1
            continue
        if domain.endswith(DOMAIN_LIST_TUPLE) and not domain.startswith(DOMAIN_LIST_TUPLE):
            filtered_count += 1
            continue
        if not domain.startswith(('||', '@@', '|', '<')) and not domain.endswith('^'):
            domain = f'||{domain}^'
        valid_domains.append(domain)
    with open(config['output_file'], 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid_domains) + '\n')
    written_count = len(valid_domains)
    print(f" ✓ Final domains written: {written_count}")
    print(f" ✓ Domains filtered out: {filtered_count}")
    print(f" ✓ File generated: {config['output_file']}")

# =========================
# MAIN
# =========================

def main():
    print("Starting unified AdGuard Home filter generation with caching...")
    print(f"Total filter types: {len(FILTER_CONFIGS)}")
    all_urls = set()
    total_urls = 0
    for config in FILTER_CONFIGS.values():
        total_urls += len(config['urls'])
        all_urls.update(config['urls'])
    print(f"\n{'='*60}")
    print("Cache Statistics:")
    print(f"{'='*60}")
    print(f"Total URLs (raw): {total_urls}")
    print(f"Unique URLs: {len(all_urls)}")
    print(f"Cache efficiency: {(total_urls - len(all_urls)) / total_urls * 100:.1f}%")
    for filter_name, config in FILTER_CONFIGS.items():
        process_filter(filter_name, config)
    print(f"\n{'='*60}")
    print("All filters generated successfully!")
    print(f"{'='*60}")
    print(f"Downloads made: {len(download_cache)}")
    print(f"Downloads saved by cache: {total_urls - len(download_cache)}")
    print(f"{'='*60}")

# =========================
# ENTRY
# =========================

if __name__ == "__main__":
    main()