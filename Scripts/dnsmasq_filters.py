import requests, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from regex import LIST_WHITELIST, DOMAIN_LIST

l1n3 = tuple(['#', '!', '-', '*', '/', '.', '&', '%', '~', '?', '[', ']', '^', ':', '@', '<', 'fe80::', 'ff00::', 'ff02::'])

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

IP_PATTERN = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+')
IP_REMOVE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
COMMENT_HASH = re.compile(r'##.*')
COMMENT = re.compile(r'#.*')
WWW = re.compile(r'www\.')
DOLLAR = re.compile(r'\$.*$')
DOMAIN_PATTERN = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

LIST_WHITELIST_TUPLE = tuple(LIST_WHITELIST)
DOMAIN_LIST_TUPLE = tuple(DOMAIN_LIST)

# =========================
# DOWNLOAD
# =========================
def download_file(url):
    if url in download_cache:
        return download_cache[url]
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        lines = response.text.splitlines()
        download_cache[url] = lines
        return lines
    except requests.exceptions.RequestException:
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
    line = line.replace('http://','').replace('https://','').replace('||','').replace('|','').replace('^','').replace('local=','').replace('/','')
    return line.strip()

def is_valid_domain(domain):
    regex_chars = ['\\','{','}','(',')','[',']','+','?','$']
    if any(char in domain for char in regex_chars):
        return False
    return bool(DOMAIN_PATTERN.match(domain))

# =========================
# FILTER LINES
# =========================
def filter_lines(lines):
    normal_domains = set()
    allowed_suffixes = {"r2.dev","dweb.link","aomg5bzv7.com","startpage.com","dbankedge.cn",
                        "teemill.com","ply.gg","myportfolio.com","webflow.io","zapto.org"}
    for raw_line in lines:
        if '@@' in raw_line or raw_line.strip().startswith('@@'):
            continue
        line = clean_line(raw_line)
        if not line or line.startswith(l1n3):
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
            normal_domains.add(line)
    return normal_domains

def download_and_process(url):
    return filter_lines(download_file(url))

def get_processed_domains_parallel(urls, max_workers=5):
    all_domains = set()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(download_and_process,url): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                domains = future.result()
                all_domains.update(domains)
                processed_domains_cache[url] = domains
            except Exception:
                pass
    return all_domains

# =========================
# REMOVE SUBDOMAINS REDUNDANTES
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
            parent = parent[dot+1:]
            if parent in domains:
                redundant.add(domain)
                break
    return domains - redundant

# =========================
# PROCESS FILTER
# =========================
def process_filter(filter_name, config):
    print(f"Processing {filter_name}...")
    unified_content = get_processed_domains_parallel(config['urls'])
    print(f"  Total before dedup: {len(unified_content)}")
    unified_content = remove_redundant_subdomains(unified_content)
    print(f"  Total after dedup: {len(unified_content)}")
    filtered_count = 0
    valid_domains = []
    for domain in sorted(unified_content):
        if not domain:
            filtered_count += 1
            continue
        if domain.endswith(LIST_WHITELIST_TUPLE):
            filtered_count += 1
            continue
        if domain.endswith(DOMAIN_LIST_TUPLE) and not domain.startswith(DOMAIN_LIST_TUPLE):
            filtered_count += 1
            continue
        valid_domains.append(domain)
    with open(config['output_file'],'w',encoding='utf-8') as f:
        f.write('\n'.join(valid_domains)+'\n')
    print(f"  Written: {len(valid_domains)} domains, filtered out: {filtered_count}")
    print(f"  File: {config['output_file']}")

# =========================
# MAIN
# =========================
def main():
    print("Starting unified dnsmasq filter generation with caching...")
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

if __name__ == "__main__":
    main()