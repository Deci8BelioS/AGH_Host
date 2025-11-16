import requests, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from regex import DOMAIN_WHITELIST, DOMAIN_WHITELIST2, DOMAIN_WHITELIST3

urls = [
    'https://raw.githubusercontent.com/celenityy/BadBlock/pages/wildcards-no-star/whitelist.txt',
    'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt'
]

unfiltered_urls = [
    'https://raw.githubusercontent.com/swetoast/adguardhome-lists/refs/heads/main/whitelist.txt'
]

output_file = r'/home/runner/work/AGH_Host/AGH_Host/Filters/whitelist/whitelist.txt'

l1n3 = tuple(['#', '!'])
l1n3_2 = tuple(['apple.com', 's3.amazonaws.com', 'wp.com', 'amazonaws.com'])

IP_PATTERN = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+')
IP_REMOVE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
COMMENT_HASH = re.compile(r'##.*')
COMMENT = re.compile(r'#.*')
WWW = re.compile(r'www\.')
DOLLAR = re.compile(r'\$.*$')

DOMAIN_WHITELIST_TUPLE = tuple(DOMAIN_WHITELIST)
DOMAIN_WHITELIST2_TUPLE = tuple(DOMAIN_WHITELIST2)

download_cache = {}

def download_file(url):
    if url in download_cache:
        print(f"  ✓ Using cached version of '{url.split('/')[-1]}'")
        return download_cache[url]
    try:
        print(f"  ↓ Downloading '{url.split('/')[-1]}'...", flush=True)
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        lines = response.text.splitlines()
        download_cache[url] = lines
        return lines
    except requests.exceptions.RequestException as e:
        print(f"  ✗ Error downloading from '{url}': {e}")
        download_cache[url] = []
        return []

def clean_line(line):
    line = line.strip()
    line = IP_PATTERN.sub('', line)
    line = IP_REMOVE.sub('', line)
    line = COMMENT_HASH.sub('', line)
    line = COMMENT.sub('', line)
    line = WWW.sub('', line)
    line = DOLLAR.sub('', line)
    line = line.replace('http://', '').replace('https://', '').replace('@@||', '').replace('^', '').replace('@@|', '')
    return line

def line_filter(lines):
    valid_domains = set()
    for raw_line in lines:
        line = clean_line(raw_line)
        if line.endswith("ntp.org"):
            valid_domains.add("ntp.org")
            continue
        if not line or line.startswith(l1n3):
            continue
        if line.startswith(l1n3_2):
            continue
        valid_domains.add(line.strip())
    return valid_domains

def unfiltered_lines(lines):
    valid_domains = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith(l1n3):
            continue
        valid_domains.add(line)
    return valid_domains

def download_and_process_filtered(url):
    lines = download_file(url)
    return line_filter(lines)

def download_and_process_unfiltered(url):
    lines = download_file(url)
    return unfiltered_lines(lines)

def process_urls_parallel(url_list, process_func, max_workers=5):
    all_domains = set()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(process_func, url): url for url in url_list}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                domains = future.result()
                all_domains.update(domains)
            except Exception as exc:
                print(f'  ✗ {url} generated an exception: {exc}')
    return all_domains

def main():
    print("Starting whitelist generation with parallel downloads...")
    print(f"Total URLs to process: {len(urls) + len(unfiltered_urls)}")
    unified_content = set()
    if urls:
        print(f"\nProcessing {len(urls)} filtered URLs...")
        filtered_domains = process_urls_parallel(urls, download_and_process_filtered)
        unified_content.update(filtered_domains)
        print(f" ✓ Collected {len(filtered_domains)} filtered domains")
    if unfiltered_urls:
        print(f"\nProcessing {len(unfiltered_urls)} unfiltered URLs...")
        unfiltered_domains = process_urls_parallel(unfiltered_urls, download_and_process_unfiltered)
        unified_content.update(unfiltered_domains)
        print(f" ✓ Collected {len(unfiltered_domains)} unfiltered domains")
    print(f"\n ✓ Total domains before final filtering: {len(unified_content)}")
    filtered_count = 0
    valid_domains = []
    for domain in sorted(unified_content):
        if not domain:
            filtered_count += 1
            continue
        if domain.startswith(DOMAIN_WHITELIST3):
            filtered_count += 1
            continue
        if domain.endswith(DOMAIN_WHITELIST_TUPLE) and not domain.startswith(DOMAIN_WHITELIST_TUPLE):
            filtered_count += 1
            continue
        if domain.endswith(DOMAIN_WHITELIST2_TUPLE) and not domain.startswith(DOMAIN_WHITELIST2_TUPLE):
            filtered_count += 1
            continue
        if not domain.startswith(('||', '@@', '|', '@@/', '/')) and not domain.endswith('$important'):
            domain = f'@@||{domain}^$important'
        valid_domains.append(domain)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid_domains) + '\n')
    written_count = len(valid_domains)
    print(f" ✓ Final domains written: {written_count}")
    print(f" ✓ Domains filtered out: {filtered_count}")
    print(f" ✓ File '{output_file}' generated successfully.")
    print(f" ✓ Downloads made: {len(download_cache)}")

if __name__ == "__main__":
    main()
