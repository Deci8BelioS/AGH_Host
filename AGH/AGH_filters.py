import requests, re

from regex import REGEX, REGEX_WHITELIST, REGEX_WHITELIST2, SUBDOMINIO_DUPLICADO, SUBDOMINIO_DUPLICADO2, SUBDOMINIO_DUPLICADO3, SUBDOMINIO_DUPLICADO4

output_file = 'hosts.txt'

l1n34 = ['#', '!', '-', '*', '/', '.', '&', '%', '~', '?', '[', '^', ':', '@']

def descargar_archivo(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text.splitlines()
    except requests.exceptions.RequestException as e:
        print(f"Error al descargar desde {url}: {e}")
        return []

def limpiar_linea(linea):
    linea = linea.strip()
    linea = re.sub(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+', '', linea)
    linea = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '', linea)
    linea = re.sub(r'##.*', '', linea)
    linea = re.sub(r'#.*', '', linea)
    linea = re.sub(r'www\.', '', linea)
    linea = re.sub(r'\$.*$', '', linea)
    linea = linea.replace('http://', '').replace('https://', '').replace('||', '').replace('|', '').replace('^', '')
    return linea

def filtrar_lineas(lineas, excepciones):
    dominios_normales = set()
    dominios_excepcion = set()
    for linea in lineas:
        linea = limpiar_linea(linea)
        if linea.startswith(tuple(l1n34)) or not linea:
            continue
        if linea.startswith(f"{SUBDOMINIO_DUPLICADO}"):
            dominios_normales.add(f"{SUBDOMINIO_DUPLICADO}*.*")
            continue
        if linea.endswith(f"{SUBDOMINIO_DUPLICADO2}"):
            dominios_normales.add(f"*.{SUBDOMINIO_DUPLICADO2}")
            continue
        if linea.startswith(f"{SUBDOMINIO_DUPLICADO3}"):
            dominios_normales.add(f"{SUBDOMINIO_DUPLICADO3}*.eu")
            continue
        if linea.endswith(f"{SUBDOMINIO_DUPLICADO4}"):
            dominios_normales.add(f"{SUBDOMINIO_DUPLICADO4}")
            continue
        if any(pattern.search(linea) for pattern in REGEX) or not linea:
            continue
        if linea.endswith(tuple(REGEX_WHITELIST)) or not linea:
            continue
        if linea.endswith(tuple(REGEX_WHITELIST2)) and not linea.startswith(tuple(REGEX_WHITELIST2)) or not linea:
            continue
        dominios_normales.add(linea.strip())
    dominios_filtrados = dominios_normales - {d[2:] for d in dominios_excepcion}
    dominios_filtrados.update(dominios_excepcion)
    return dominios_filtrados

contenido_unificado = set()
file_excepciones = "/home/runner/work/hosts/hosts/AGH/filters/whitelist/whitelist.txt"

print(f"Leyendo desde archivo de excepciones: {file_excepciones}...\n")
with open(file_excepciones, 'r', encoding='utf-8') as file:
    excepciones = file.readlines()

urls = [
    # 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/light.txt',
    'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
    'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&amp;showintro=0&amp;mimetype=plaintext',
    'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=1&mimetype=plaintext',
    'https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt',
    'https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt',
    'https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/oisd_small.txt',
    'https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts'
]

for url in urls:
    print(f"Descargando desde {url}...")
    lineas = descargar_archivo(url)
    dominios_filtrados = filtrar_lineas(lineas, excepciones)
    contenido_unificado.update(dominios_filtrados)

with open(output_file, 'w', encoding='utf-8') as f:
    for dominio in sorted(contenido_unificado):
        if dominio.startswith('@@'):
            dominio = f'{dominio}^'.replace('|^', '^|')
        if not dominio.startswith('||') and not dominio.startswith('@@') and not dominio.startswith('|'):
            dominio = f'||{dominio}'
        if not dominio.endswith('^') and not dominio.endswith('^|') and not dominio.endswith('^$important'):
            dominio = f'{dominio}^'.replace('$important^', '^$important')
        f.write(f"{dominio}\n")

print(f"Archivo '{output_file}' generado con éxito.")
