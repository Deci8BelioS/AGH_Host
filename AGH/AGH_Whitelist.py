import requests, re

urls = [
    'https://raw.githubusercontent.com/celenityy/BadBlock/refs/heads/main/wildcards-no-star/whitelist.txt',
    'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt'
]

urls_sinfiltrar = [
    'https://raw.githubusercontent.com/swetoast/adguardhome-lists/refs/heads/main/whitelist.txt'
]

output_file = '/home/runner/work/hosts/hosts/AGH/filters/whitelist/whitelist.txt'

l1n34 = ['#', '!']
l1n34_2 = ['apple.com', 's3.amazonaws.com', 'wp.com', 'amazonaws.com']

def descargar_archivo(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text.splitlines()
    except requests.exceptions.RequestException as e:
        print(f"Error descargando {url}: {e}")
        return []
    
REGEX_WHITELIST = [
    "rain-alarm.com",
    "activision.com",
    "chomikuj.pl",
    "firebasedynamiclinks.googleapis.com",
    "epic.download",
    "geotrust.com",
    "cloudflare.com",
    "evyy.net",
    "adjust.com",
    "alimentacionchino.com",
    "cbsivideo.com",
    "pluto.tv",
    "onetrust.com",
    "cbsi.com",
    "tiqcdn.com",
    "instagram.com",
    "typekit.net",
    "robertsspaceindustries.com",
    "soundcloud.com",
    "ipqualityscore.com",
    "suyu.dev",
    "plex.direct",
    "revanced.net",
    "atomixhq.baby",
    "atresmedia.com",
    "microsoft.com",
    "leinad4mind.top",
    "split.io",
    "github.io",
    "gitlab.com",
    "raw.githubusercontent.com",
    "digidip.net",
    "chollometro.digidip.net",
    "tradedoubler.com",
    "plex.tv",
    "fapality.com",
    "virtualbox.org",
    "ddos-guard.net",
    "bbva.es",
    "pccomponentes.com",
    "es.spankbang.com",
    "tinder.com",
    "haiku-os.org",
    "milanuncios.com",
    "aliexpress.com",
    "alicdn.com",
    "go-mpulse.net",
    "nsw2u.com",
    "waaw.to",
    "raidrive.com",
    "netflixmirror.com",
    "oraclecloud.com",
    "eset.com",
    "elamigos-games.net",
    "mparticle.com",
    "cookielaw.org",
    "mmcdn.com",
    "azure.com",
    "nickchan.lol",
    "ddnsfree.com",
    "duckdns.org",
    "dynu.com"
]
REGEX_WHITELIST2 = [
    "3gppnetwork.org",
    "microsoft.com",
    "lencr.org",
    "symantec.com",
    "signal.org",
    "t-mobile.com",
    "tuyomovil.com",
    "symcd.com",
    "verisign.com",
    "viero.com",
    "symcb.com",
    "zonamovil.com.pa",
    "sectigo.com",
    "geotrust.com",
    "letsencrypt.org",
    "mycricket.com",
    "movistar.cl",
    "movistar.com.ar",
    "movistar.com.co",
    "movistar.com.ec",
    "movistar.com.uy",
    "movistar.com.ve",
    "movistar.com",
    "movistar.cr",
    "movistar.es",
    "movistar.gt",
    "movistar.mx",
    "movistar.ni",
    "movistar.pa",
    "movistar.pe",
    "movistar.sv",
    "movistar.ve",
    "3ireland.ie",
    "accv.es",
    "github.io",
    "entrust.net",
    "ocsp-responder.com",
    "live.com",
    "office.com",
    "office.net",
    "office365.com",
    "wosign.com",
    "globalsign.com",
    "mopera.net",
    "usertrust.com",
    "trustwave.com",
    "trust-provider.com",
    "digicert.com",
    "amazontrust.com",
    "vodafone.al",
    "vodafone.co.uk",
    "vodafone.com.eg",
    "vodafone.com.mt",
    "vodafone.com.qa",
    "vodafone.es",
    "vodafone.gr",
    "vodafone.hu",
    "vodafone.ie",
    "vodafone.is",
    "vodafone.it",
    "vodafone.net.nz",
    "vodafone.pt",
    "comodo.com",
    "comodo.net",
    "googleapis.com",
    "orange.acte",
    "orange.at",
    "orange.cm",
    "orange.co.uk",
    "orange.com.do",
    "orange.es",
    "orange.fr",
    "orange.lu",
    "orange.mms",
    "orange.ne",
    "orange.nl",
    "orange.pl",
    "orange.re",
    "orange.smartphone",
    "orange.tn",
    "orange.ug",
    "orange.video",
    "orange.web",
    "orange.world",
    "euskaltel.mobi",
    "thawte.com",
    "pepephone.com"
]

REGEX_WHITELIST3 = "mmsc."

def filtrar_lineas(lineas):
    dominios_validos = set()
    for linea in lineas:
        linea = linea.strip()
        linea = re.sub(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+', '', linea)
        linea = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '', linea)
        linea = re.sub(r'##.*', '', linea)
        linea = re.sub(r'#.*', '', linea)
        linea = re.sub(r'www\.', '', linea)
        linea = re.sub(r'\$.*$', '', linea)
        linea = linea.replace('http://', '').replace('https://', '').replace('@@||', '').replace('^', '').replace('@@|', '')
        if linea.startswith(tuple(l1n34)) or not linea:
            continue
        if linea.startswith(tuple(l1n34_2)) or not linea:
            continue
        if linea.startswith(REGEX_WHITELIST3):
            continue
        if linea.endswith(tuple(REGEX_WHITELIST)) and not linea.startswith(tuple(REGEX_WHITELIST)) or not linea:
            continue
        if linea.endswith(tuple(REGEX_WHITELIST2)) and not linea.startswith(tuple(REGEX_WHITELIST2)) or not linea:
            continue
        if not linea.startswith('||') and not linea.startswith('@@') and not linea.startswith('|') and not linea.startswith('@@/') and not linea.endswith('$important'):
            linea = f'@@||{linea}^$important'
        if linea:
            dominios_validos.add(linea.strip())
    return dominios_validos

def lineas__sinfiltrar(lineas):
    dominios_validos = set()
    for linea in lineas:
        if linea.startswith(tuple(l1n34)) or not linea:
            continue
        linea = linea.strip()
        if linea:
            dominios_validos.add(linea.strip())
    return dominios_validos

contenido_unificado = set()

for url in urls:
    print(f"Descargando desde {url}...")
    lineas = descargar_archivo(url)
    dominios_filtrados = filtrar_lineas(lineas)
    contenido_unificado.update(dominios_filtrados)

for url in urls_sinfiltrar:
    print(f"Descargando desde {url}...")
    lineas = descargar_archivo(url)
    dominios_sinfiltrar = lineas__sinfiltrar(lineas)
    contenido_unificado.update(dominios_sinfiltrar)

with open(output_file, 'w', encoding='utf-8') as f:
    for dominio in sorted(contenido_unificado):
        f.write(dominio + '\n')

print(f"Archivo '{output_file}' generado con éxito.")
