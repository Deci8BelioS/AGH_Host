import re

REGEX = [
    re.compile(r'^ad(?:[sxv]?[0-9]*|system)[_.-](?:[^\s.]+\.){1,}|[_.-]ad(?:[sxv]?[0-9]*|system)[_.-]'),
    re.compile(r'([.\-_])?(logging|annons|crashlytics(reports)?|metrics|banner(s)?|marketing|analytics|telemetry|(stats|statistics)|events|track(ing)?|(insights\-)?collector|(d)?trace)([.\-_])?'),
    re.compile(r'(?:.*\.)?(imrworldwide\.com$|sentry\.io$|brandmetrics\.com|$brandmetrics\.com$|tsyndicate\.com$|adnxs\.com|moatads\.com$|app-measurement\.com$|admob\.com$|statsy\.net$|footprintdns\.com$|app-measurement\.com$|acuityads\.com$|doubleclick\.net$|ezcybersearch\.com$|affiliator\.(?:com|nu)$|affiliaxe\.com$|datadoghq\.(?:com$|eu$)|findbetterresults\.com|funnelytics\.io|tradedoubler\.com)'),
    re.compile(r'^(?:.+?([\.\-_]))?adse?rv(er?|ice)?s?[0-9]*([\.\-_])'),
    re.compile(r'^(cbox4\.ignorelist|atlas-upd)\.com$|^(claudfront|allowlisted)\.net|^hsdps\.cc$|^ads-tm-glb\.click$'),
    re.compile(r'^allegro'),
    re.compile(r'^beacons?[0-9]*([\.\-_])'),
    re.compile(r'^mads\.'),
    re.compile(r'^count(?:er(s)?)?([\.\-_])'),
    re.compile(r'^footprints([\.\-_])'),
    re.compile(r'^pixel(?:s)?([\.\-_])'),
    re.compile(r'^app\.adjust\.(?:world|com|net\.in$)'),
    re.compile(r'^(developer)\.asustor\.com$'),
    re.compile(r'^galaxy-client-reports\.gog\.com$'),
    re.compile(r'^svt\.d[0-9]\.sc\.omtrdc\.net$'),
    re.compile(r'^deb\.fdmpkg\.org$'),
    re.compile(r'^(track-my-delivery\.net|unsubscribeprime\.info)$'),
    re.compile(r'^(.*)?(duc3k|amazingtodaynotsaidhimherwhathe|ankabuttech|tadogem|deveparty|plus-lema|es-megado|focustopbreed78d|fermonesgobide|sertvs|jqscr|jqueryns|maximumpushtodaynotnowbut|motiontodaynotgogoodnowok|mavelecgr|eerier-safety\.000webhostapp|catknock|specialblueitems|violetlovelines|panel\.cheater-zone|allfamax|client\.cheater-zone|bitcoinpricealertexpert|coindexalerter|uniswapdataprice|immagirls\.myvnc|alpatrik|justinstalledpanel|damnater)\.com$'),
    re.compile(r'[-\w]+\.casalemedia\.com\s*'),
    re.compile(r'[-\w]+\.actonservice\.com\s*'),
    re.compile(r'[-\w]+\.smartadserver\.com\s*'),
    re.compile(r'[-\w]+\.advertnative\.com\s*'),
]

LIST_WHITELIST = ["rain-alarm.com","activision.com","chomikuj.pl","firebasedynamiclinks.googleapis.com","epic.download","geotrust.com","cloudflare.com","evyy.net","adjust.com","alimentacionchino.com","cbsivideo.com","pluto.tv","onetrust.com","cbsi.com","tiqcdn.com","instagram.com","typekit.net","robertsspaceindustries.com","soundcloud.com","ipqualityscore.com","suyu.dev","plex.direct","revanced.net","atomixhq.baby","atresmedia.com","leinad4mind.top","split.io","github.io","gitlab.com","raw.githubusercontent.com","digidip.net","chollometro.digidip.net","tradedoubler.com","plex.tv","fapality.com","virtualbox.org","ddos-guard.net","bbva.es","cn.pccomponentes.com","es.spankbang.com","tinder.com","haiku-os.org","milanuncios.com","aliexpress.com","alicdn.com","go-mpulse.net","nsw2u.com","waaw.to","raidrive.com","netflixmirror.com","oraclecloud.com","eset.com","mparticle.com","cookielaw.org","mmcdn.com","azure.com","nickchan.lol"]

DOMAIN_LIST = ["file.co.pl","apps.co.pl","metadsp.co.uk","momentummedia.com.au","dvgtm.akadns.net","admaster.com.cn","i-mobile.co.jp","myishop.co.uk","l.qq.com","research.de.com","bugly.qq.com","free-counter.co.uk","adskeeper.co.uk","smlog.co.kr","searchteria.co.jp","free-counters.co.uk","ebis.ne.jp","rozetka.com.ua","procook.co.uk","scorptec.com.au","rakuten.co.jp","sina.com.cn","valuecommerce.ne.jp","jwespeex.co.in","rumahweb.org","adriver.ru","adacado.com","dewrain.site","adtegrity.net","ad2iction.com","dewrain.world","adten.eu","netshelter.net","dewrain.life"]

SUBDOMAIN_PATTERNS = {
    "vinted-": "*.*",
    "hotel-": "*.*",
    "piwik.": "*",
    "matomo.": "*",
    "metric.": "*",
    "olx-": "*.*",
    "olx.": "*",
    "mdp-appconf-": "*.*"
}

DOMAIN_WHITELIST = ["rain-alarm.com","activision.com","chomikuj.pl","firebasedynamiclinks.googleapis.com","epic.download","geotrust.com","cloudflare.com","evyy.net","adjust.com","alimentacionchino.com","cbsivideo.com","pluto.tv","onetrust.com","cbsi.com","tiqcdn.com","instagram.com","typekit.net","robertsspaceindustries.com","soundcloud.com","ipqualityscore.com","suyu.dev","plex.direct","revanced.net","atomixhq.baby","atresmedia.com","microsoft.com","leinad4mind.top","split.io","github.io","gitlab.com","raw.githubusercontent.com","digidip.net","chollometro.digidip.net","tradedoubler.com","plex.tv","fapality.com","virtualbox.org","ddos-guard.net","bbva.es","pccomponentes.com","es.spankbang.com","tinder.com","haiku-os.org","milanuncios.com","aliexpress.com","alicdn.com","go-mpulse.net","nsw2u.com","waaw.to","raidrive.com","netflixmirror.com","oraclecloud.com","eset.com","elamigos-games.net","mparticle.com","cookielaw.org","mmcdn.com","azure.com","nickchan.lol"]

DOMAIN_WHITELIST2 = ["3gppnetwork.org","microsoft.com","lencr.org","symantec.com","signal.org","t-mobile.com","tuyomovil.com","symcd.com","verisign.com","viero.com","symcb.com","zonamovil.com.pa","sectigo.com","geotrust.com","letsencrypt.org","mycricket.com","movistar.cl","movistar.com.ar","movistar.com.co","movistar.com.ec","movistar.com.uy","movistar.com.ve","movistar.com","movistar.cr","movistar.es","movistar.gt","movistar.mx","movistar.ni","movistar.pa","movistar.pe","movistar.sv","movistar.ve","3ireland.ie","accv.es","github.io","entrust.net","ocsp-responder.com","live.com","office.com","office.net","office365.com","wosign.com","globalsign.com","mopera.net","usertrust.com","trustwave.com","trust-provider.com","digicert.com","amazontrust.com","vodafone.al","vodafone.co.uk","vodafone.com.eg","vodafone.com.mt","vodafone.com.qa","vodafone.es","vodafone.gr","vodafone.hu","vodafone.ie","vodafone.is","vodafone.it","vodafone.net.nz","vodafone.pt","comodo.com","comodo.net","googleapis.com","orange.acte","orange.at","orange.cm","orange.co.uk","orange.com.do","orange.es","orange.fr","orange.lu","orange.mms","orange.ne","orange.nl","orange.pl","orange.re","orange.smartphone","orange.tn","orange.ug","orange.video","orange.web","orange.world","euskaltel.mobi","thawte.com","pepephone.com"]

DOMAIN_WHITELIST3 = "mmsc."