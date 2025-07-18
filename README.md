# AGH Host by DeciBelioS
<div align="right">

[**Spanish**](README_ES.md)

</div>

## Unified filters optimized for use in Adguard home and [adblock-lean](https://github.com/lynxthecat/adblock-lean).
| Links | Description | 
| -- | -- |
| [**Link raw to AGH_Host**](https://raw.githubusercontent.com/Deci8BelioS/AGH_Host/main/Filters/AGH_Host.txt) (Only AGH) | (100k+ of filters, eliminating subdomains if they appear in the original lists to block the main domain) |
| [**Link raw to AGH_Host+**](https://raw.githubusercontent.com/Deci8BelioS/AGH_Host/main/Filters/AGH_Host%2B.txt) (Only AGH) | (250k+ of filters, eliminating subdomains if they appear in the original lists to block the main domain) |
| [**Link raw to dnsmasq+**](https://raw.githubusercontent.com/Deci8BelioS/AGH_Host/main/Filters/dnsmasq.txt) (Only adblock-lean) | (200k+ of filters, eliminating subdomains if they appear in the original lists to block the main domain) |

Note: dnsmasq+ list has only been tested in openWRT using [adblock-lean](https://github.com/lynxthecat/adblock-lean)

# The use of the following filters is recommended to complement the AGH_Host or AGH_Host+ file
| Blocklist (Only AGH) | Whitelist (Only AGH) | 
| -- | -- |
| [**AGH_Host - Regex Blocklist**](https://raw.githubusercontent.com/Deci8BelioS/AGH_Host/main/Filters/blocklist/Regex%20Blocklist.txt) | [**AGH_Host - Custom Whitelist**](https://raw.githubusercontent.com/Deci8BelioS/AGH_Host/main/Filters/whitelist/Custom%20Whitelist.txt) |
| [**AGH_Host - Custom Blocklist**](https://raw.githubusercontent.com/Deci8BelioS/AGH_Host/main/Filters/blocklist/Custom%20Blocklist.txt) | [**AGH_Host - Whitelist**](https://raw.githubusercontent.com/Deci8BelioS/AGH_Host/main/Filters/whitelist/whitelist.txt) |
| [**swetoast - adguardhome-lists "REGEX"**](https://raw.githubusercontent.com/swetoast/adguardhome-lists/main/blacklist.txt) | [**AGH_Host - Personal Whitelist**](https://raw.githubusercontent.com/Deci8BelioS/AGH_Host/refs/heads/main/Filters/whitelist/Personal%20Whitelist.txt) |

# NOTICE: This list of filters has been created specifically for Adguard Home and adblock-lean.

This list is being tested on the following O.S., routers and software

| Operating System | Router | Software | 
| -- | -- | -- |
| OpenWrt 24.10.2 | Xiaomi Redmi Router AX6S/AX3200 | AdGuard Home v0.107.63 |
| OpenWrt 24.10.2 | Xiaomi Redmi Router AX6S/AX3200 | [adblock-lean](https://github.com/lynxthecat/adblock-lean) |

## Filters on which this list is based:
* [**1Hosts (Lite)**](https://github.com/badmojr/1Hosts)
* [**HaGeZi's Blocklist**](https://github.com/hagezi/dns-blocklists)
* [**AdGuardSDNSFilter**](https://github.com/AdguardTeam/AdGuardSDNSFilter)
* [**yoyo filters**](https://pgl.yoyo.org/)
* [**scamblocklist**](https://github.com/durablenapkin/scamblocklist/)
* [**malware-filter**](https://gitlab.com/malware-filter/phishing-filter)
* [**oisd filters**](https://github.com/sjhgvr/oisd/)
* [**StevenBlack filters**](https://github.com/StevenBlack/hosts)
* [**uBlockOrigin uAssets**](https://github.com/uBlockOrigin/uAssets/)
* [**ShadowWhisperer filters**](https://github.com/ShadowWhisperer/BlockLists/)
* [**hoshsadiq nocoin filters**](https://github.com/hoshsadiq/adblock-nocoin-list)
