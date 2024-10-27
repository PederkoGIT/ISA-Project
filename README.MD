# ISA Projekt - DNS monitor
Peter Páleník (xpalen06)
27.10.2024

# Popis
Program na monitorovanie DNS komunikácie na zvolenom rozhraní, alebo z pcap súboru.

# Spúšťanie
Program sa spúšťa príkazom `sudo ./dns-monitor` s parametram:
- `-i [rozhranie]` pre monitorovanie na rozhraní
- `-p [súbor]` pre monitorovanie zaznamenanej komunikácie zo súboru
- `-v` pre kompletný výpis
- `-d [súbor]` pre výpis zaznamenaných domén do daného súboru
- `-t [súbor]` pre výpis preložených adries do daného súboru
- `-h` pre výpis návodu

Monitorovanie prebieha **vždy len** na jednom rozhraní **alebo** z jedného súbory. **Nikdy** na ich kombinácii. Ak sa číta zo súboru, nie je potrebné spúšťanie s root právami, aj keď nie je priamo odporúčané.

## Príklad spúšťania
`sudo ./dns-monitor -i enp0s3 -v -d domains.txt -t translations.txt`
`sudo ./dns-monitor -p test.pcapng -v -d domains.txt -t translations.txt`
`sudo ./dns-monitor -h`
`sudo ./dns-monitor -i enp0s3`

# Odovzdané súbody
- `dns-monitor.c`
- `dns-monitor.h`
- `Makefile`
- `README.MD`

