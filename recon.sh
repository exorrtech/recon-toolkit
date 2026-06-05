#!/usr/bin/env bash
# EXORR Recon Toolkit — Automated Attack Surface Discovery
# Usage: ./recon.sh <target> [--phase subfinder|httpx|nmap|nuclei|scrape]

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

TARGET=""
PHASE="all"
OUTPUT_DIR=""
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Tools
SUBFINDER=$(which subfinder 2>/dev/null || echo "")
HTTPX=$(which httpx 2>/dev/null || echo "")
NMAP=$(which nmap 2>/dev/null || echo "")
NUCLEI=$(which nuclei 2>/dev/null || echo "")
ENGRAM=$(which engram 2>/dev/null || echo "")

banner() {
    echo -e "${CYAN}"
    echo "  ___  ___  ___ ___ ___ "
    echo " | _ \\/ _ \\/ __| __/ __|"
    echo " |   / (_) \\__ \\ _|\\__ \\"
    echo " |_|_\\\\___/|___/\\___|___/"
    echo -e "${NC}"
    echo -e "  ${GREEN}EXORR Security Advisory${NC} — Recon Toolkit"
    echo -e "  ${YELLOW}The void has no surface to attack.${NC}"
    echo ""
}

usage() {
    banner
    echo "Usage: $0 <target> [--phase subfinder|httpx|nmap|nuclei|scrape|all]"
    echo ""
    echo "Phases:"
    echo "  subfinder  — Passive subdomain enumeration"
    echo "  httpx      — Live host probing + tech detection"
    echo "  nmap       — Port scanning + service versioning"
    echo "  nuclei     — Vulnerability scanning"
    echo "  scrape     — Adaptive web scraping"
    echo "  all        — Full pipeline (default)"
    echo ""
    exit 1
}

parse_args() {
    if [ $# -lt 1 ]; then usage; fi
    TARGET="$1"
    shift
    while [ $# -gt 0 ]; do
        case "$1" in
            --phase) PHASE="$2"; shift 2 ;;
            *) usage ;;
        esac
    done
    OUTPUT_DIR="recon_${TARGET}_${TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR"
}

run_subfinder() {
    echo -e "${GREEN}[Phase 1]${NC} Subfinder — Subdomain Enumeration"
    if [ -z "$SUBFINDER" ]; then
        echo -e "${RED}  subfinder not found. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest${NC}"
        return 1
    fi
    $SUBFINDER -d "$TARGET" -silent 2>/dev/null | tee "$OUTPUT_DIR/subdomains.txt"
    local count=$(wc -l < "$OUTPUT_DIR/subdomains.txt")
    echo -e "${CYAN}  Found $count subdomains${NC}"
}

run_httpx() {
    echo -e "${GREEN}[Phase 2]${NC} HTTPX — Live Host Probing"
    if [ -z "$HTTPX" ]; then
        echo -e "${RED}  httpx not found. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest${NC}"
        return 1
    fi
    local input="${OUTPUT_DIR}/subdomains.txt"
    [ ! -f "$input" ] && echo "$TARGET" > "$input"
    $HTTPX -l "$input" -sc -title -td -fr -timeout 10 -rl 50 2>/dev/null | tee "$OUTPUT_DIR/live_hosts.txt"
    local count=$(wc -l < "$OUTPUT_DIR/live_hosts.txt" 2>/dev/null || echo 0)
    echo -e "${CYAN}  $count live hosts found${NC}"
}

run_nmap() {
    echo -e "${GREEN}[Phase 3]${NC} Nmap — Port Scanning"
    if [ -z "$NMAP" ]; then
        echo -e "${RED}  nmap not found. Install: apt install nmap${NC}"
        return 1
    fi
    $NMAP -sV -T4 --top-ports 100 -Pn "$TARGET" 2>&1 | tee "$OUTPUT_DIR/nmap.txt"
}

run_nuclei() {
    echo -e "${GREEN}[Phase 4]${NC} Nuclei — Vulnerability Scanning"
    if [ -z "$NUCLEI" ]; then
        echo -e "${RED}  nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${NC}"
        return 1
    fi
    local templates="/root/nuclei-templates/http/technologies/,/root/nuclei-templates/http/misconfiguration/"
    $NUCLEI -u "https://$TARGET" -t "$templates" -severity low,medium,high,critical -timeout 10 -rl 50 2>&1 | tee "$OUTPUT_DIR/nuclei.txt"
}

run_scrape() {
    echo -e "${GREEN}[Phase 5]${NC} Scrapling — Adaptive Scrape"
    python3 -c "
from scrapling import Fetcher
f = Fetcher()
r = f.get('https://$TARGET')
print(f'Status: {r.status}')
title = r.css('title')
for t in title: print(f'Title: {t.text()}')
links = r.css('a')
for a in links[:10]:
    href = a.attrib.get('href','?')
    print(f'Link: {href}')
" 2>&1 | tee "$OUTPUT_DIR/scrape.txt"
}

save_memory() {
    echo -e "${GREEN}[Memory]${NC} Storing results in Engram"
    if [ -z "$ENGRAM" ]; then
        echo -e "${YELLOW}  engram not found. Results saved to $OUTPUT_DIR/${NC}"
        return
    fi
    local summary="Recon pipeline on $TARGET. Timestamp: $TIMESTAMP."
    [ -f "$OUTPUT_DIR/subdomains.txt" ] && summary+=" Subdomains: $(wc -l < "$OUTPUT_DIR/subdomains.txt")"
    [ -f "$OUTPUT_DIR/live_hosts.txt" ] && summary+=" Live hosts: $(wc -l < "$OUTPUT_DIR/live_hosts.txt" 2>/dev/null || echo 0)"
    $ENGRAM save "Recon: $TARGET" "$summary" --project "recon-$TARGET" --type finding 2>/dev/null || true
}

main() {
    parse_args "$@"
    banner
    echo -e "${YELLOW}Target:${NC} $TARGET"
    echo -e "${YELLOW}Phase:${NC}  $PHASE"
    echo -e "${YELLOW}Output:${NC} $OUTPUT_DIR/"
    echo ""

    case "$PHASE" in
        subfinder) run_subfinder ;;
        httpx) run_httpx ;;
        nmap) run_nmap ;;
        nuclei) run_nuclei ;;
        scrape) run_scrape ;;
        all)
            run_subfinder
            run_httpx
            run_nmap
            run_nuclei
            run_scrape
            ;;
        *) usage ;;
    esac

    save_memory

    echo ""
    echo -e "${GREEN}✓ Pipeline complete.${NC} Results in $OUTPUT_DIR/"
}

main "$@"
