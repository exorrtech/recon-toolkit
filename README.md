# Recon Toolkit

<p align="center">
  <img src="https://img.shields.io/badge/Toolkit-Attack_Surface_Discovery-00ff41?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Engine-Subfinder_|_HTTPX_|_Nuclei_|_Nmap_|_Scrapling-blue?style=for-the-badge" />
</p>

Automated reconnaissance pipeline for attack surface discovery. End-to-end from subdomain enumeration to vulnerability scanning with persistent memory.

## Pipeline

```
Target → Subfinder → HTTPX → Nmap → Nuclei → Scrapling → Engram (Memory)
```

| Phase | Tool | Purpose |
|-------|------|---------|
| 1 | **Subfinder** | Passive subdomain enumeration |
| 2 | **HTTPX** | Live host probing, tech detection |
| 3 | **Nmap** | Port scanning, service versioning |
| 4 | **Nuclei** | Vulnerability scanning (818+ templates) |
| 5 | **Scrapling** | Adaptive web scraping, JS rendering |
| 6 | **Engram** | Persistent memory across sessions |

## Quick Start

```bash
# Full recon pipeline
./recon.sh target.com

# Individual phases
./recon.sh target.com --phase subfinder
./recon.sh target.com --phase httpx
./recon.sh target.com --phase nmap
./recon.sh target.com --phase nuclei
./recon.sh target.com --phase scrape
```

## Requirements

- [Subfinder](https://github.com/projectdiscovery/subfinder) — `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
- [HTTPX](https://github.com/projectdiscovery/httpx) — `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`
- [Nuclei](https://github.com/projectdiscovery/nuclei) — `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
- [Nmap](https://nmap.org) — `apt install nmap`
- [Scrapling](https://github.com/D4Vinci/Scrapling) — `pip install scrapling`
- [Engram](https://github.com/nickschmeiter/engram) — Memory backbone

## Memory Integration

All results are stored in Engram persistent memory:

```bash
# Store findings
engram save "Recon: target.com" "Full pipeline results..." --project recon --type finding

# Recall past results
engram search "target.com" --project recon

# Cross-session context
engram context recon
```

## License

MIT — See [LICENSE](LICENSE)

---

*Part of [EXORR Security Advisory](https://github.com/exorrtech)*
