# EXORR Recon Toolkit

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![MIT License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-1.0.0-orange)

**Automated attack surface discovery pipeline** by EXORR Security.

Orchestrates subfinder, httpx, nmap, and nuclei into a single automated recon pipeline. Python CLI with phase-by-phase execution, structured output, and JSON reporting.

---

## Features

- **Multi-phase pipeline** — subfinder -> httpx -> nmap -> nuclei, fully automated
- **Selective execution** — run individual phases or the full chain
- **Structured output** — JSON results with subdomain counts, live hosts, open ports, vuln findings
- **Graceful degradation** — missing tools are reported, not crash-causing
- **Timestamped results** — every run saved to organized output directories
- **Bash script included** — `recon.sh` for lightweight shell-based recon

---

## Requirements

- Python 3.9+
- Optional (auto-detected): [subfinder](https://github.com/projectdiscovery/subfinder), [httpx](https://github.com/projectdiscovery/httpx), [nmap](https://nmap.org/), [nuclei](https://github.com/projectdiscovery/nuclei)

---

## Installation

```bash
git clone https://github.com/exorrtech/recon-toolkit.git
cd recon-toolkit
pip install -e .
```

---

## Usage

### Full pipeline

```bash
exorr-recon example.com
```

### Specific phases only

```bash
exorr-recon example.com --phases subfinder,httpx
```

### With verbose output and report

```bash
exorr-recon example.com --verbose --report results.json
```

### Using the bash script

```bash
./recon.sh example.com --phase all
./recon.sh example.com --phase subfinder
```

---

## Pipeline Phases

| Phase | Tool | What it does |
|-------|------|-------------|
| **subfinder** | ProjectDiscovery subfinder | Passive subdomain enumeration |
| **httpx** | ProjectDiscovery httpx | Probe live HTTP/HTTPS hosts |
| **nmap** | Nmap | Port scan top 100 ports with service detection |
| **nuclei** | ProjectDiscovery nuclei | Vulnerability scanning with templates |

Each phase feeds its output into the next. Missing tools are skipped with a clear error message.

---

## Output

Results are saved to `./recon-output/<target>/`:

- `subdomains.txt` — discovered subdomains
- `live_hosts.json` — HTTP-probed live hosts
- `nmap_scan.txt` — Nmap output
- `nuclei_results.txt` — Nuclei findings

JSON report includes summary:

```json
{
  "summary": {
    "subdomains": 50,
    "live_hosts": 12,
    "open_ports": 8,
    "vulnerabilities": 3
  }
}
```

---

## Project Structure

```
recon-toolkit/
  exorr_recon/
    __init__.py
    __main__.py
    cli.py        # CLI interface
    engine.py     # Core pipeline engine
  tests/
    test_engine.py
  recon.sh       # Bash script alternative
  pyproject.toml
  README.md
  LICENSE
```

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

*Walk with the void. EXORR Security*
