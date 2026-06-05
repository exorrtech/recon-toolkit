#!/usr/bin/env python3
"""EXORR Recon Toolkit — Automated Attack Surface Discovery CLI."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .engine import ReconEngine


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="exorr-recon",
        description="EXORR Recon Toolkit — automated attack surface discovery",
        epilog="Walk with the void. EXORR Security",
    )
    p.add_argument("target", help="Target domain (e.g. example.com)")
    p.add_argument("-p", "--phases", default="subfinder,httpx,nmap,nuclei",
                   help="Comma-separated phases (default: subfinder,httpx,nmap,nuclei)")
    p.add_argument("-o", "--output-dir", default="./recon-output", help="Output directory")
    p.add_argument("--report", default=None, help="Save JSON report to file")
    p.add_argument("--verbose", action="store_true", help="Verbose output")
    p.add_argument("-v", "--version", action="version", version="%(prog)s 1.0.0")
    return p.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)
    phases = [p.strip() for p in args.phases.split(",")]

    print(f"\n  EXORR Recon Toolkit v1.0.0")
    print(f"  =========================")
    print(f"  Target: {args.target}")
    print(f"  Phases: {', '.join(phases)}")
    print()

    engine = ReconEngine(
        target=args.target,
        output_dir=args.output_dir,
        phases=phases,
        verbose=args.verbose,
    )

    result = engine.run()

    # Print summary
    print(f"\n  =========================")
    print(f"  Recon complete")
    for phase in result.phases:
        status = "OK" if phase.success else "FAIL"
        print(f"    {phase.phase}: {status} ({phase.count} results, {phase.duration_seconds:.1f}s)")
    print(f"    Total: {result.duration_seconds:.1f}s")

    summary = result.to_dict().get("summary", {})
    print(f"\n  Summary:")
    print(f"    Subdomains:      {summary.get('subdomains', 0)}")
    print(f"    Live hosts:      {summary.get('live_hosts', 0)}")
    print(f"    Open ports:      {summary.get('open_ports', 0)}")
    print(f"    Vulnerabilities: {summary.get('vulnerabilities', 0)}")
    print()

    if args.report:
        Path(args.report).write_text(json.dumps(result.to_dict(), indent=2, default=str))
        print(f"  Report saved: {args.report}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
