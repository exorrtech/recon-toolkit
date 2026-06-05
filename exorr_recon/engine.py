"""Core recon engine — orchestrates subfinder, httpx, nmap, nuclei."""

import json
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class PhaseResult:
    """Result from a single recon phase."""
    phase: str
    success: bool
    output_file: str = ""
    data: Any = None
    count: int = 0
    duration_seconds: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "success": self.success,
            "output_file": self.output_file,
            "count": self.count,
            "duration_seconds": round(self.duration_seconds, 2),
            "error": self.error,
        }


@dataclass
class ReconResult:
    """Complete recon pipeline result."""
    target: str
    timestamp: str = ""
    phases: List[PhaseResult] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scanner": "exorr-recon-toolkit",
            "version": "1.0.0",
            "target": self.target,
            "timestamp": self.timestamp,
            "duration_seconds": round(self.duration_seconds, 2),
            "phases": [p.to_dict() for p in self.phases],
            "summary": {
                "subdomains": next((p.count for p in self.phases if p.phase == "subfinder"), 0),
                "live_hosts": next((p.count for p in self.phases if p.phase == "httpx"), 0),
                "open_ports": next((p.count for p in self.phases if p.phase == "nmap"), 0),
                "vulnerabilities": next((p.count for p in self.phases if p.phase == "nuclei"), 0),
            },
        }


class ReconEngine:
    """Orchestrate multi-phase recon pipeline."""

    def __init__(
        self,
        target: str,
        output_dir: str = "./recon-output",
        phases: Optional[List[str]] = None,
        verbose: bool = False,
    ):
        self.target = target
        self.output_dir = Path(output_dir) / target
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.phases = phases or ["subfinder", "httpx", "nmap", "nuclei"]
        self.verbose = verbose

    def _run(self, cmd: List[str], timeout: int = 300) -> tuple:
        """Run a command, return (stdout, stderr, returncode)."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", 127
        except subprocess.TimeoutExpired:
            return "", "Timeout", 124

    def _tool_exists(self, name: str) -> bool:
        """Check if a tool is available on PATH."""
        stdout, _, code = self._run(["which", name])
        return code == 0 and stdout.strip() != ""

    def phase_subfinder(self) -> PhaseResult:
        """Discover subdomains using subfinder."""
        start = time.time()
        output_file = str(self.output_dir / "subdomains.txt")

        if not self._tool_exists("subfinder"):
            return PhaseResult(phase="subfinder", success=False, error="subfinder not found on PATH", duration_seconds=time.time()-start)

        stdout, stderr, code = self._run(
            ["subfinder", "-d", self.target, "-silent", "-o", output_file],
            timeout=300,
        )

        if code == 0 and Path(output_file).exists():
            content = Path(output_file).read_text().strip()
            subs = [s for s in content.splitlines() if s.strip()]
            return PhaseResult(
                phase="subfinder", success=True,
                output_file=output_file, data=subs,
                count=len(subs), duration_seconds=time.time()-start,
            )
        return PhaseResult(phase="subfinder", success=False, error=stderr[:200], duration_seconds=time.time()-start)

    def phase_httpx(self) -> PhaseResult:
        """Probe live HTTP hosts using httpx."""
        start = time.time()
        subs_file = str(self.output_dir / "subdomains.txt")
        output_file = str(self.output_dir / "live_hosts.json")

        if not self._tool_exists("httpx"):
            return PhaseResult(phase="httpx", success=False, error="httpx not found", duration_seconds=time.time()-start)

        if not Path(subs_file).exists():
            return PhaseResult(phase="httpx", success=False, error="No subdomains file (run subfinder first)", duration_seconds=time.time()-start)

        stdout, stderr, code = self._run(
            ["httpx", "-l", subs_file, "-silent", "-json", "-o", output_file],
            timeout=300,
        )

        if code == 0 and Path(output_file).exists():
            content = Path(output_file).read_text().strip()
            hosts = [json.loads(line) for line in content.splitlines() if line.strip()]
            return PhaseResult(
                phase="httpx", success=True,
                output_file=output_file, count=len(hosts),
                duration_seconds=time.time()-start,
            )
        return PhaseResult(phase="httpx", success=False, error=stderr[:200], duration_seconds=time.time()-start)

    def phase_nmap(self) -> PhaseResult:
        """Port scan live hosts using nmap."""
        start = time.time()
        output_file = str(self.output_dir / "nmap_scan.txt")

        if not self._tool_exists("nmap"):
            return PhaseResult(phase="nmap", success=False, error="nmap not found", duration_seconds=time.time()-start)

        # Get live hosts from httpx output
        live_file = str(self.output_dir / "live_hosts.json")
        if not Path(live_file).exists():
            # Fallback: scan target directly
            target = self.target
        else:
            content = Path(live_file).read_text().strip()
            hosts = [json.loads(line).get("host", "") for line in content.splitlines() if line.strip()]
            target = ",".join(hosts[:10]) if hosts else self.target

        stdout, stderr, code = self._run(
            ["nmap", "-sV", "-top-ports", "100", "-oN", output_file, target],
            timeout=600,
        )

        if code == 0 and Path(output_file).exists():
            content = Path(output_file).read_text()
            open_ports = content.count("open")
            return PhaseResult(
                phase="nmap", success=True,
                output_file=output_file, count=open_ports,
                duration_seconds=time.time()-start,
            )
        return PhaseResult(phase="nmap", success=False, error=stderr[:200], duration_seconds=time.time()-start)

    def phase_nuclei(self) -> PhaseResult:
        """Run vulnerability templates using nuclei."""
        start = time.time()
        output_file = str(self.output_dir / "nuclei_results.txt")

        if not self._tool_exists("nuclei"):
            return PhaseResult(phase="nuclei", success=False, error="nuclei not found", duration_seconds=time.time()-start)

        subs_file = str(self.output_dir / "subdomains.txt")
        target_list = subs_file if Path(subs_file).exists() else self.target

        stdout, stderr, code = self._run(
            ["nuclei", "-u" if not Path(subs_file).exists() else "-l",
             target_list, "-silent", "-o", output_file],
            timeout=600,
        )

        if code == 0 and Path(output_file).exists():
            content = Path(output_file).read_text().strip()
            findings = len([l for l in content.splitlines() if l.strip()])
            return PhaseResult(
                phase="nuclei", success=True,
                output_file=output_file, count=findings,
                duration_seconds=time.time()-start,
            )
        return PhaseResult(phase="nuclei", success=False, error=stderr[:200], duration_seconds=time.time()-start)

    def run(self) -> ReconResult:
        """Run all enabled phases sequentially."""
        start = time.time()
        result = ReconResult(
            target=self.target,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        phase_runners = {
            "subfinder": self.phase_subfinder,
            "httpx": self.phase_httpx,
            "nmap": self.phase_nmap,
            "nuclei": self.phase_nuclei,
        }

        for phase_name in self.phases:
            runner = phase_runners.get(phase_name)
            if runner:
                if self.verbose:
                    print(f"  Running: {phase_name}...")
                phase_result = runner()
                result.phases.append(phase_result)
                if self.verbose:
                    status = "OK" if phase_result.success else "FAIL"
                    print(f"    {phase_name}: {status} ({phase_result.count} results, {phase_result.duration_seconds:.1f}s)")

        result.duration_seconds = time.time() - start
        return result
