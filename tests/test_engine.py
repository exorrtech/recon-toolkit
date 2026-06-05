"""Tests for the recon toolkit engine."""
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from exorr_recon.engine import ReconEngine, PhaseResult, ReconResult


def test_phase_result_to_dict():
    """PhaseResult should serialize correctly."""
    pr = PhaseResult(phase="subfinder", success=True, count=50, duration_seconds=3.5)
    d = pr.to_dict()
    assert d["phase"] == "subfinder"
    assert d["success"] is True
    assert d["count"] == 50
    assert d["duration_seconds"] == 3.5


def test_recon_result_to_dict():
    """ReconResult should include summary."""
    rr = ReconResult(
        target="example.com",
        timestamp="2026-01-01T00:00:00Z",
        phases=[
            PhaseResult(phase="subfinder", success=True, count=10),
            PhaseResult(phase="httpx", success=True, count=3),
            PhaseResult(phase="nmap", success=True, count=5),
            PhaseResult(phase="nuclei", success=True, count=2),
        ],
    )
    d = rr.to_dict()
    assert d["target"] == "example.com"
    assert d["summary"]["subdomains"] == 10
    assert d["summary"]["live_hosts"] == 3
    assert d["summary"]["open_ports"] == 5
    assert d["summary"]["vulnerabilities"] == 2


def test_tool_exists_check():
    """_tool_exists should detect available tools."""
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = ReconEngine(target="test.com", output_dir=tmpdir)
        # 'ls' should exist on any Linux system
        assert engine._tool_exists("ls") is True
        # Fake tool should not exist
        assert engine._tool_exists("nonexistent_tool_xyz") is False


def test_subfinder_missing_tool():
    """Subfinder phase should report error when tool is missing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = ReconEngine(target="test.com", output_dir=tmpdir)
        engine._tool_exists = lambda name: False
        result = engine.phase_subfinder()
        assert result.success is False
        assert "not found" in result.error


def test_httpx_missing_subdomains():
    """Httpx phase should fail gracefully without subdomain file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = ReconEngine(target="test.com", output_dir=tmpdir)
        engine._tool_exists = lambda name: True
        result = engine.phase_httpx()
        assert result.success is False


def test_run_pipeline_with_missing_tools():
    """Full pipeline should handle missing tools gracefully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = ReconEngine(
            target="test.com",
            output_dir=tmpdir,
            phases=["subfinder"],
        )
        engine._tool_exists = lambda name: False
        result = engine.run()
        assert len(result.phases) == 1
        assert result.phases[0].success is False


def test_run_multiple_phases():
    """Running multiple phases should produce results for each."""
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = ReconEngine(
            target="test.com",
            output_dir=tmpdir,
            phases=["subfinder", "httpx"],
        )
        engine._tool_exists = lambda name: False
        result = engine.run()
        assert len(result.phases) == 2


def test_output_dir_created():
    """Output directory should be created automatically."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "new_dir"
        engine = ReconEngine(target="test.com", output_dir=str(output))
        assert engine.output_dir.exists()
