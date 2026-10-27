"""Unit and integration tests for Section 6.4 Scalability Benchmark Suite."""

from __future__ import annotations

from pathlib import Path

from iam.cli import main
from iam.parser.capability import load_default_capability_model
from iam.verifier.scalability import (
    ScalabilityBenchmarkResult,
    ScalabilityBenchmarkRunner,
    ScalabilityDataPoint,
)


class TestScalabilityBenchmarkSuite:
    """Test suite verifying scaling evaluation and report generation."""

    def test_evaluate_single_scale(self) -> None:
        """Verify evaluate_scale produces valid ScalabilityDataPoint."""
        cap_model = load_default_capability_model()
        runner = ScalabilityBenchmarkRunner(
            capability_model=cap_model,
            max_z3_scale=50,
            z3_timeout_sec=2.0,
        )

        dp = runner.evaluate_scale(num_nodes=50, seed=42, num_completions=5)
        assert isinstance(dp, ScalabilityDataPoint)
        assert dp.num_nodes >= 30
        assert dp.greedy_repair_latency_ms > 0.0
        assert dp.total_pipeline_latency_ms > 0.0
        assert dp.pruning_reduction_pct >= 0.0

    def test_run_suite_and_export_reports(self, tmp_path: Path) -> None:
        """Verify run_suite executes and exports report files."""
        cap_model = load_default_capability_model()
        runner = ScalabilityBenchmarkRunner(
            capability_model=cap_model,
            max_z3_scale=50,
            z3_timeout_sec=2.0,
        )

        res = runner.run_suite(scales=[50], output_dir=tmp_path, seed=42)
        assert isinstance(res, ScalabilityBenchmarkResult)
        assert len(res.data_points) == 1
        assert res.max_scale_evaluated >= 30

        report_file = tmp_path / "scalability_report.md"
        json_file = tmp_path / "scalability_results.json"
        assert report_file.exists()
        assert json_file.exists()
        assert "Runtime Scalability" in report_file.read_text(encoding="utf-8")

    def test_cli_evaluate_scalability(self, tmp_path: Path) -> None:
        """Verify `iam evaluate-scalability` CLI command executes cleanly."""
        exit_code = main(
            [
                "evaluate-scalability",
                "--output-dir",
                str(tmp_path),
                "--scales",
                "50",
                "--max-z3-scale",
                "50",
                "--seed",
                "42",
            ]
        )
        assert exit_code == 0
        assert (tmp_path / "scalability_report.md").exists()
        assert (tmp_path / "scalability_results.json").exists()
