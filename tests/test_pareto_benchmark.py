"""Unit and integration tests for Gate G2 Pareto Benchmark Suite."""

from __future__ import annotations

from pathlib import Path

from iam.cli import main
from iam.parser.capability import load_default_capability_model
from iam.verifier.pareto import (
    ParetoBenchmarkSuiteResult,
    ParetoBenchmarkSuiteRunner,
    ParetoSolution,
)
from iam.verifier.tradeoff import RemediationMethod, TradeoffConfig


class TestParetoBenchmarkSuite:
    """Test suite verifying multi-environment Pareto analysis and Gate G2 verdict."""

    def test_pareto_solution_dominance_logic(self) -> None:
        """Verify ParetoSolution.dominates under multi-objective criteria."""
        sol_a = ParetoSolution(
            method=RemediationMethod.UNCERTAINTY_AWARE,
            method_name="Uncertainty-Aware Repair",
            level1_risk=0.0,
            level2_risk=0.0,
            level3_risk=0.0,
            t1_breakage=0.0,
            t2_breakage=0.0,
            transformation_cost=1.0,
            execution_time_sec=0.02,
            is_safe_gt=True,
            is_misleading=False,
            num_transformations=1,
        )
        sol_b = ParetoSolution(
            method=RemediationMethod.NO_ACTION,
            method_name="No Action",
            level1_risk=0.0,
            level2_risk=0.9,
            level3_risk=1.0,
            t1_breakage=0.0,
            t2_breakage=0.0,
            transformation_cost=0.0,
            execution_time_sec=0.001,
            is_safe_gt=False,
            is_misleading=True,
            num_transformations=0,
        )
        sol_c = ParetoSolution(
            method=RemediationMethod.COARSE_DELETION,
            method_name="Coarse Deletion",
            level1_risk=0.0,
            level2_risk=0.0,
            level3_risk=0.0,
            t1_breakage=0.30,
            t2_breakage=0.20,
            transformation_cost=2.0,
            execution_time_sec=0.01,
            is_safe_gt=True,
            is_misleading=False,
            num_transformations=1,
        )

        # sol_a strictly dominates sol_c (lower breakage, lower cost, equal risk)
        assert sol_a.dominates(sol_c) is True
        assert sol_c.dominates(sol_a) is False

        # sol_a and sol_b are non-dominating (sol_b has lower cost, sol_a has lower risk)
        assert sol_a.dominates(sol_b) is False
        assert sol_b.dominates(sol_a) is False

    def test_run_suite_on_canonical_environment(self, tmp_path: Path) -> None:
        """Verify Pareto suite runs end-to-end on canonical environment."""
        cap_model = load_default_capability_model()
        cfg = TradeoffConfig(num_completions=5)
        runner = ParetoBenchmarkSuiteRunner(capability_model=cap_model, tradeoff_config=cfg)

        env1 = runner.build_canonical_environment()
        res = runner.run_suite(environments=[env1], output_dir=tmp_path, seed=42)

        assert isinstance(res, ParetoBenchmarkSuiteResult)
        assert len(res.environments) == 1
        assert "canonical_passrole_lambda" in res.environments[0].environment_name
        assert "PASSED" in res.gate_g2_status

        # Verify exported report files
        report_file = tmp_path / "gate_g2_pareto_report.md"
        json_file = tmp_path / "gate_g2_pareto_results.json"
        assert report_file.exists()
        assert json_file.exists()
        assert "Gate G2" in report_file.read_text(encoding="utf-8")

    def test_cli_evaluate_pareto(self, tmp_path: Path) -> None:
        """Verify `iam evaluate-pareto` CLI command executes and exits cleanly."""
        exit_code = main(
            [
                "evaluate-pareto",
                "--output-dir",
                str(tmp_path),
                "--num-completions",
                "5",
                "--seed",
                "42",
            ]
        )
        assert exit_code == 0
        assert (tmp_path / "gate_g2_pareto_report.md").exists()
        assert (tmp_path / "gate_g2_pareto_results.json").exists()
