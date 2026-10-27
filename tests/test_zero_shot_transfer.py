"""Unit and integration tests for Synthetic-to-TAC-Bench Zero-Shot Inductive Transfer.

Verifies:
- ZeroShotTransferConfig configuration contracts.
- RGCN candidate pair continuous scoring and calibration on TAC-Bench graphs.
- Tabular baseline fitting and inference on cross-account candidate pairs.
- Full ZeroShotTransferRunner pipeline execution and Gate G1 evaluation.
- Markdown benchmark report and JSON results serialization.
- CLI subcommands: `iam ingest-tac-bench` and `iam evaluate-transfer`.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from iam.cli import main
from iam.models.decoder import DecoderConfig
from iam.models.rgcn import RGCNConfig
from iam.models.training import RGCNLinkPredictionModel
from iam.models.zero_shot import (
    ZeroShotTransferConfig,
    ZeroShotTransferResult,
    ZeroShotTransferRunner,
)
from iam.parser.tac_bench import (
    TACBenchCategory,
    TACBenchGenerator,
)


class TestZeroShotTransferPipeline:
    """Tests for zero-shot inductive transfer evaluation pipeline."""

    @pytest.fixture
    def generator(self) -> TACBenchGenerator:
        return TACBenchGenerator(seed=42)

    @pytest.fixture
    def minimal_model(self) -> RGCNLinkPredictionModel:
        encoder_cfg = RGCNConfig(hidden_channels=32, num_bases=4, dropout=0.0)
        decoder_cfg = DecoderConfig(hidden_channels=32, mode="basis", num_bases=2)
        return RGCNLinkPredictionModel(
            encoder_config=encoder_cfg,
            decoder_config=decoder_cfg,
        )

    def test_score_rgcn_pairs_bounded_in_unit_interval(
        self,
        generator: TACBenchGenerator,
        minimal_model: RGCNLinkPredictionModel,
    ) -> None:
        task = generator.generate_task(
            "tac-test-score",
            TACBenchCategory.MULTI_ACCOUNT_PE,
            num_background_nodes=10,
        )
        runner = ZeroShotTransferRunner()
        hetero_data = task.to_hetero_data(runner.converter, use_observed=True)

        eval_pairs = task.pos_pairs + task.neg_pairs
        scores = runner.score_rgcn_pairs(
            model=minimal_model,
            data=hetero_data,
            graph=task.observed_graph,
            pairs=eval_pairs,
            temperature=1.2,
        )

        assert len(scores) == len(eval_pairs)
        assert np.all(scores >= 0.0)
        assert np.all(scores <= 1.0)
        assert scores.dtype == np.float32

    def test_score_rgcn_empty_and_invalid_pairs(
        self,
        generator: TACBenchGenerator,
        minimal_model: RGCNLinkPredictionModel,
    ) -> None:
        task = generator.generate_task(
            "tac-empty", TACBenchCategory.CICD_COMPROMISE, num_background_nodes=5
        )
        runner = ZeroShotTransferRunner()
        hetero_data = task.to_hetero_data(runner.converter, use_observed=True)

        # Empty pairs
        empty_scores = runner.score_rgcn_pairs(
            minimal_model, hetero_data, task.observed_graph, [], temperature=1.0
        )
        assert len(empty_scores) == 0

        # Non-existent node ID
        invalid_scores = runner.score_rgcn_pairs(
            minimal_model,
            hetero_data,
            task.observed_graph,
            [("non_existent_u", "non_existent_v")],
            temperature=1.0,
        )
        assert len(invalid_scores) == 1
        assert invalid_scores[0] == 0.0

    def test_fit_tabular_baselines(self, generator: TACBenchGenerator) -> None:
        runner = ZeroShotTransferRunner()
        fixtures = [
            generator.generate_task(f"fit_{i}", cat, num_background_nodes=10)
            for i, cat in enumerate(
                [TACBenchCategory.MULTI_ACCOUNT_PE, TACBenchCategory.CICD_COMPROMISE]
            )
        ]
        tac_gb, rf = runner.fit_tabular_baselines(fixtures)

        assert tac_gb.is_fitted is True
        assert rf.is_fitted is True

        test_task = generator.generate_task(
            "test_eval", TACBenchCategory.MULTI_ACCOUNT_PE, num_background_nodes=8
        )
        eval_pairs = test_task.pos_pairs + test_task.neg_pairs
        gb_preds = tac_gb.predict_proba(test_task.observed_graph, eval_pairs)
        rf_preds = rf.predict_proba(test_task.observed_graph, eval_pairs)

        assert len(gb_preds) == len(eval_pairs)
        assert len(rf_preds) == len(eval_pairs)
        assert np.all(gb_preds >= 0.0) and np.all(gb_preds <= 1.0)
        assert np.all(rf_preds >= 0.0) and np.all(rf_preds <= 1.0)

    def test_run_transfer_benchmark_end_to_end(
        self,
        generator: TACBenchGenerator,
        tmp_path: Path,
    ) -> None:
        out_dir = tmp_path / "transfer_results"
        cfg = ZeroShotTransferConfig(
            num_synthetic_train_envs=2,
            num_synthetic_val_envs=1,
            synthetic_train_nodes=35,
            synthetic_val_nodes=35,
            num_epochs=2,
            hidden_channels=32,
            num_bases=4,
            output_dir=out_dir,
            seed=42,
        )
        runner = ZeroShotTransferRunner(config=cfg)

        # Generate a small suite of 7 tasks (1 per category)
        dataset = generator.generate_benchmark_suite(num_tasks=7, num_background_nodes=8)
        result = runner.run_transfer_benchmark(dataset)

        assert isinstance(result, ZeroShotTransferResult)
        assert result.task_count == 7
        assert result.calibrated_temperature > 0.0
        assert result.gate_g1_status in ("PASSED (GO)", "REFRAME")
        assert len(result.model_metrics) == 6
        assert "HeteroRGCN (Zero-Shot)" in result.model_metrics
        assert "TAC-GB" in result.model_metrics
        assert "IAMPERE SMT" in result.model_metrics
        assert "BFS" in result.model_metrics
        assert "Oracle" in result.model_metrics

        # Verify artifacts exist
        md_file = out_dir / cfg.markdown_filename
        json_file = out_dir / cfg.json_filename
        assert md_file.exists()
        assert json_file.exists()

        md_content = md_file.read_text(encoding="utf-8")
        assert "Gate G1" in md_content
        assert "Comparative Benchmark Results" in md_content

        json_data = json.loads(json_file.read_text(encoding="utf-8"))
        assert json_data["task_count"] == 7
        assert "model_metrics" in json_data


class TestZeroShotCLICommands:
    """Verifies CLI integration for TAC-Bench ingestion and zero-shot transfer."""

    def test_cli_ingest_tac_bench(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "tac_bench_data"
        exit_code = main(
            [
                "ingest-tac-bench",
                "--num-tasks",
                "14",
                "--output-dir",
                str(out_dir),
                "--seed",
                "99",
            ]
        )
        assert exit_code == 0
        manifest_file = out_dir / "manifest.json"
        assert manifest_file.exists()

        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        assert len(manifest) == 14

    def test_cli_evaluate_transfer(self, tmp_path: Path) -> None:
        tac_dir = tmp_path / "tac_bench"
        out_dir = tmp_path / "zero_shot_out"

        exit_code = main(
            [
                "evaluate-transfer",
                "--tac-bench-dir",
                str(tac_dir),
                "--num-tasks",
                "7",
                "--output-dir",
                str(out_dir),
                "--epochs",
                "1",
                "--seed",
                "101",
            ]
        )
        assert exit_code == 0
        assert (out_dir / "zero_shot_transfer_report.md").exists()
        assert (out_dir / "zero_shot_transfer_results.json").exists()
