"""Unit and integration tests for TAC-Bench ingestion and benchmark dataset generation.

Verifies:
- TACBenchTask schema serialization, deserialization, and JSON file round-trips.
- Generation of canonical tasks across all 7 TAC-Bench architectural categories:
    1. Multi-Account PE
    2. Cross-Account Delegation
    3. Data Lake Governance
    4. Microservices Zero-Trust
    5. CI/CD Compromise
    6. Dormant Policy Rollback
    7. Federated Identity Pivot
- Ground-truth reachability in G* versus severed unreachability in G_o.
- Stratified negative sampling and candidate pair generation.
- TACBenchDataset container methods, category filtering, and manifest persistence.
- PyG HeteroData conversion and tensor dimensions.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iam.baselines.iampere import IAMPEREBaselineEngine
from iam.models.converter import IAMHeteroDataConverter
from iam.parser.tac_bench import (
    TACBenchCategory,
    TACBenchDataset,
    TACBenchGenerator,
    TACBenchTask,
)


class TestTACBenchTaskAndDataset:
    """Tests for TACBenchTask and TACBenchDataset containers."""

    @pytest.fixture
    def generator(self) -> TACBenchGenerator:
        return TACBenchGenerator(seed=42)

    @pytest.fixture
    def sample_task(self, generator: TACBenchGenerator) -> TACBenchTask:
        return generator.generate_task(
            task_id="tac-test-0001",
            category=TACBenchCategory.MULTI_ACCOUNT_PE,
            num_background_nodes=10,
        )

    def test_task_serialization_roundtrip(self, sample_task: TACBenchTask) -> None:
        t_dict = sample_task.to_dict()
        assert t_dict["task_id"] == "tac-test-0001"
        assert t_dict["category"] == "multi_account_pe"
        assert len(t_dict["hidden_bridge"]) == 3
        assert len(t_dict["pos_pairs"]) >= 1
        assert len(t_dict["neg_pairs"]) >= 1

        reconstructed = TACBenchTask.from_dict(t_dict)
        assert reconstructed.task_id == sample_task.task_id
        assert reconstructed.category == sample_task.category
        assert reconstructed.hidden_bridge == sample_task.hidden_bridge
        assert reconstructed.observed_graph.num_nodes == sample_task.observed_graph.num_nodes
        assert (
            reconstructed.ground_truth_graph.num_edges == sample_task.ground_truth_graph.num_edges
        )

    def test_task_file_persistence(self, sample_task: TACBenchTask, tmp_path: Path) -> None:
        file_path = tmp_path / "task.json"
        sample_task.save_to_file(file_path)
        assert file_path.exists()

        loaded = TACBenchTask.load_from_file(file_path)
        assert loaded.task_id == sample_task.task_id
        assert loaded.source_principal == sample_task.source_principal
        assert loaded.target_crown_jewel == sample_task.target_crown_jewel

    def test_dataset_save_and_load_manifest(
        self, generator: TACBenchGenerator, tmp_path: Path
    ) -> None:
        tasks = [
            generator.generate_task(f"tac-test-{i}", cat, num_background_nodes=5)
            for i, cat in enumerate(TACBenchCategory)
        ]
        dataset = TACBenchDataset(tasks=tasks)
        assert len(dataset) == 7

        out_dir = tmp_path / "dataset"
        dataset.save_to_dir(out_dir)

        manifest_file = out_dir / "manifest.json"
        assert manifest_file.exists()
        manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
        assert len(manifest_data) == 7

        loaded_dataset = TACBenchDataset.load_from_dir(out_dir)
        assert len(loaded_dataset) == 7
        summary = loaded_dataset.summary()
        assert summary["total_tasks"] == 7
        assert len(summary["categories"]) == 7

        pe_tasks = loaded_dataset.filter_by_category(TACBenchCategory.MULTI_ACCOUNT_PE)
        assert len(pe_tasks) == 1
        assert pe_tasks[0].task_id == "tac-test-0"


class TestTACBenchCategoryGenerators:
    """Verifies each of the 7 TAC-Bench procedural category generators."""

    @pytest.fixture
    def generator(self) -> TACBenchGenerator:
        return TACBenchGenerator(seed=123)

    @pytest.fixture
    def iampere_engine(self) -> IAMPEREBaselineEngine:
        return IAMPEREBaselineEngine(max_steps=5)

    @pytest.mark.parametrize(
        "category",
        [
            TACBenchCategory.MULTI_ACCOUNT_PE,
            TACBenchCategory.CROSS_ACCOUNT_DELEGATION,
            TACBenchCategory.DATA_LAKE_GOVERNANCE,
            TACBenchCategory.MICROSERVICES_ZERO_TRUST,
            TACBenchCategory.CICD_COMPROMISE,
            TACBenchCategory.DORMANT_POLICY_ROLLBACK,
            TACBenchCategory.FEDERATED_IDENTITY_PIVOT,
        ],
    )
    def test_category_generation_and_reachability_invariants(
        self,
        generator: TACBenchGenerator,
        iampere_engine: IAMPEREBaselineEngine,
        category: TACBenchCategory,
    ) -> None:
        task = generator.generate_task(
            task_id=f"test_{category.value}",
            category=category,
            num_background_nodes=15,
        )

        assert task.category == category.value
        assert task.observed_graph.num_nodes >= 10
        assert task.ground_truth_graph.num_edges == task.observed_graph.num_edges + 1

        # Invariant 1: In ground truth G*, attacker can reach target crown jewel
        gt_witness = iampere_engine.check_reachability(
            task.ground_truth_graph,
            source_id=task.source_principal,
            target_id=task.target_crown_jewel,
        )
        assert gt_witness.is_reachable is True, f"Failed reachability on G* for {category}"
        assert gt_witness.status == "SAT"

        # Invariant 2: In observed G_o, attacker cannot reach crown jewel (hidden bridge severed)
        obs_witness = iampere_engine.check_reachability(
            task.observed_graph,
            source_id=task.source_principal,
            target_id=task.target_crown_jewel,
        )
        assert obs_witness.is_reachable is False, (
            f"Observed graph G_o was not severed for {category}"
        )
        assert obs_witness.status == "UNSAT"

        # Invariant 3: Positive and negative pairs exist and are disjoint
        assert len(task.pos_pairs) >= 1
        assert len(task.neg_pairs) >= 1
        pos_set = set(task.pos_pairs)
        neg_set = set(task.neg_pairs)
        assert pos_set.isdisjoint(neg_set)

    def test_task_to_hetero_data_conversion(self, generator: TACBenchGenerator) -> None:
        converter = IAMHeteroDataConverter()
        task = generator.generate_task(
            "test_hetero", TACBenchCategory.CICD_COMPROMISE, num_background_nodes=12
        )

        data = task.to_hetero_data(converter, use_observed=True)
        assert hasattr(data, "node_id_to_idx")
        assert "Role" in data.node_types
        assert data["Role"].x.size(0) >= 2
        assert data["Role"].x.dim() == 2

        # Check forward edge stores exist
        has_edges = any(data[edge_type].edge_index.size(1) > 0 for edge_type in data.edge_types)
        assert has_edges is True

    def test_benchmark_suite_generation_balance(self, generator: TACBenchGenerator) -> None:
        dataset = generator.generate_benchmark_suite(num_tasks=21, num_background_nodes=8)
        assert len(dataset) == 21
        summary = dataset.summary()
        # With 21 tasks across 7 categories, each category should have exactly 3 tasks
        for cat in TACBenchCategory:
            assert summary["categories"][cat.value] == 3
