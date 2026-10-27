"""TAC-Bench benchmark task schema, dataset container, and high-fidelity ingestion engine.

Provides formal data structures and generator pipelines for TAC-Bench (Hu et al. 2023–2026),
an access-control topology benchmark evaluating inductive link prediction and reachability
under partial observability and unqueryable organizational boundaries.

Supports 7 canonical access control topologies:
1. Multi-Account Privilege Escalation (`multi_account_pe`)
2. Cross-Account Delegation Chaining (`cross_account_delegation`)
3. Data Lake & Storage Governance (`data_lake_governance`)
4. Microservices Zero-Trust Pod Identities (`microservices_zero_trust`)
5. CI/CD & Service Role Compromise (`cicd_compromise`)
6. Dormant Administrative Policy Rollback (`dormant_policy_rollback`)
7. Federated Identity Provider Pivoting (`federated_identity_pivot`)
"""

from __future__ import annotations

import json
import logging
import random
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from iam.generator.graph import (
    EdgeRelation,
    GraphEdge,
    GraphNode,
    IAMGraph,
    NodeType,
)
from iam.parser.schema import Effect, PolicyDocument, Principal, Statement

if TYPE_CHECKING:
    from torch_geometric.data import HeteroData

    from iam.models.converter import IAMHeteroDataConverter

logger = logging.getLogger(__name__)


class TACBenchCategory(str, Enum):
    """Canonical access control architectural categories in TAC-Bench."""

    MULTI_ACCOUNT_PE = "multi_account_pe"
    CROSS_ACCOUNT_DELEGATION = "cross_account_delegation"
    DATA_LAKE_GOVERNANCE = "data_lake_governance"
    MICROSERVICES_ZERO_TRUST = "microservices_zero_trust"
    CICD_COMPROMISE = "cicd_compromise"
    DORMANT_POLICY_ROLLBACK = "dormant_policy_rollback"
    FEDERATED_IDENTITY_PIVOT = "federated_identity_pivot"


@dataclass
class TACBenchTask:
    """A discrete benchmark scenario in TAC-Bench.

    Encapsulates an observed graph G_o, ground truth graph G*, the masked bridge H,
    the attack source and target entities, and evaluation candidate pairs.
    """

    task_id: str
    category: str
    name: str
    description: str
    observed_graph: IAMGraph
    ground_truth_graph: IAMGraph
    hidden_bridge: tuple[str, str, str]  # (source_id, relation_name, target_id)
    source_principal: str
    target_crown_jewel: str
    pos_pairs: list[tuple[str, str]]
    neg_pairs: list[tuple[str, str]]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_hetero_data(
        self,
        converter: IAMHeteroDataConverter | None = None,
        use_observed: bool = True,
    ) -> HeteroData:
        """Convert observed or ground-truth graph to PyG HeteroData."""
        from iam.models.converter import IAMHeteroDataConverter

        conv = converter or IAMHeteroDataConverter()
        graph = self.observed_graph if use_observed else self.ground_truth_graph
        return conv.convert(graph)

    def to_dict(self) -> dict[str, Any]:
        """Serialize task to JSON-compatible dictionary."""
        return {
            "task_id": self.task_id,
            "category": self.category,
            "name": self.name,
            "description": self.description,
            "observed_graph": self.observed_graph.to_dict(),
            "ground_truth_graph": self.ground_truth_graph.to_dict(),
            "hidden_bridge": list(self.hidden_bridge),
            "source_principal": self.source_principal,
            "target_crown_jewel": self.target_crown_jewel,
            "pos_pairs": [list(p) for p in self.pos_pairs],
            "neg_pairs": [list(p) for p in self.neg_pairs],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TACBenchTask:
        """Deserialize task from a dictionary."""
        obs_g = IAMGraph.from_dict(data["observed_graph"])
        gt_g = IAMGraph.from_dict(data["ground_truth_graph"])
        hb_list = data["hidden_bridge"]
        hidden_bridge = (str(hb_list[0]), str(hb_list[1]), str(hb_list[2]))
        pos_pairs = [(str(p[0]), str(p[1])) for p in data.get("pos_pairs", [])]
        neg_pairs = [(str(p[0]), str(p[1])) for p in data.get("neg_pairs", [])]

        return cls(
            task_id=data["task_id"],
            category=data["category"],
            name=data["name"],
            description=data.get("description", ""),
            observed_graph=obs_g,
            ground_truth_graph=gt_g,
            hidden_bridge=hidden_bridge,
            source_principal=data["source_principal"],
            target_crown_jewel=data["target_crown_jewel"],
            pos_pairs=pos_pairs,
            neg_pairs=neg_pairs,
            metadata=data.get("metadata", {}),
        )

    def save_to_file(self, file_path: Path) -> None:
        """Save task to JSON file."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load_from_file(cls, file_path: Path) -> TACBenchTask:
        """Load task from JSON file."""
        data = json.loads(file_path.read_text(encoding="utf-8"))
        return cls.from_dict(data)


@dataclass
class TACBenchDataset:
    """Collection container for TAC-Bench benchmark tasks."""

    tasks: list[TACBenchTask] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.tasks)

    def __getitem__(self, idx: int) -> TACBenchTask:
        return self.tasks[idx]

    def __iter__(self) -> Any:
        return iter(self.tasks)

    def get_by_id(self, task_id: str) -> TACBenchTask | None:
        """Find task by its unique identifier."""
        for t in self.tasks:
            if t.task_id == task_id:
                return t
        return None

    def filter_by_category(self, category: str | TACBenchCategory) -> list[TACBenchTask]:
        """Filter tasks by architectural category."""
        cat_str = category.value if isinstance(category, TACBenchCategory) else category
        return [t for t in self.tasks if t.category == cat_str]

    def save_to_dir(self, directory: Path) -> None:
        """Save all tasks to individual JSON files inside directory."""
        directory.mkdir(parents=True, exist_ok=True)
        manifest: list[dict[str, Any]] = []

        for task in self.tasks:
            task_file = directory / f"{task.task_id}.json"
            task.save_to_file(task_file)
            manifest.append(
                {
                    "task_id": task.task_id,
                    "category": task.category,
                    "name": task.name,
                    "file": task_file.name,
                    "nodes_observed": task.observed_graph.num_nodes,
                    "edges_observed": task.observed_graph.num_edges,
                    "hidden_bridge": task.hidden_bridge,
                }
            )

        manifest_file = directory / "manifest.json"
        manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        logger.info(
            "Saved %d TAC-Bench tasks to %s (manifest: %s)",
            len(self.tasks),
            directory,
            manifest_file,
        )

    @classmethod
    def load_from_dir(cls, directory: Path) -> TACBenchDataset:
        """Load tasks from directory with manifest or json scan."""
        if not directory.exists():
            raise FileNotFoundError(f"TAC-Bench directory not found: {directory}")

        manifest_file = directory / "manifest.json"
        tasks: list[TACBenchTask] = []

        if manifest_file.exists():
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            for entry in manifest:
                t_file = directory / entry["file"]
                if t_file.exists():
                    tasks.append(TACBenchTask.load_from_file(t_file))
        else:
            for json_file in sorted(directory.glob("tac-*.json")):
                tasks.append(TACBenchTask.load_from_file(json_file))

        return cls(tasks=tasks)

    def summary(self) -> dict[str, Any]:
        """Compute dataset summary metrics."""
        categories: dict[str, int] = {}
        total_obs_nodes = 0
        total_obs_edges = 0

        for t in self.tasks:
            categories[t.category] = categories.get(t.category, 0) + 1
            total_obs_nodes += t.observed_graph.num_nodes
            total_obs_edges += t.observed_graph.num_edges

        n = len(self.tasks)
        return {
            "total_tasks": n,
            "categories": categories,
            "avg_observed_nodes": round(total_obs_nodes / max(1, n), 1),
            "avg_observed_edges": round(total_obs_edges / max(1, n), 1),
        }


class TACBenchGenerator:
    """High-fidelity procedural generator synthesizing the canonical TAC-Bench task distribution.

    Synthesizes realistic cross-account trust boundaries, pod identities, CI/CD pipelines,
    and dormant policies with exact ground-truth reachability and telemetry blackouts.
    """

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        self.rng = random.Random(seed)

    def generate_task(
        self,
        task_id: str,
        category: TACBenchCategory | str,
        num_background_nodes: int = 25,
    ) -> TACBenchTask:
        """Generate a single benchmark task for a specific category."""
        cat_enum = (
            category if isinstance(category, TACBenchCategory) else TACBenchCategory(category)
        )

        if cat_enum == TACBenchCategory.MULTI_ACCOUNT_PE:
            return self._gen_multi_account_pe(task_id, num_background_nodes)
        if cat_enum == TACBenchCategory.CROSS_ACCOUNT_DELEGATION:
            return self._gen_cross_account_delegation(task_id, num_background_nodes)
        if cat_enum == TACBenchCategory.DATA_LAKE_GOVERNANCE:
            return self._gen_data_lake_governance(task_id, num_background_nodes)
        if cat_enum == TACBenchCategory.MICROSERVICES_ZERO_TRUST:
            return self._gen_microservices_zero_trust(task_id, num_background_nodes)
        if cat_enum == TACBenchCategory.CICD_COMPROMISE:
            return self._gen_cicd_compromise(task_id, num_background_nodes)
        if cat_enum == TACBenchCategory.DORMANT_POLICY_ROLLBACK:
            return self._gen_dormant_policy_rollback(task_id, num_background_nodes)
        if cat_enum == TACBenchCategory.FEDERATED_IDENTITY_PIVOT:
            return self._gen_federated_identity_pivot(task_id, num_background_nodes)

        raise ValueError(f"Unsupported TAC-Bench category: {category}")

    def generate_benchmark_suite(
        self,
        num_tasks: int = 35,
        num_background_nodes: int = 20,
    ) -> TACBenchDataset:
        """Generate a balanced benchmark dataset across all 7 TAC-Bench categories.

        Args:
            num_tasks: Total number of tasks to generate.
            num_background_nodes: Average background noise nodes per environment.

        Returns:
            dataset: Populated TACBenchDataset with balanced task distribution.
        """
        categories = list(TACBenchCategory)
        tasks: list[TACBenchTask] = []

        for idx in range(num_tasks):
            cat = categories[idx % len(categories)]
            task_id = f"tac-task-{idx + 1:04d}"
            task = self.generate_task(
                task_id=task_id,
                category=cat,
                num_background_nodes=num_background_nodes,
            )
            tasks.append(task)

        return TACBenchDataset(tasks=tasks)

    # --------------------------------------------------------------------------
    # Category 1: Multi-Account Privilege Escalation
    # --------------------------------------------------------------------------
    def _gen_multi_account_pe(self, task_id: str, bg_nodes: int) -> TACBenchTask:
        g = IAMGraph(f"{task_id}_graph")
        acc_a = "111122223333"
        acc_b = "444455556666"
        acc_c = "777788889999"

        # 1. Attacker principal in Account A
        attacker = GraphNode(
            id=f"{task_id}_auditor_user",
            node_type=NodeType.USER,
            arn=f"arn:aws:iam::{acc_a}:user/security-auditor",
            name="security-auditor",
            account_id=acc_a,
            department="Security",
        )
        g.add_node(attacker)

        # 2. Intermediate Jump Role in Account B
        jump_role = GraphNode(
            id=f"{task_id}_jump_role",
            node_type=NodeType.ROLE,
            arn=f"arn:aws:iam::{acc_b}:role/staging-jump-role",
            name="staging-jump-role",
            account_id=acc_b,
            department="DevOps",
            trust_policy=PolicyDocument(
                Statement=[
                    Statement(
                        Effect=Effect.ALLOW,
                        Action=["sts:AssumeRole"],
                        Principal=Principal.model_validate({"AWS": [attacker.arn]}),
                    )
                ]
            ),
        )
        g.add_node(jump_role)

        # 3. Production Admin Role in Account C
        prod_admin = GraphNode(
            id=f"{task_id}_prod_admin_role",
            node_type=NodeType.ROLE,
            arn=f"arn:aws:iam::{acc_c}:role/production-admin-role",
            name="production-admin-role",
            account_id=acc_c,
            department="Production",
            is_admin=True,
            trust_policy=PolicyDocument(
                Statement=[
                    Statement(
                        Effect=Effect.ALLOW,
                        Action=["sts:AssumeRole"],
                        Principal=Principal.model_validate({"AWS": [jump_role.arn]}),
                    )
                ]
            ),
        )
        g.add_node(prod_admin)

        # 4. Crown jewel resource in Account C
        crown = GraphNode(
            id=f"{task_id}_vault_key",
            node_type=NodeType.RESOURCE,
            arn=f"arn:aws:kms:us-east-1:{acc_c}:key/production-vault-key",
            name="production-vault-key",
            account_id=acc_c,
            department="Production",
            is_high_value=True,
        )
        g.add_node(crown)

        # 5. Admin policy attached to Prod Admin
        admin_pol = GraphNode(
            id=f"{task_id}_admin_policy",
            node_type=NodeType.POLICY,
            arn=f"arn:aws:iam::{acc_c}:policy/AdministratorAccess",
            name="AdministratorAccess",
            account_id=acc_c,
            department="Production",
            policy_document=PolicyDocument(
                Statement=[
                    Statement(
                        Effect=Effect.ALLOW,
                        Action=["*"],
                        Resource=["*"],
                    )
                ]
            ),
        )
        g.add_node(admin_pol)

        # Edges
        # Legitimate first hop: Attacker -> Jump Role (AssumesRole)
        g.add_edge(
            GraphEdge(
                source=attacker.id,
                target=jump_role.id,
                relation=EdgeRelation.ASSUMES_ROLE,
                actions=["sts:AssumeRole"],
            )
        )
        # Policy attachments and action
        g.add_edge(
            GraphEdge(
                source=prod_admin.id,
                target=admin_pol.id,
                relation=EdgeRelation.ATTACHED_WITH,
            )
        )
        g.add_edge(
            GraphEdge(
                source=admin_pol.id,
                target=crown.id,
                relation=EdgeRelation.ACTS_ON,
                actions=["kms:Decrypt", "kms:*"],
            )
        )

        # The Hidden Bridge: Jump Role -> Prod Admin (AssumesRole)
        bridge_edge = GraphEdge(
            source=jump_role.id,
            target=prod_admin.id,
            relation=EdgeRelation.ASSUMES_ROLE,
            actions=["sts:AssumeRole"],
            is_bridge=True,
        )
        g.add_edge(bridge_edge)

        # Add background noise
        self._add_background_nodes(g, task_id, acc_b, bg_nodes)

        # Create observed graph by removing the bridge
        obs_g = g.clone()
        obs_g.remove_edge(jump_role.id, prod_admin.id, EdgeRelation.ASSUMES_ROLE)

        # Candidate evaluation pairs
        pos_pairs = [(jump_role.id, prod_admin.id)]
        neg_pairs = self._sample_negative_pairs(obs_g, pos_pairs, NodeType.ROLE, NodeType.ROLE)

        return TACBenchTask(
            task_id=task_id,
            category=TACBenchCategory.MULTI_ACCOUNT_PE.value,
            name="Multi-Account Cross-Jump Role Assumption Chain",
            description="Attacker assumes jump role in staging account to pivot into production admin role across trust boundary.",
            observed_graph=obs_g,
            ground_truth_graph=g,
            hidden_bridge=(jump_role.id, EdgeRelation.ASSUMES_ROLE.value, prod_admin.id),
            source_principal=attacker.id,
            target_crown_jewel=crown.id,
            pos_pairs=pos_pairs,
            neg_pairs=neg_pairs,
            metadata={
                "accounts": [acc_a, acc_b, acc_c],
                "hop_distance": 3,
                "vector": "sts:AssumeRole",
            },
        )

    # --------------------------------------------------------------------------
    # Category 2: Cross-Account Delegation Chaining
    # --------------------------------------------------------------------------
    def _gen_cross_account_delegation(self, task_id: str, bg_nodes: int) -> TACBenchTask:
        g = IAMGraph(f"{task_id}_graph")
        acc_ou = "222233334444"
        acc_target = "555566667777"

        attacker_role = GraphNode(
            id=f"{task_id}_partner_role",
            node_type=NodeType.ROLE,
            arn=f"arn:aws:iam::{acc_ou}:role/partner-analyst-role",
            name="partner-analyst-role",
            account_id=acc_ou,
            department="Analytics",
        )
        g.add_node(attacker_role)

        gateway_role = GraphNode(
            id=f"{task_id}_gateway_role",
            node_type=NodeType.ROLE,
            arn=f"arn:aws:iam::{acc_target}:role/internal-gateway-role",
            name="internal-gateway-role",
            account_id=acc_target,
            department="CoreServices",
            is_admin=True,
        )
        g.add_node(gateway_role)

        crown = GraphNode(
            id=f"{task_id}_finance_bucket",
            node_type=NodeType.RESOURCE,
            arn=f"arn:aws:s3:::partner-finance-records-{task_id}",
            name=f"partner-finance-records-{task_id}",
            account_id=acc_target,
            department="CoreServices",
            is_high_value=True,
        )
        g.add_node(crown)

        pol = GraphNode(
            id=f"{task_id}_gateway_pol",
            node_type=NodeType.POLICY,
            arn=f"arn:aws:iam::{acc_target}:policy/GatewayDataAccess",
            name="GatewayDataAccess",
            account_id=acc_target,
            department="CoreServices",
        )
        g.add_node(pol)

        g.add_edge(
            GraphEdge(
                source=gateway_role.id,
                target=pol.id,
                relation=EdgeRelation.ATTACHED_WITH,
            )
        )
        g.add_edge(
            GraphEdge(
                source=pol.id,
                target=crown.id,
                relation=EdgeRelation.ACTS_ON,
                actions=["s3:GetObject", "s3:ListBucket"],
            )
        )

        # Bridge: AssumesRole from partner role to gateway role
        g.add_edge(
            GraphEdge(
                source=attacker_role.id,
                target=gateway_role.id,
                relation=EdgeRelation.ASSUMES_ROLE,
                actions=["sts:AssumeRole"],
                is_bridge=True,
            )
        )

        self._add_background_nodes(g, task_id, acc_ou, bg_nodes)
        obs_g = g.clone()
        obs_g.remove_edge(attacker_role.id, gateway_role.id, EdgeRelation.ASSUMES_ROLE)

        pos_pairs = [(attacker_role.id, gateway_role.id)]
        neg_pairs = self._sample_negative_pairs(obs_g, pos_pairs, NodeType.ROLE, NodeType.ROLE)

        return TACBenchTask(
            task_id=task_id,
            category=TACBenchCategory.CROSS_ACCOUNT_DELEGATION.value,
            name="Organizational Unit Transitive Cross-Delegation",
            description="Transitive assume-role delegation between partner analytics role and internal gateway role.",
            observed_graph=obs_g,
            ground_truth_graph=g,
            hidden_bridge=(attacker_role.id, EdgeRelation.ASSUMES_ROLE.value, gateway_role.id),
            source_principal=attacker_role.id,
            target_crown_jewel=crown.id,
            pos_pairs=pos_pairs,
            neg_pairs=neg_pairs,
            metadata={"accounts": [acc_ou, acc_target], "vector": "sts:AssumeRole"},
        )

    # --------------------------------------------------------------------------
    # Category 3: Data Lake & Storage Governance
    # --------------------------------------------------------------------------
    def _gen_data_lake_governance(self, task_id: str, bg_nodes: int) -> TACBenchTask:
        g = IAMGraph(f"{task_id}_graph")
        acc = "123456789012"

        analyst = GraphNode(
            id=f"{task_id}_analyst_user",
            node_type=NodeType.USER,
            arn=f"arn:aws:iam::{acc}:user/contractor-analyst",
            name="contractor-analyst",
            account_id=acc,
            department="DataEngineering",
        )
        g.add_node(analyst)

        lake_role = GraphNode(
            id=f"{task_id}_lake_role",
            node_type=NodeType.ROLE,
            arn=f"arn:aws:iam::{acc}:role/lake-formation-governance-role",
            name="lake-formation-governance-role",
            account_id=acc,
            department="DataEngineering",
            is_admin=True,
        )
        g.add_node(lake_role)

        crown = GraphNode(
            id=f"{task_id}_lake_kms",
            node_type=NodeType.RESOURCE,
            arn=f"arn:aws:kms:us-east-1:{acc}:key/data-lake-master-key",
            name="data-lake-master-key",
            account_id=acc,
            department="DataEngineering",
            is_high_value=True,
        )
        g.add_node(crown)

        pol = GraphNode(
            id=f"{task_id}_lake_pol",
            node_type=NodeType.POLICY,
            arn=f"arn:aws:iam::{acc}:policy/LakeFormationAdminAccess",
            name="LakeFormationAdminAccess",
            account_id=acc,
            department="DataEngineering",
        )
        g.add_node(pol)

        g.add_edge(
            GraphEdge(
                source=lake_role.id,
                target=pol.id,
                relation=EdgeRelation.ATTACHED_WITH,
            )
        )
        g.add_edge(
            GraphEdge(
                source=pol.id,
                target=crown.id,
                relation=EdgeRelation.ACTS_ON,
                actions=["kms:Decrypt", "kms:DescribeKey"],
            )
        )

        # Bridge: User PassesTo / Assumes Role to lake_role
        g.add_edge(
            GraphEdge(
                source=analyst.id,
                target=lake_role.id,
                relation=EdgeRelation.PASSES_TO,
                actions=["iam:PassRole"],
                is_bridge=True,
            )
        )

        self._add_background_nodes(g, task_id, acc, bg_nodes)
        obs_g = g.clone()
        obs_g.remove_edge(analyst.id, lake_role.id, EdgeRelation.PASSES_TO)

        pos_pairs = [(analyst.id, lake_role.id)]
        neg_pairs = self._sample_negative_pairs(obs_g, pos_pairs, NodeType.USER, NodeType.ROLE)

        return TACBenchTask(
            task_id=task_id,
            category=TACBenchCategory.DATA_LAKE_GOVERNANCE.value,
            name="Data Lake Governance & Master KMS Delegation",
            description="Contractor analyst accesses data lake governance master key via unobserved PassRole bridge.",
            observed_graph=obs_g,
            ground_truth_graph=g,
            hidden_bridge=(analyst.id, EdgeRelation.PASSES_TO.value, lake_role.id),
            source_principal=analyst.id,
            target_crown_jewel=crown.id,
            pos_pairs=pos_pairs,
            neg_pairs=neg_pairs,
            metadata={"account_id": acc, "vector": "iam:PassRole"},
        )

    # --------------------------------------------------------------------------
    # Category 4: Microservices Zero-Trust Pod Identities
    # --------------------------------------------------------------------------
    def _gen_microservices_zero_trust(self, task_id: str, bg_nodes: int) -> TACBenchTask:
        g = IAMGraph(f"{task_id}_graph")
        acc = "333344445555"

        pod_role = GraphNode(
            id=f"{task_id}_pod_role",
            node_type=NodeType.ROLE,
            arn=f"arn:aws:iam::{acc}:role/frontend-pod-service-role",
            name="frontend-pod-service-role",
            account_id=acc,
            department="CloudInfrastructure",
        )
        g.add_node(pod_role)

        cluster_admin_role = GraphNode(
            id=f"{task_id}_cluster_admin_role",
            node_type=NodeType.ROLE,
            arn=f"arn:aws:iam::{acc}:role/eks-cluster-admin-worker-role",
            name="eks-cluster-admin-worker-role",
            account_id=acc,
            department="CloudInfrastructure",
            is_admin=True,
        )
        g.add_node(cluster_admin_role)

        crown = GraphNode(
            id=f"{task_id}_db_secret",
            node_type=NodeType.RESOURCE,
            arn=f"arn:aws:secretsmanager:us-east-1:{acc}:secret:db-master-credential",
            name="db-master-credential",
            account_id=acc,
            department="CloudInfrastructure",
            is_high_value=True,
        )
        g.add_node(crown)

        pol = GraphNode(
            id=f"{task_id}_cluster_admin_pol",
            node_type=NodeType.POLICY,
            arn=f"arn:aws:iam::{acc}:policy/ClusterAdminSecretsAccess",
            name="ClusterAdminSecretsAccess",
            account_id=acc,
            department="CloudInfrastructure",
        )
        g.add_node(pol)

        g.add_edge(
            GraphEdge(
                source=cluster_admin_role.id,
                target=pol.id,
                relation=EdgeRelation.ATTACHED_WITH,
            )
        )
        g.add_edge(
            GraphEdge(
                source=pol.id,
                target=crown.id,
                relation=EdgeRelation.ACTS_ON,
                actions=["secretsmanager:GetSecretValue"],
            )
        )

        # Bridge: iam:PassRole from pod_role to cluster_admin_role
        g.add_edge(
            GraphEdge(
                source=pod_role.id,
                target=cluster_admin_role.id,
                relation=EdgeRelation.PASSES_TO,
                actions=["iam:PassRole"],
                is_bridge=True,
            )
        )

        self._add_background_nodes(g, task_id, acc, bg_nodes)
        obs_g = g.clone()
        obs_g.remove_edge(pod_role.id, cluster_admin_role.id, EdgeRelation.PASSES_TO)

        pos_pairs = [(pod_role.id, cluster_admin_role.id)]
        neg_pairs = self._sample_negative_pairs(obs_g, pos_pairs, NodeType.ROLE, NodeType.ROLE)

        return TACBenchTask(
            task_id=task_id,
            category=TACBenchCategory.MICROSERVICES_ZERO_TRUST.value,
            name="EKS Pod Identity & Node Role Boundary Breach",
            description="Compromised pod identity role escalates to cluster admin worker role via unobserved PassRole link.",
            observed_graph=obs_g,
            ground_truth_graph=g,
            hidden_bridge=(pod_role.id, EdgeRelation.PASSES_TO.value, cluster_admin_role.id),
            source_principal=pod_role.id,
            target_crown_jewel=crown.id,
            pos_pairs=pos_pairs,
            neg_pairs=neg_pairs,
            metadata={"account_id": acc, "vector": "iam:PassRole"},
        )

    # --------------------------------------------------------------------------
    # Category 5: CI/CD & Service Role Compromise
    # --------------------------------------------------------------------------
    def _gen_cicd_compromise(self, task_id: str, bg_nodes: int) -> TACBenchTask:
        g = IAMGraph(f"{task_id}_graph")
        acc = "666677778888"

        runner_role = GraphNode(
            id=f"{task_id}_github_runner",
            node_type=NodeType.ROLE,
            arn=f"arn:aws:iam::{acc}:role/github-actions-builder",
            name="github-actions-builder",
            account_id=acc,
            department="DevOps",
        )
        g.add_node(runner_role)

        deployer_role = GraphNode(
            id=f"{task_id}_prod_deployer",
            node_type=NodeType.ROLE,
            arn=f"arn:aws:iam::{acc}:role/production-release-deployer",
            name="production-release-deployer",
            account_id=acc,
            department="DevOps",
            is_admin=True,
        )
        g.add_node(deployer_role)

        crown = GraphNode(
            id=f"{task_id}_release_s3",
            node_type=NodeType.RESOURCE,
            arn=f"arn:aws:s3:::production-artifact-registry-{task_id}",
            name=f"production-artifact-registry-{task_id}",
            account_id=acc,
            department="DevOps",
            is_high_value=True,
        )
        g.add_node(crown)

        pol = GraphNode(
            id=f"{task_id}_deploy_pol",
            node_type=NodeType.POLICY,
            arn=f"arn:aws:iam::{acc}:policy/ProductionReleaseArtifactsPolicy",
            name="ProductionReleaseArtifactsPolicy",
            account_id=acc,
            department="DevOps",
        )
        g.add_node(pol)

        g.add_edge(
            GraphEdge(
                source=deployer_role.id,
                target=pol.id,
                relation=EdgeRelation.ATTACHED_WITH,
            )
        )
        g.add_edge(
            GraphEdge(
                source=pol.id,
                target=crown.id,
                relation=EdgeRelation.ACTS_ON,
                actions=["s3:PutObject", "s3:DeleteObject"],
            )
        )

        # Bridge: AssumesRole from runner_role to deployer_role
        g.add_edge(
            GraphEdge(
                source=runner_role.id,
                target=deployer_role.id,
                relation=EdgeRelation.ASSUMES_ROLE,
                actions=["sts:AssumeRole"],
                is_bridge=True,
            )
        )

        self._add_background_nodes(g, task_id, acc, bg_nodes)
        obs_g = g.clone()
        obs_g.remove_edge(runner_role.id, deployer_role.id, EdgeRelation.ASSUMES_ROLE)

        pos_pairs = [(runner_role.id, deployer_role.id)]
        neg_pairs = self._sample_negative_pairs(obs_g, pos_pairs, NodeType.ROLE, NodeType.ROLE)

        return TACBenchTask(
            task_id=task_id,
            category=TACBenchCategory.CICD_COMPROMISE.value,
            name="CI/CD Build Runner Privilege Hijacking",
            description="GitHub Actions build runner pivots to production release deployer via unlogged AssumeRole bridge.",
            observed_graph=obs_g,
            ground_truth_graph=g,
            hidden_bridge=(runner_role.id, EdgeRelation.ASSUMES_ROLE.value, deployer_role.id),
            source_principal=runner_role.id,
            target_crown_jewel=crown.id,
            pos_pairs=pos_pairs,
            neg_pairs=neg_pairs,
            metadata={"account_id": acc, "vector": "sts:AssumeRole"},
        )

    # --------------------------------------------------------------------------
    # Category 6: Dormant Administrative Policy Rollback
    # --------------------------------------------------------------------------
    def _gen_dormant_policy_rollback(self, task_id: str, bg_nodes: int) -> TACBenchTask:
        g = IAMGraph(f"{task_id}_graph")
        acc = "888899990000"

        operator = GraphNode(
            id=f"{task_id}_maint_user",
            node_type=NodeType.USER,
            arn=f"arn:aws:iam::{acc}:user/maintenance-operator",
            name="maintenance-operator",
            account_id=acc,
            department="Operations",
        )
        g.add_node(operator)

        dormant_pol = GraphNode(
            id=f"{task_id}_dormant_admin_pol",
            node_type=NodeType.POLICY,
            arn=f"arn:aws:iam::{acc}:policy/DormantSuperAdminPolicy",
            name="DormantSuperAdminPolicy",
            account_id=acc,
            department="Operations",
            is_admin=True,
        )
        g.add_node(dormant_pol)

        crown = GraphNode(
            id=f"{task_id}_iam_root",
            node_type=NodeType.RESOURCE,
            arn=f"arn:aws:iam::{acc}:root",
            name="root",
            account_id=acc,
            department="Operations",
            is_high_value=True,
        )
        g.add_node(crown)

        g.add_edge(
            GraphEdge(
                source=dormant_pol.id,
                target=crown.id,
                relation=EdgeRelation.ACTS_ON,
                actions=["iam:*", "*"],
            )
        )

        # Bridge: AttachedWith from operator to dormant_pol
        g.add_edge(
            GraphEdge(
                source=operator.id,
                target=dormant_pol.id,
                relation=EdgeRelation.ATTACHED_WITH,
                actions=["iam:AttachUserPolicy", "iam:CreatePolicyVersion"],
                is_bridge=True,
            )
        )

        self._add_background_nodes(g, task_id, acc, bg_nodes)
        obs_g = g.clone()
        obs_g.remove_edge(operator.id, dormant_pol.id, EdgeRelation.ATTACHED_WITH)

        pos_pairs = [(operator.id, dormant_pol.id)]
        neg_pairs = self._sample_negative_pairs(obs_g, pos_pairs, NodeType.USER, NodeType.POLICY)

        return TACBenchTask(
            task_id=task_id,
            category=TACBenchCategory.DORMANT_POLICY_ROLLBACK.value,
            name="Dormant Administrative Policy Version Reversion",
            description="Operator identity re-attaches dormant administrative policy version recovering unrestricted account access.",
            observed_graph=obs_g,
            ground_truth_graph=g,
            hidden_bridge=(operator.id, EdgeRelation.ATTACHED_WITH.value, dormant_pol.id),
            source_principal=operator.id,
            target_crown_jewel=crown.id,
            pos_pairs=pos_pairs,
            neg_pairs=neg_pairs,
            metadata={"account_id": acc, "vector": "iam:CreatePolicyVersion"},
        )

    # --------------------------------------------------------------------------
    # Category 7: Federated Identity Provider Pivoting
    # --------------------------------------------------------------------------
    def _gen_federated_identity_pivot(self, task_id: str, bg_nodes: int) -> TACBenchTask:
        g = IAMGraph(f"{task_id}_graph")
        acc = "999900001111"

        federated_principal = GraphNode(
            id=f"{task_id}_saml_contractor",
            node_type=NodeType.USER,
            arn=f"arn:aws:iam::{acc}:saml-provider/OktaSAML/contractor-alice",
            name="contractor-alice",
            account_id=acc,
            department="ExternalVendor",
        )
        g.add_node(federated_principal)

        gateway_role = GraphNode(
            id=f"{task_id}_federated_gateway",
            node_type=NodeType.ROLE,
            arn=f"arn:aws:iam::{acc}:role/federated-staging-gateway",
            name="federated-staging-gateway",
            account_id=acc,
            department="CloudInfrastructure",
            is_admin=True,
        )
        g.add_node(gateway_role)

        crown = GraphNode(
            id=f"{task_id}_financial_db",
            node_type=NodeType.RESOURCE,
            arn=f"arn:aws:rds:us-east-1:{acc}:db:customer-financial-vault",
            name="customer-financial-vault",
            account_id=acc,
            department="CloudInfrastructure",
            is_high_value=True,
        )
        g.add_node(crown)

        pol = GraphNode(
            id=f"{task_id}_rds_admin_pol",
            node_type=NodeType.POLICY,
            arn=f"arn:aws:iam::{acc}:policy/RDSFinancialVaultAdminAccess",
            name="RDSFinancialVaultAdminAccess",
            account_id=acc,
            department="CloudInfrastructure",
        )
        g.add_node(pol)

        g.add_edge(
            GraphEdge(
                source=gateway_role.id,
                target=pol.id,
                relation=EdgeRelation.ATTACHED_WITH,
            )
        )
        g.add_edge(
            GraphEdge(
                source=pol.id,
                target=crown.id,
                relation=EdgeRelation.ACTS_ON,
                actions=["rds-db:connect", "rds:*"],
            )
        )

        # Bridge: AssumesRole from saml_contractor to gateway_role
        g.add_edge(
            GraphEdge(
                source=federated_principal.id,
                target=gateway_role.id,
                relation=EdgeRelation.ASSUMES_ROLE,
                actions=["sts:AssumeRoleWithSAML"],
                is_bridge=True,
            )
        )

        self._add_background_nodes(g, task_id, acc, bg_nodes)
        obs_g = g.clone()
        obs_g.remove_edge(federated_principal.id, gateway_role.id, EdgeRelation.ASSUMES_ROLE)

        pos_pairs = [(federated_principal.id, gateway_role.id)]
        neg_pairs = self._sample_negative_pairs(obs_g, pos_pairs, NodeType.USER, NodeType.ROLE)

        return TACBenchTask(
            task_id=task_id,
            category=TACBenchCategory.FEDERATED_IDENTITY_PIVOT.value,
            name="Federated SAML Identity Provider Pivoting",
            description="External vendor SAML identity assumes unobserved internal staging gateway role granting financial database access.",
            observed_graph=obs_g,
            ground_truth_graph=g,
            hidden_bridge=(
                federated_principal.id,
                EdgeRelation.ASSUMES_ROLE.value,
                gateway_role.id,
            ),
            source_principal=federated_principal.id,
            target_crown_jewel=crown.id,
            pos_pairs=pos_pairs,
            neg_pairs=neg_pairs,
            metadata={"account_id": acc, "vector": "sts:AssumeRoleWithSAML"},
        )

    # --------------------------------------------------------------------------
    # Background Topology & Negative Sampling Helpers
    # --------------------------------------------------------------------------
    def _add_background_nodes(
        self,
        g: IAMGraph,
        prefix: str,
        account_id: str,
        count: int,
    ) -> None:
        """Inject benign background nodes and edges into the graph."""
        departments = ["Engineering", "Product", "Analytics", "Operations"]

        bg_users: list[GraphNode] = []
        bg_roles: list[GraphNode] = []
        bg_pols: list[GraphNode] = []
        bg_res: list[GraphNode] = []

        for i in range(count):
            dept = self.rng.choice(departments)
            n_type = self.rng.choice(
                [NodeType.USER, NodeType.ROLE, NodeType.POLICY, NodeType.RESOURCE]
            )
            nid = f"{prefix}_bg_{i}"

            if n_type == NodeType.USER:
                node = GraphNode(
                    id=nid,
                    node_type=NodeType.USER,
                    arn=f"arn:aws:iam::{account_id}:user/bg-user-{i}",
                    name=f"bg-user-{i}",
                    account_id=account_id,
                    department=dept,
                )
                bg_users.append(node)
            elif n_type == NodeType.ROLE:
                node = GraphNode(
                    id=nid,
                    node_type=NodeType.ROLE,
                    arn=f"arn:aws:iam::{account_id}:role/bg-role-{i}",
                    name=f"bg-role-{i}",
                    account_id=account_id,
                    department=dept,
                )
                bg_roles.append(node)
            elif n_type == NodeType.POLICY:
                node = GraphNode(
                    id=nid,
                    node_type=NodeType.POLICY,
                    arn=f"arn:aws:iam::{account_id}:policy/bg-policy-{i}",
                    name=f"bg-policy-{i}",
                    account_id=account_id,
                    department=dept,
                )
                bg_pols.append(node)
            else:
                node = GraphNode(
                    id=nid,
                    node_type=NodeType.RESOURCE,
                    arn=f"arn:aws:s3:::bg-bucket-{i}",
                    name=f"bg-bucket-{i}",
                    account_id=account_id,
                    department=dept,
                )
                bg_res.append(node)

            g.add_node(node)

        # Connect some benign background edges
        for u in bg_users:
            if bg_pols and self.rng.random() < 0.6:
                p = self.rng.choice(bg_pols)
                g.add_edge(GraphEdge(source=u.id, target=p.id, relation=EdgeRelation.ATTACHED_WITH))
            if bg_roles and self.rng.random() < 0.3:
                r = self.rng.choice(bg_roles)
                g.add_edge(GraphEdge(source=u.id, target=r.id, relation=EdgeRelation.ASSUMES_ROLE))

        for r in bg_roles:
            if bg_pols and self.rng.random() < 0.6:
                p = self.rng.choice(bg_pols)
                g.add_edge(GraphEdge(source=r.id, target=p.id, relation=EdgeRelation.ATTACHED_WITH))

        for p in bg_pols:
            if bg_res and self.rng.random() < 0.5:
                res = self.rng.choice(bg_res)
                g.add_edge(
                    GraphEdge(
                        source=p.id,
                        target=res.id,
                        relation=EdgeRelation.ACTS_ON,
                        actions=["s3:GetObject"],
                    )
                )

    def _sample_negative_pairs(
        self,
        g: IAMGraph,
        pos_pairs: list[tuple[str, str]],
        src_type: NodeType,
        dst_type: NodeType,
        target_count: int = 15,
    ) -> list[tuple[str, str]]:
        """Stratified sampling of non-escalating candidate pairs matching entity types."""
        src_nodes = [n.id for n in g.get_nodes() if n.node_type == src_type]
        dst_nodes = [n.id for n in g.get_nodes() if n.node_type == dst_type]

        existing_edges = {(e.source, e.target) for e in g.get_edges()}
        pos_set = set(pos_pairs)

        candidates: list[tuple[str, str]] = []
        for u in src_nodes:
            for v in dst_nodes:
                if u != v and (u, v) not in existing_edges and (u, v) not in pos_set:
                    candidates.append((u, v))

        self.rng.shuffle(candidates)
        return candidates[:target_count]
