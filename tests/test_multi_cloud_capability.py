"""Unit and integration tests for MultiCloudCapabilityModel (AWS, Azure RBAC, GCP IAM)."""

from __future__ import annotations

from pathlib import Path

from iam.generator.graph import EdgeRelation, NodeType
from iam.parser.multi_cloud import (
    AzureRoleAssignment,
    AzureScopeLevel,
    CloudProvider,
    CrossCloudFederationTrust,
    GCPAccessLevel,
    GCPIAMBinding,
    MultiCloudCapabilityModel,
    MultiCloudGraphAdapter,
    create_canonical_multi_cloud_topology,
    is_azure_scope_contained,
    is_gcp_resource_contained,
    load_default_multi_cloud_model,
)


class TestMultiCloudCapabilityModel:
    """Test suite verifying cross-cloud authorization constraints and capability enforcement."""

    def test_load_default_multi_cloud_model(self) -> None:
        """Verify loading default multi-cloud capability snapshot from disk."""
        model = load_default_multi_cloud_model()
        assert isinstance(model, MultiCloudCapabilityModel)
        assert len(model.azure_actions) > 0
        assert len(model.gcp_permissions) > 0

    def test_azure_scope_parsing(self) -> None:
        """Verify parsing of Azure scope URIs into proper AzureScopeLevel enum."""
        model = load_default_multi_cloud_model()

        mg = "/providers/Microsoft.Management/managementGroups/prod-mg"
        assert model.parse_azure_scope_level(mg) == AzureScopeLevel.MANAGEMENT_GROUP

        sub = "/subscriptions/12345678-1234-1234-1234-123456789012"
        assert model.parse_azure_scope_level(sub) == AzureScopeLevel.SUBSCRIPTION

        rg = "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/secops-rg"
        assert model.parse_azure_scope_level(rg) == AzureScopeLevel.RESOURCE_GROUP

        vm = "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/secops-rg/providers/Microsoft.Compute/virtualMachines/worker-vm"
        assert model.parse_azure_scope_level(vm) == AzureScopeLevel.RESOURCE

    def test_gcp_level_parsing(self) -> None:
        """Verify parsing of GCP resource hierarchy strings."""
        model = load_default_multi_cloud_model()

        assert model.parse_gcp_level("organizations/123456789") == GCPAccessLevel.ORGANIZATION
        assert model.parse_gcp_level("folders/987654321") == GCPAccessLevel.FOLDER
        assert model.parse_gcp_level("projects/my-prod-project") == GCPAccessLevel.PROJECT
        assert (
            model.parse_gcp_level("projects/my-prod-project/zones/us-central1-a/instances/vm-1")
            == GCPAccessLevel.RESOURCE
        )

    def test_azure_capability_validation(self) -> None:
        """Verify Azure RBAC action scope constraints."""
        model = load_default_multi_cloud_model()

        # KeyVault read secrets can only be scoped at resource level
        kv_act = "Microsoft.KeyVault/vaults/secrets/read"
        valid_kv = "/subscriptions/123/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault1/secrets/sec1"
        invalid_kv = "/subscriptions/123"

        assert model.is_valid_transformation(CloudProvider.AZURE, kv_act, valid_kv) is True
        assert model.is_valid_transformation(CloudProvider.AZURE, kv_act, invalid_kv) is False

        # VirtualMachines write cannot be scoped at tenant or management group
        vm_act = "Microsoft.Compute/virtualMachines/write"
        assert (
            model.is_valid_transformation(
                CloudProvider.AZURE,
                vm_act,
                "/providers/Microsoft.Management/managementGroups/mg",
            )
            is False
        )
        assert (
            model.is_valid_transformation(
                CloudProvider.AZURE,
                vm_act,
                "/subscriptions/123/resourceGroups/secops",
            )
            is True
        )

    def test_gcp_capability_validation(self) -> None:
        """Verify GCP IAM permission level constraints."""
        model = load_default_multi_cloud_model()

        # setIamPolicy can be bound at org, folder, or project level
        set_iam = "resourcemanager.projects.setIamPolicy"
        assert (
            model.is_valid_transformation(CloudProvider.GCP, set_iam, "projects/prod-project")
            is True
        )
        assert (
            model.is_valid_transformation(CloudProvider.GCP, set_iam, "organizations/12345") is True
        )

        # actAs permission can be bound at project or resource level
        act_as = "iam.serviceAccounts.actAs"
        assert (
            model.is_valid_transformation(CloudProvider.GCP, act_as, "projects/prod-project")
            is True
        )
        assert (
            model.is_valid_transformation(CloudProvider.GCP, act_as, "organizations/12345") is False
        )

    def test_aws_backward_compatibility(self) -> None:
        """Verify that AWS validations still run identically through MultiCloudCapabilityModel."""
        model = load_default_multi_cloud_model()

        # iam:PassRole valid on role ARN, invalid on S3
        assert (
            model.is_valid_transformation(
                CloudProvider.AWS,
                "iam:PassRole",
                "arn:aws:iam::123456789012:role/worker-role",
            )
            is True
        )
        assert (
            model.is_valid_transformation(
                CloudProvider.AWS,
                "iam:PassRole",
                "arn:aws:s3:::my-bucket",
            )
            is False
        )

    def test_multi_cloud_evaluation_runner(self, tmp_path: Path) -> None:
        """Verify automated execution and artifact generation of MultiCloudEvaluationRunner."""
        from iam.verifier.multi_cloud_eval import MultiCloudEvaluationRunner

        runner = MultiCloudEvaluationRunner()
        res = runner.run_suite(output_dir=tmp_path, seed=42)

        assert res.total_rules_tested >= 20
        assert res.conformance_pass_rate == 100.0
        assert res.illegal_transformations_blocked_pct == 100.0
        assert res.remediation_utility_preserved_pct == 100.0
        assert "aws" in res.provider_metrics
        assert "azure" in res.provider_metrics
        assert "gcp" in res.provider_metrics
        assert len(res.cross_cloud_path_nodes) >= 6
        assert res.cross_cloud_remediation_verified is True

        report_file = tmp_path / "multi_cloud_report.md"
        json_file = tmp_path / "multi_cloud_summary.json"
        assert report_file.is_file()
        assert json_file.is_file()
        assert "Multi-Cloud Authorization Capability" in report_file.read_text(encoding="utf-8")
        assert (
            "Cross-Cloud Lateral Movement & Federation Remediation Analysis"
            in report_file.read_text(encoding="utf-8")
        )

    def test_synthesize_remediation_patch(self) -> None:
        """Verify cross-cloud remediation patch synthesis across AWS, Azure, and GCP."""
        model = load_default_multi_cloud_model()

        # Azure role assignment scoping
        az_patch = model.synthesize_remediation_patch(
            provider=CloudProvider.AZURE,
            principal_id="user:devops-engineer",
            action_or_role="Microsoft.Compute/virtualMachines/read",
            original_scope="/",
            remediated_scope="/subscriptions/sub-1/resourceGroups/rg-1",
            risk_mitigated="Tenant-level VM discovery escalation cut",
        )
        assert az_patch.is_valid is True
        assert az_patch.provider == CloudProvider.AZURE
        assert '-  "scope": "/"' in az_patch.policy_diff
        assert '+  "scope": "/subscriptions/sub-1/resourceGroups/rg-1"' in az_patch.policy_diff

        # GCP IAM project scoping
        gcp_patch = model.synthesize_remediation_patch(
            provider=CloudProvider.GCP,
            principal_id="user:analyst@corp.internal",
            action_or_role="compute.instances.create",
            original_scope="organizations/12345",
            remediated_scope="projects/core-prod",
            risk_mitigated="Org-level compute takeover privilege cut",
        )
        assert gcp_patch.is_valid is True
        assert gcp_patch.provider == CloudProvider.GCP
        assert '+  "resource": "projects/core-prod"' in gcp_patch.policy_diff

    def test_azure_scope_containment(self) -> None:
        """Verify hierarchical containment evaluation for Azure RBAC scopes."""
        # Root tenant contains all scopes
        assert is_azure_scope_contained("/subscriptions/sub-1", "/") is True
        assert is_azure_scope_contained("/subscriptions/sub-1/resourceGroups/rg-1", "") is True

        # Subscription contains resource groups and resources within it
        sub = "/subscriptions/12345678-1234-1234-1234-123456789012"
        rg = f"{sub}/resourceGroups/secops-rg"
        res = f"{rg}/providers/Microsoft.KeyVault/vaults/vault1"

        assert is_azure_scope_contained(rg, sub) is True
        assert is_azure_scope_contained(res, sub) is True
        assert is_azure_scope_contained(res, rg) is True
        assert is_azure_scope_contained(sub, sub) is True

        # Non-overlapping scopes
        other_sub = "/subscriptions/99999999-9999-9999-9999-999999999999"
        assert is_azure_scope_contained(other_sub, sub) is False
        assert is_azure_scope_contained(sub, rg) is False  # Child does not contain parent

        # Avoid prefix collision without boundary
        sub_colliding = f"{sub}-extra/resourceGroups/rg"
        assert is_azure_scope_contained(sub_colliding, sub) is False

    def test_gcp_resource_containment(self) -> None:
        """Verify hierarchical containment evaluation for Google Cloud IAM resources."""
        proj = "projects/prod-cluster-01"
        topic = f"{proj}/topics/security-alerts"

        assert is_gcp_resource_contained(proj, proj) is True
        assert is_gcp_resource_contained(topic, proj) is True
        assert is_gcp_resource_contained("projects/other-proj", proj) is False

        # Avoid prefix false positives
        assert is_gcp_resource_contained("projects/prod-cluster-01-dev/topics/t1", proj) is False

        # Dynamic hierarchy map resolution (project -> folder -> org)
        hierarchy_map = {
            "projects/prod-cluster-01": "folders/engineering",
            "folders/engineering": "organizations/1000000001",
        }
        assert (
            is_gcp_resource_contained(
                "projects/prod-cluster-01", "organizations/1000000001", hierarchy_map
            )
            is True
        )
        assert (
            is_gcp_resource_contained(
                "projects/prod-cluster-01", "folders/engineering", hierarchy_map
            )
            is True
        )
        assert (
            is_gcp_resource_contained(
                "projects/unmapped-proj", "organizations/1000000001", hierarchy_map
            )
            is False
        )

    def test_multi_cloud_graph_adapter_ingestion(self) -> None:
        """Verify ingestion of Azure, GCP, and federation trusts into IAMGraph via MultiCloudGraphAdapter."""
        adapter = MultiCloudGraphAdapter()

        az_assignments = [
            AzureRoleAssignment(
                principal_id="sp-finops-automation",
                role_definition_name="Cost Management Reader",
                scope="/subscriptions/sub-100",
                principal_type="ServicePrincipal",
            ),
            AzureRoleAssignment(
                principal_id="user-auditor@enterprise.com",
                role_definition_name="Reader",
                scope="/subscriptions/sub-100/resourceGroups/rg-audit",
                principal_type="User",
            ),
        ]

        gcp_bindings = [
            GCPIAMBinding(
                role="roles/viewer",
                members=[
                    "user:auditor@enterprise.com",
                    "serviceAccount:sa-worker@proj.iam.gserviceaccount.com",
                    "group:security-team@enterprise.com",
                ],
                resource="projects/proj-data",
            )
        ]

        cross_trusts = [
            CrossCloudFederationTrust(
                trust_id="trust-az-sp-to-gcp-sa",
                source_cloud=CloudProvider.AZURE,
                source_identity="sp-finops-automation",
                target_cloud=CloudProvider.GCP,
                target_identity="serviceAccount:sa-worker@proj.iam.gserviceaccount.com",
                federation_type="WorkloadIdentity",
            )
        ]

        graph = adapter.build_multicloud_graph(
            graph_id="test_multicloud_ingestion",
            azure_assignments=az_assignments,
            gcp_bindings=gcp_bindings,
            cross_cloud_trusts=cross_trusts,
        )

        assert graph.num_nodes > 0
        assert graph.num_edges > 0

        # Verify Azure nodes
        az_sp = graph.get_node("azure:sp-finops-automation")
        assert az_sp is not None
        assert az_sp.node_type == NodeType.ROLE
        assert az_sp.metadata["provider"] == "azure"

        az_user = graph.get_node("azure:user-auditor@enterprise.com")
        assert az_user is not None
        assert az_user.node_type == NodeType.USER

        # Verify GCP nodes
        gcp_sa = graph.get_node("gcp:serviceAccount:sa-worker@proj.iam.gserviceaccount.com")
        assert gcp_sa is not None
        assert gcp_sa.node_type == NodeType.ROLE

        gcp_group = graph.get_node("gcp:group:security-team@enterprise.com")
        assert gcp_group is not None
        assert gcp_group.node_type == NodeType.GROUP

        gcp_res = graph.get_node("gcp:resource:projects/proj-data")
        assert gcp_res is not None
        assert gcp_res.node_type == NodeType.RESOURCE

        # Verify federation edge
        bridge_edges = graph.get_bridge_edges()
        assert len(bridge_edges) >= 1
        fed_edge = bridge_edges[0]
        assert fed_edge.source == "azure:sp-finops-automation"
        assert fed_edge.target == "gcp:serviceAccount:sa-worker@proj.iam.gserviceaccount.com"
        assert fed_edge.relation == EdgeRelation.ASSUMES_ROLE
        assert fed_edge.metadata["cross_cloud"] is True

    def test_canonical_multi_cloud_topology_reachability_and_cut(self) -> None:
        """Verify reachability and least-privilege remediation cut on canonical 3-cloud topology."""
        graph = create_canonical_multi_cloud_topology()
        adapter = MultiCloudGraphAdapter()

        # Check graph contents
        assert graph.num_nodes >= 6
        assert graph.num_edges >= 5

        # Check that high-value target is flagged
        hvts = graph.get_high_value_targets()
        assert len(hvts) == 1
        hvt_id = hvts[0].id
        assert hvt_id == "gcp:resource:organizations/org-corp-enterprise"

        # Trace attack path from Azure SP to GCP Org Admin resource
        source_id = "azure:sp-devops-ci"
        paths = adapter.find_cross_cloud_escalation_paths(
            graph, source_id=source_id, target_id=hvt_id
        )
        assert len(paths) >= 1

        attack_path = paths[0]
        # Expected sequence:
        # 1. azure:sp-devops-ci
        # 2. arn:aws:iam::123456789012:role/CrossCloudDeploymentRole
        # 3. arn:aws:iam::123456789012:role/GCPWorkloadIdentityFederator
        # 4. gcp:serviceAccount:deployer@corp-enterprise.iam.gserviceaccount.com
        # 5. gcp:role:roles/resourcemanager.organizationAdmin
        # 6. gcp:resource:organizations/org-corp-enterprise
        assert attack_path[0] == source_id
        assert attack_path[-1] == hvt_id
        assert "arn:aws:iam::123456789012:role/CrossCloudDeploymentRole" in attack_path
        assert "gcp:serviceAccount:deployer@corp-enterprise.iam.gserviceaccount.com" in attack_path

        # Perform Remediation: Cut internal AWS lateral pivot edge
        removed = graph.remove_edge(
            source="arn:aws:iam::123456789012:role/CrossCloudDeploymentRole",
            target="arn:aws:iam::123456789012:role/GCPWorkloadIdentityFederator",
            relation=EdgeRelation.ASSUMES_ROLE,
        )
        assert removed is True

        # Verify that attack path is now broken
        remediated_paths = adapter.find_cross_cloud_escalation_paths(
            graph, source_id=source_id, target_id=hvt_id
        )
        assert len(remediated_paths) == 0
