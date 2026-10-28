"""Unit and integration tests for MultiCloudCapabilityModel (AWS, Azure RBAC, GCP IAM)."""

from __future__ import annotations

from pathlib import Path

from iam.parser.multi_cloud import (
    AzureScopeLevel,
    CloudProvider,
    GCPAccessLevel,
    MultiCloudCapabilityModel,
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

        report_file = tmp_path / "multi_cloud_report.md"
        json_file = tmp_path / "multi_cloud_summary.json"
        assert report_file.is_file()
        assert json_file.is_file()
        assert "Multi-Cloud Authorization Capability" in report_file.read_text(encoding="utf-8")

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
