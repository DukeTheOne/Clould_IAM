"""Multi-Cloud Action Capability Specification and Validation Module.

Extends the AWS Action Capability Model C(a, r, c) to Azure Role-Based Access Control (RBAC)
and Google Cloud IAM policy frameworks. Formalizes provider-specific scope hierarchies,
data vs. control action dichotomies, and conditional access semantics.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from iam.parser.capability import CapabilityModel, load_default_capability_model


class CloudProvider(str, Enum):
    """Supported enterprise cloud authorization providers."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class AzureScopeLevel(str, Enum):
    """Hierarchical scope levels in Microsoft Azure resource management."""

    TENANT = "tenant"
    MANAGEMENT_GROUP = "management_group"
    SUBSCRIPTION = "subscription"
    RESOURCE_GROUP = "resource_group"
    RESOURCE = "resource"


class GCPAccessLevel(str, Enum):
    """Hierarchical resource levels in Google Cloud Resource Manager."""

    ORGANIZATION = "organization"
    FOLDER = "folder"
    PROJECT = "project"
    RESOURCE = "resource"


class AzureActionCapability(BaseModel):
    """Specification of access constraints for an Azure RBAC action."""

    model_config = ConfigDict(frozen=True)

    action: str
    service: str
    is_data_action: bool = False
    supported_scopes: list[AzureScopeLevel] = Field(default_factory=list)
    wildcard_only: bool = False
    condition_keys: list[str] = Field(default_factory=list)

    def is_scope_admissible(self, scope_level: AzureScopeLevel) -> bool:
        """Verify whether action can be granted or scoped at the designated Azure scope level."""
        return scope_level in self.supported_scopes


class GCPPermissionCapability(BaseModel):
    """Specification of access constraints for a Google Cloud IAM permission."""

    model_config = ConfigDict(frozen=True)

    permission: str
    service: str
    supported_levels: list[GCPAccessLevel] = Field(default_factory=list)
    wildcard_only: bool = False
    condition_keys: list[str] = Field(default_factory=list)

    def is_level_admissible(self, level: GCPAccessLevel) -> bool:
        """Verify whether permission can be bound at the designated GCP resource hierarchy level."""
        return level in self.supported_levels


class MultiCloudCapabilityModel:
    """Unified multi-cloud capability model spanning AWS, Azure RBAC, and GCP IAM."""

    def __init__(
        self,
        aws_model: CapabilityModel | None = None,
        azure_actions: dict[str, AzureActionCapability] | None = None,
        gcp_permissions: dict[str, GCPPermissionCapability] | None = None,
    ) -> None:
        self.aws_model: CapabilityModel = aws_model or load_default_capability_model()
        self.azure_actions: dict[str, AzureActionCapability] = azure_actions or {}
        self.gcp_permissions: dict[str, GCPPermissionCapability] = gcp_permissions or {}

    @classmethod
    def load_from_json(
        cls,
        json_path: Path | str,
        aws_model: CapabilityModel | None = None,
    ) -> MultiCloudCapabilityModel:
        """Load multi-cloud capability definitions from JSON file."""
        p = Path(json_path)
        if not p.is_file():
            raise FileNotFoundError(f"Multi-cloud capability file not found at: {p}")

        data: dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))

        # Parse Azure
        az_actions: dict[str, AzureActionCapability] = {}
        az_raw = data.get("azure", {}).get("actions", {})
        for act_name, raw in az_raw.items():
            scopes = [AzureScopeLevel(s) for s in raw.get("supported_scopes", [])]
            az_actions[act_name.lower()] = AzureActionCapability(
                action=raw["action"],
                service=raw.get("service", act_name.split("/")[0]),
                is_data_action=raw.get("is_data_action", False),
                supported_scopes=scopes,
                wildcard_only=raw.get("wildcard_only", False),
                condition_keys=raw.get("condition_keys", []),
            )

        # Parse GCP
        gcp_perms: dict[str, GCPPermissionCapability] = {}
        gcp_raw = data.get("gcp", {}).get("permissions", {})
        for perm_name, raw in gcp_raw.items():
            levels = [GCPAccessLevel(lv) for lv in raw.get("supported_levels", [])]
            gcp_perms[perm_name.lower()] = GCPPermissionCapability(
                permission=raw["permission"],
                service=raw.get("service", perm_name.split(".")[0]),
                supported_levels=levels,
                wildcard_only=raw.get("wildcard_only", False),
                condition_keys=raw.get("condition_keys", []),
            )

        return cls(
            aws_model=aws_model,
            azure_actions=az_actions,
            gcp_permissions=gcp_perms,
        )

    def parse_azure_scope_level(self, scope_string: str) -> AzureScopeLevel:
        """Infer Azure scope level from a resource ID or scope URI."""
        s = scope_string.strip().lower()
        if s.startswith("/providers/microsoft.management/managementgroups/"):
            return AzureScopeLevel.MANAGEMENT_GROUP
        if s.startswith("/subscriptions/") and "/resourcegroups/" not in s:
            return AzureScopeLevel.SUBSCRIPTION
        if "/resourcegroups/" in s and "/providers/" not in s.split("/resourcegroups/")[1]:
            return AzureScopeLevel.RESOURCE_GROUP
        if "/providers/" in s:
            return AzureScopeLevel.RESOURCE
        return AzureScopeLevel.TENANT

    def parse_gcp_level(self, resource_name: str) -> GCPAccessLevel:
        """Infer GCP hierarchy level from a resource name prefix."""
        r = resource_name.strip().lower()
        if r.startswith("organizations/"):
            return GCPAccessLevel.ORGANIZATION
        if r.startswith("folders/"):
            return GCPAccessLevel.FOLDER
        if r.startswith("projects/") and "/locations/" not in r and "/zones/" not in r:
            return GCPAccessLevel.PROJECT
        return GCPAccessLevel.RESOURCE

    def is_valid_transformation(
        self,
        provider: CloudProvider,
        action: str,
        target_resource: str,
        condition_key: str | None = None,
    ) -> bool:
        """Validate proposed least-privilege repair transformation for specified cloud provider.

        Args:
            provider: CloudProvider enum (AWS, AZURE, GCP).
            action: Action, permission, or operation string.
            target_resource: Resource ARN, Azure scope URI, or GCP resource path.
            condition_key: Optional context condition key.

        Returns:
            True if the proposed scoping/condition transformation is grammatically valid.
        """
        if provider == CloudProvider.AWS:
            cap = self.aws_model.get_action_capability(action)
            if cap is None:
                return True
            if cap.wildcard_only and target_resource != "*":
                return False
            if target_resource != "*" and not cap.matches_resource_type(target_resource):
                return False
            if condition_key is not None:
                return cap.supports_condition_key(
                    condition_key, self.aws_model.global_condition_keys
                )
            return True

        if provider == CloudProvider.AZURE:
            act_cap = self.azure_actions.get(action.lower())
            if act_cap is None:
                return True
            scope_lvl = self.parse_azure_scope_level(target_resource)
            if not act_cap.is_scope_admissible(scope_lvl):
                return False
            if condition_key is not None and act_cap.condition_keys:
                return condition_key in act_cap.condition_keys
            return True

        if provider == CloudProvider.GCP:
            perm_cap = self.gcp_permissions.get(action.lower())
            if perm_cap is None:
                return True
            gcp_lvl = self.parse_gcp_level(target_resource)
            if not perm_cap.is_level_admissible(gcp_lvl):
                return False
            if condition_key is not None and perm_cap.condition_keys:
                return condition_key in perm_cap.condition_keys
            return True

        return False

    def synthesize_remediation_patch(
        self,
        provider: CloudProvider,
        principal_id: str,
        action_or_role: str,
        original_scope: str,
        remediated_scope: str,
        risk_mitigated: str = "Privilege Escalation Cut",
    ) -> MultiCloudRemediationPatch:
        """Synthesize a capability-checked least-privilege remediation patch with structured diff.

        Args:
            provider: CloudProvider enum (AWS, AZURE, GCP).
            principal_id: Identity identifier (e.g. user, role, service account).
            action_or_role: Action, permission, or role definition name.
            original_scope: Over-privileged scope or resource pattern.
            remediated_scope: Narrowed target scope or resource pattern.
            risk_mitigated: Narrative description of privilege escalation risk cut.

        Returns:
            MultiCloudRemediationPatch containing validation status and unified diff.
        """
        is_valid = self.is_valid_transformation(provider, action_or_role, remediated_scope)
        if provider == CloudProvider.AZURE:
            diff = (
                "--- role_assignment_before.json\n"
                "+++ role_assignment_after.json\n"
                "@@ -1,4 +1,4 @@\n"
                " {\n"
                f'   "principalId": "{principal_id}",\n'
                f'   "roleDefinition": "{action_or_role}",\n'
                f'-  "scope": "{original_scope}"\n'
                f'+  "scope": "{remediated_scope}"\n'
                " }\n"
            )
        elif provider == CloudProvider.GCP:
            diff = (
                "--- iam_binding_before.json\n"
                "+++ iam_binding_after.json\n"
                "@@ -1,4 +1,4 @@\n"
                " {\n"
                f'   "role": "{action_or_role}",\n'
                f'-  "resource": "{original_scope}",\n'
                f'+  "resource": "{remediated_scope}",\n'
                f'   "members": ["{principal_id}"]\n'
                " }\n"
            )
        else:
            diff = (
                "--- aws_policy_before.json\n"
                "+++ aws_policy_after.json\n"
                "@@ -1,4 +1,4 @@\n"
                " {\n"
                f'   "Action": "{action_or_role}",\n'
                f'-  "Resource": "{original_scope}"\n'
                f'+  "Resource": "{remediated_scope}"\n'
                " }\n"
            )

        return MultiCloudRemediationPatch(
            provider=provider,
            principal_id=principal_id,
            target_action_or_role=action_or_role,
            original_scope=original_scope,
            remediated_scope=remediated_scope,
            is_valid=is_valid,
            risk_mitigated=risk_mitigated,
            policy_diff=diff,
        )


class MultiCloudRemediationPatch(BaseModel):
    """Specification of a synthesized least-privilege remediation patch across cloud providers."""

    model_config = ConfigDict(frozen=True)

    provider: CloudProvider
    principal_id: str
    target_action_or_role: str
    original_scope: str
    remediated_scope: str
    is_valid: bool
    risk_mitigated: str
    policy_diff: str


def load_default_multi_cloud_model() -> MultiCloudCapabilityModel:
    """Load default MultiCloudCapabilityModel from repository schema snapshot."""
    schema_path = (
        Path(__file__).resolve().parent.parent.parent.parent
        / "data"
        / "schemas"
        / "multi_cloud_capability.json"
    )
    if schema_path.is_file():
        return MultiCloudCapabilityModel.load_from_json(schema_path)
    return MultiCloudCapabilityModel()
