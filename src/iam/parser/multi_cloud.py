"""Multi-Cloud Action Capability Specification and Validation Module.

Extends the AWS Action Capability Model C(a, r, c) to Azure Role-Based Access Control (RBAC)
and Google Cloud IAM policy frameworks. Formalizes provider-specific scope hierarchies,
data vs. control action dichotomies, and conditional access semantics.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from iam.parser.capability import CapabilityModel, load_default_capability_model

if TYPE_CHECKING:
    from iam.generator.graph import GraphEdge, GraphNode, IAMGraph


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


class AzureRoleAssignment(BaseModel):
    """Specification of an Azure RBAC role assignment binding a principal to a scope."""

    model_config = ConfigDict(frozen=True)

    principal_id: str = Field(description="Entra ID / Azure AD object ID or user/sp identifier")
    role_definition_name: str = Field(
        description="Role definition name, e.g. 'Contributor', 'Owner'"
    )
    scope: str = Field(
        description="Target scope URI, e.g. '/subscriptions/sub-1/resourceGroups/rg-1'"
    )
    principal_type: str = Field(
        default="ServicePrincipal", description="Principal type (User, Group, ServicePrincipal)"
    )
    assignment_id: str | None = Field(
        default=None, description="Optional unique role assignment UUID"
    )
    condition: str | None = Field(
        default=None, description="Optional conditional access expression"
    )


class GCPIAMBinding(BaseModel):
    """Specification of a Google Cloud IAM policy binding on a resource."""

    model_config = ConfigDict(frozen=True)

    role: str = Field(description="GCP IAM role, e.g. 'roles/resourcemanager.organizationAdmin'")
    members: list[str] = Field(
        description="List of member identities (user:, serviceAccount:, group:)"
    )
    resource: str = Field(
        description="Resource path, e.g. 'organizations/123456' or 'projects/proj-1'"
    )
    condition: dict[str, Any] | None = Field(
        default=None, description="Optional CEL condition specification"
    )


class CrossCloudFederationTrust(BaseModel):
    """Specification of a cross-cloud identity federation trust relationship.

    Models OIDC/SAML federated trust across clouds, such as:
    - Azure Entra ID Service Principal -> AWS IAM Role (via AssumeRoleWithWebIdentity)
    - AWS IAM Role -> GCP Service Account (via GCP Workload Identity Federation)
    """

    model_config = ConfigDict(frozen=True)

    trust_id: str = Field(description="Unique identifier of this federation trust configuration")
    source_cloud: CloudProvider = Field(description="Originating identity cloud provider")
    source_identity: str = Field(
        description="Source principal identifier (e.g. Azure SP object ID or AWS Role ARN)"
    )
    target_cloud: CloudProvider = Field(
        description="Target cloud provider issuing federated credential"
    )
    target_identity: str = Field(
        description="Target identity assumed in destination cloud (e.g. AWS Role ARN or GCP SA)"
    )
    federation_type: str = Field(
        default="OIDC", description="Federation mechanism: OIDC, SAML2, or WorkloadIdentity"
    )
    trust_conditions: dict[str, Any] = Field(
        default_factory=dict, description="Trust boundary claims and constraints"
    )


def is_azure_scope_contained(target_scope: str, granting_scope: str) -> bool:
    """Verify whether target_scope is subsumed by granting_scope in Azure hierarchy.

    Hierarchy: Tenant (/) -> Management Group -> Subscription -> Resource Group -> Resource.
    """
    g = granting_scope.strip().lower()
    t = target_scope.strip().lower()

    if g in ("/", ""):
        return True
    if g == t:
        return True

    prefix = g.rstrip("/") + "/"
    return t.startswith(prefix)


def is_gcp_resource_contained(
    target_resource: str,
    granting_resource: str,
    hierarchy_map: dict[str, str] | None = None,
) -> bool:
    """Verify whether target_resource is subsumed by granting_resource in GCP hierarchy.

    Hierarchy: Organization -> Folder -> Project -> Resource.
    """
    g = granting_resource.strip().lower()
    t = target_resource.strip().lower()

    if g == t:
        return True

    prefix = g.rstrip("/") + "/"
    if t.startswith(prefix):
        return True

    if hierarchy_map is not None:
        curr = t
        while curr in hierarchy_map:
            parent = hierarchy_map[curr].strip().lower()
            if parent == g:
                return True
            curr = parent

    return False


class MultiCloudGraphAdapter:
    """Constructs unified multi-cloud authorization multigraphs (IAMGraph).

    Ingests Azure RBAC role assignments, GCP IAM bindings, and cross-cloud federation
    trusts (e.g. Entra ID -> AWS STS -> GCP Workload Identity) into an enterprise multigraph.
    """

    def __init__(self, capability_model: MultiCloudCapabilityModel | None = None) -> None:
        self.capability_model: MultiCloudCapabilityModel = (
            capability_model or load_default_multi_cloud_model()
        )

    def build_multicloud_graph(
        self,
        graph_id: str = "multicloud_topology",
        azure_assignments: list[AzureRoleAssignment] | None = None,
        gcp_bindings: list[GCPIAMBinding] | None = None,
        cross_cloud_trusts: list[CrossCloudFederationTrust] | None = None,
        aws_nodes: list[GraphNode] | None = None,
        aws_edges: list[GraphEdge] | None = None,
    ) -> IAMGraph:
        """Synthesize unified multi-cloud IAMGraph from heterogeneous cloud configurations."""
        from iam.generator.graph import EdgeRelation, GraphEdge, GraphNode, IAMGraph, NodeType

        graph = IAMGraph(
            graph_id=graph_id,
            metadata={
                "topology_type": "multi_cloud",
                "providers": [p.value for p in CloudProvider],
            },
        )

        # 1. Ingest base AWS nodes and edges
        if aws_nodes:
            graph.add_nodes(aws_nodes)
        if aws_edges:
            graph.add_edges(aws_edges)

        # 2. Ingest Azure RBAC Assignments
        if azure_assignments:
            for assignment in azure_assignments:
                # Principal Node
                principal_node_id = f"azure:{assignment.principal_id}"
                if graph.get_node(principal_node_id) is None:
                    p_type = assignment.principal_type.lower()
                    if p_type == "user":
                        node_type = NodeType.USER
                    elif p_type == "group":
                        node_type = NodeType.GROUP
                    else:
                        node_type = NodeType.ROLE

                    graph.add_node(
                        GraphNode(
                            id=principal_node_id,
                            node_type=node_type,
                            arn=f"azure://aad/principals/{assignment.principal_id}",
                            name=assignment.principal_id,
                            department="Azure-EntraID",
                            metadata={
                                "provider": CloudProvider.AZURE.value,
                                "principal_type": assignment.principal_type,
                            },
                        )
                    )

                # Scope / Resource Node
                scope_lvl = self.capability_model.parse_azure_scope_level(assignment.scope)
                scope_node_id = f"azure:scope:{assignment.scope}"
                if graph.get_node(scope_node_id) is None:
                    graph.add_node(
                        GraphNode(
                            id=scope_node_id,
                            node_type=NodeType.RESOURCE,
                            arn=f"azure://resource-manager{assignment.scope}",
                            name=assignment.scope,
                            department="Azure-Resource",
                            metadata={
                                "provider": CloudProvider.AZURE.value,
                                "scope_level": scope_lvl.value,
                                "scope": assignment.scope,
                            },
                        )
                    )

                # Role Definition Node
                role_node_id = f"azure:role:{assignment.role_definition_name}"
                if graph.get_node(role_node_id) is None:
                    graph.add_node(
                        GraphNode(
                            id=role_node_id,
                            node_type=NodeType.POLICY,
                            arn=f"azure://roles/{assignment.role_definition_name}",
                            name=assignment.role_definition_name,
                            metadata={
                                "provider": CloudProvider.AZURE.value,
                                "role_name": assignment.role_definition_name,
                            },
                        )
                    )

                # Edge: Principal -> Role (AttachedWith)
                if not graph.has_edge(principal_node_id, role_node_id, EdgeRelation.ATTACHED_WITH):
                    graph.add_edge(
                        GraphEdge(
                            source=principal_node_id,
                            target=role_node_id,
                            relation=EdgeRelation.ATTACHED_WITH,
                            actions=[assignment.role_definition_name],
                            metadata={"provider": CloudProvider.AZURE.value},
                        )
                    )

                # Edge: Role -> Scope (ActsOn)
                if not graph.has_edge(role_node_id, scope_node_id, EdgeRelation.ACTS_ON):
                    cond = (
                        {"scope": assignment.scope}
                        if assignment.condition is None
                        else {"scope": assignment.scope, "cond": assignment.condition}
                    )
                    graph.add_edge(
                        GraphEdge(
                            source=role_node_id,
                            target=scope_node_id,
                            relation=EdgeRelation.ACTS_ON,
                            actions=[assignment.role_definition_name],
                            condition=cond,
                            metadata={"provider": CloudProvider.AZURE.value},
                        )
                    )

        # 3. Ingest GCP IAM Bindings
        if gcp_bindings:
            for binding in gcp_bindings:
                res_lvl = self.capability_model.parse_gcp_level(binding.resource)
                res_node_id = f"gcp:resource:{binding.resource}"
                if graph.get_node(res_node_id) is None:
                    is_hvt = res_lvl == GCPAccessLevel.ORGANIZATION
                    graph.add_node(
                        GraphNode(
                            id=res_node_id,
                            node_type=NodeType.RESOURCE,
                            arn=f"gcp://{binding.resource}",
                            name=binding.resource,
                            department="GCP-ResourceManager",
                            is_high_value=is_hvt,
                            metadata={
                                "provider": CloudProvider.GCP.value,
                                "access_level": res_lvl.value,
                                "resource": binding.resource,
                            },
                        )
                    )

                role_node_id = f"gcp:role:{binding.role}"
                if graph.get_node(role_node_id) is None:
                    graph.add_node(
                        GraphNode(
                            id=role_node_id,
                            node_type=NodeType.POLICY,
                            arn=f"gcp://roles/{binding.role}",
                            name=binding.role,
                            metadata={
                                "provider": CloudProvider.GCP.value,
                                "role": binding.role,
                            },
                        )
                    )

                # Edge: Role -> Resource (ActsOn)
                if not graph.has_edge(role_node_id, res_node_id, EdgeRelation.ACTS_ON):
                    graph.add_edge(
                        GraphEdge(
                            source=role_node_id,
                            target=res_node_id,
                            relation=EdgeRelation.ACTS_ON,
                            actions=[binding.role],
                            condition=binding.condition,
                            metadata={"provider": CloudProvider.GCP.value},
                        )
                    )

                for member in binding.members:
                    member_node_id = f"gcp:{member}"
                    if graph.get_node(member_node_id) is None:
                        if member.startswith("user:"):
                            node_type = NodeType.USER
                        elif member.startswith("group:"):
                            node_type = NodeType.GROUP
                        else:
                            node_type = NodeType.ROLE

                        graph.add_node(
                            GraphNode(
                                id=member_node_id,
                                node_type=node_type,
                                arn=f"gcp://identities/{member}",
                                name=member,
                                department="GCP-IAM",
                                metadata={
                                    "provider": CloudProvider.GCP.value,
                                    "member": member,
                                },
                            )
                        )

                    # Edge: Member -> Role (AttachedWith)
                    if not graph.has_edge(member_node_id, role_node_id, EdgeRelation.ATTACHED_WITH):
                        graph.add_edge(
                            GraphEdge(
                                source=member_node_id,
                                target=role_node_id,
                                relation=EdgeRelation.ATTACHED_WITH,
                                actions=[binding.role],
                                metadata={"provider": CloudProvider.GCP.value},
                            )
                        )

        # 4. Ingest Cross-Cloud Federation Trusts
        if cross_cloud_trusts:
            for trust in cross_cloud_trusts:
                src_id = self._canonical_node_id(trust.source_cloud, trust.source_identity)
                tgt_id = self._canonical_node_id(trust.target_cloud, trust.target_identity)

                # Ensure source node exists
                if graph.get_node(src_id) is None:
                    src_arn = (
                        trust.source_identity
                        if trust.source_cloud == CloudProvider.AWS
                        else f"{trust.source_cloud.value}://identity/{trust.source_identity}"
                    )
                    graph.add_node(
                        GraphNode(
                            id=src_id,
                            node_type=NodeType.ROLE,
                            arn=src_arn,
                            name=trust.source_identity,
                            metadata={"provider": trust.source_cloud.value},
                        )
                    )

                # Ensure target node exists
                if graph.get_node(tgt_id) is None:
                    tgt_arn = (
                        trust.target_identity
                        if trust.target_cloud == CloudProvider.AWS
                        else f"{trust.target_cloud.value}://identity/{trust.target_identity}"
                    )
                    graph.add_node(
                        GraphNode(
                            id=tgt_id,
                            node_type=NodeType.ROLE,
                            arn=tgt_arn,
                            name=trust.target_identity,
                            metadata={"provider": trust.target_cloud.value},
                        )
                    )

                # Federation Bridge Edge
                action_name = (
                    "sts:AssumeRoleWithWebIdentity"
                    if trust.target_cloud == CloudProvider.AWS
                    else f"{trust.target_cloud.value}:workloadIdentityUser"
                )
                graph.add_edge(
                    GraphEdge(
                        source=src_id,
                        target=tgt_id,
                        relation=EdgeRelation.ASSUMES_ROLE,
                        is_bridge=True,
                        actions=[action_name],
                        condition=trust.trust_conditions if trust.trust_conditions else None,
                        metadata={
                            "cross_cloud": True,
                            "federation_type": trust.federation_type,
                            "source_cloud": trust.source_cloud.value,
                            "target_cloud": trust.target_cloud.value,
                            "trust_id": trust.trust_id,
                        },
                    )
                )

        return graph

    def _canonical_node_id(self, provider: CloudProvider, identity: str) -> str:
        """Resolve canonical graph node identifier based on provider syntax."""
        if provider == CloudProvider.AWS:
            return identity
        prefix = f"{provider.value}:"
        if identity.startswith(prefix):
            return identity
        return f"{prefix}{identity}"

    def find_cross_cloud_escalation_paths(
        self,
        graph: IAMGraph,
        source_id: str,
        target_id: str,
        cutoff: int = 10,
    ) -> list[list[str]]:
        """Compute lateral movement attack paths connecting source to target across cloud boundaries."""
        import networkx as nx

        if not graph.nx_graph.has_node(source_id) or not graph.nx_graph.has_node(target_id):
            return []
        try:
            paths = list(
                nx.all_simple_paths(
                    graph.nx_graph, source=source_id, target=target_id, cutoff=cutoff
                )
            )
            return paths
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []


def create_canonical_multi_cloud_topology() -> IAMGraph:
    """Construct canonical 3-cloud enterprise multigraph with an unobserved lateral privilege escalation path.

    Topology features:
    1. Azure Entra ID Service Principal ('sp-devops-ci') assigned 'Contributor' on Azure dev resource group.
    2. Cross-cloud OIDC federation trust: 'azure:sp-devops-ci' -> AWS IAM role 'arn:aws:iam::123456789012:role/CrossCloudDeploymentRole'.
    3. AWS AssumeRole pivot: 'CrossCloudDeploymentRole' -> 'arn:aws:iam::123456789012:role/GCPWorkloadIdentityFederator'.
    4. Cross-cloud Workload Identity federation trust: 'GCPWorkloadIdentityFederator' -> GCP SA 'serviceAccount:deployer@corp-enterprise.iam.gserviceaccount.com'.
    5. GCP IAM Binding: GCP SA has 'roles/resourcemanager.organizationAdmin' on 'organizations/org-corp-enterprise' (High Value Target!).

    This path demonstrates unobserved cross-cloud blast radius expansion:
    Azure SP -> AWS Deployment Role -> AWS Federator -> GCP SA -> GCP Org Admin!
    """
    from iam.generator.graph import EdgeRelation, GraphEdge, GraphNode, NodeType

    adapter = MultiCloudGraphAdapter()

    # Azure Assignments
    az_assignments = [
        AzureRoleAssignment(
            principal_id="sp-devops-ci",
            role_definition_name="Contributor",
            scope="/subscriptions/sub-dev-01/resourceGroups/rg-ci-cd",
            principal_type="ServicePrincipal",
        )
    ]

    # AWS Internal Nodes & Edges
    aws_deploy_role = GraphNode(
        id="arn:aws:iam::123456789012:role/CrossCloudDeploymentRole",
        node_type=NodeType.ROLE,
        arn="arn:aws:iam::123456789012:role/CrossCloudDeploymentRole",
        name="CrossCloudDeploymentRole",
        department="Engineering",
        metadata={"provider": CloudProvider.AWS.value},
    )
    aws_gcp_role = GraphNode(
        id="arn:aws:iam::123456789012:role/GCPWorkloadIdentityFederator",
        node_type=NodeType.ROLE,
        arn="arn:aws:iam::123456789012:role/GCPWorkloadIdentityFederator",
        name="GCPWorkloadIdentityFederator",
        department="Infrastructure",
        metadata={"provider": CloudProvider.AWS.value},
    )
    aws_pivot_edge = GraphEdge(
        source="arn:aws:iam::123456789012:role/CrossCloudDeploymentRole",
        target="arn:aws:iam::123456789012:role/GCPWorkloadIdentityFederator",
        relation=EdgeRelation.ASSUMES_ROLE,
        is_bridge=True,
        actions=["sts:AssumeRole"],
        metadata={"provider": CloudProvider.AWS.value, "pivot": "internal_aws"},
    )

    # GCP Bindings
    gcp_bindings = [
        GCPIAMBinding(
            role="roles/resourcemanager.organizationAdmin",
            members=["serviceAccount:deployer@corp-enterprise.iam.gserviceaccount.com"],
            resource="organizations/org-corp-enterprise",
        )
    ]

    # Cross-Cloud Federation Trusts
    cross_trusts = [
        CrossCloudFederationTrust(
            trust_id="trust-azure-to-aws",
            source_cloud=CloudProvider.AZURE,
            source_identity="sp-devops-ci",
            target_cloud=CloudProvider.AWS,
            target_identity="arn:aws:iam::123456789012:role/CrossCloudDeploymentRole",
            federation_type="OIDC",
            trust_conditions={"aud": "https://aws.amazon.com", "sub": "azure-sp-devops-ci"},
        ),
        CrossCloudFederationTrust(
            trust_id="trust-aws-to-gcp",
            source_cloud=CloudProvider.AWS,
            source_identity="arn:aws:iam::123456789012:role/GCPWorkloadIdentityFederator",
            target_cloud=CloudProvider.GCP,
            target_identity="serviceAccount:deployer@corp-enterprise.iam.gserviceaccount.com",
            federation_type="WorkloadIdentity",
            trust_conditions={"attribute.aws_role": "GCPWorkloadIdentityFederator"},
        ),
    ]

    graph = adapter.build_multicloud_graph(
        graph_id="canonical_multi_cloud_3cloud_topology",
        azure_assignments=az_assignments,
        gcp_bindings=gcp_bindings,
        cross_cloud_trusts=cross_trusts,
        aws_nodes=[aws_deploy_role, aws_gcp_role],
        aws_edges=[aws_pivot_edge],
    )

    # Flag the GCP org resource as high value target
    target_node = graph.get_node("gcp:resource:organizations/org-corp-enterprise")
    if target_node:
        target_node.is_high_value = True

    return graph
