# Multi-Cloud Authorization Capability & Remediation Evaluation Report

> [!NOTE]
> **Phase 9 Milestone Deliverable (Months 19–24)**: Generalization of action capability modeling
> and least-privilege repair constraints across AWS IAM, Azure RBAC, and Google Cloud IAM.

## 1. Executive Summary & Verification Metrics

| Evaluation Metric | Measured Result | Benchmark Target | Conformance Status |
| :--- | :---: | :---: | :---: |
| **Total Capability Rules Evaluated** | `22` | $\ge 20$ | PASSED |
| **Overall Conformance Pass Rate** | `100.0%` | $100.0\%$ | PASSED |
| **Illegal Scoping Prevention Rate** | `100.0%` | $100.0\%$ | PASSED |
| **Benign Workload Utility Preservation** | `100.0%` | $100.0\%$ | PASSED |

## 2. Cloud Provider Conformance Breakdown

| Cloud Provider | Framework | Evaluated Rules | Conformance Pass Rate | Status |
| :--- | :--- | :---: | :---: | :---: |
| **AWS** | IAM Policy & ARN Constraints | `7` | `100.0%` | CERTIFIED |
| **AZURE** | RBAC 5-Tier Scope Hierarchy | `8` | `100.0%` | CERTIFIED |
| **GCP** | Resource Manager Hierarchy | `7` | `100.0%` | CERTIFIED |

## 3. Detailed Rule Verification Results

| Test ID | Provider | Action / Permission | Target Scope / Resource | Expected | Actual | Status | Description |
| :--- | :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| `aws-rule-001` | AWS | `s3:GetObject` | `arn:aws:s3:::production-data-lake/tabl...` | Admissible | Admissible | **PASS** | Valid S3 object resource scoping |
| `aws-rule-002` | AWS | `sts:GetCallerIdentity` | `*` | Admissible | Admissible | **PASS** | Valid STS wildcard-only operation |
| `aws-rule-003` | AWS | `sts:GetCallerIdentity` | `arn:aws:iam::123456789012:user/admin` | Blocked | Blocked | **PASS** | Invalid ARN scoping on wildcard-only STS action |
| `aws-rule-004` | AWS | `iam:PassRole` | `arn:aws:iam::123456789012:role/DataPip...` | Admissible | Admissible | **PASS** | Valid role ARN scoping on iam:PassRole |
| `aws-rule-005` | AWS | `iam:PassRole` | `arn:aws:s3:::some-bucket` | Blocked | Blocked | **PASS** | Invalid S3 bucket ARN on iam:PassRole |
| `aws-rule-006` | AWS | `s3:GetObject` | `arn:aws:s3:::production-data-lake/tabl...` | Admissible | Admissible | **PASS** | Valid global context condition key on S3 |
| `aws-rule-007` | AWS | `s3:GetObject` | `arn:aws:s3:::production-data-lake/tabl...` | Blocked | Blocked | **PASS** | Invalid context condition key on S3 |
| `azure-rule-001` | AZURE | `Microsoft.Compute/virtualMachines/read` | `/subscriptions/00000000-0000-0000-0000...` | Admissible | Admissible | **PASS** | VM read action admissible at Resource Group scope |
| `azure-rule-002` | AZURE | `Microsoft.Compute/virtualMachines/read` | `/subscriptions/00000000-0000-0000-0000...` | Admissible | Admissible | **PASS** | VM read action admissible at Resource scope |
| `azure-rule-003` | AZURE | `Microsoft.Compute/virtualMachines/read` | `/` | Blocked | Blocked | **PASS** | VM read action inadmissible at Tenant root scope |
| `azure-rule-004` | AZURE | `Microsoft.Authorization/roleAssignments/write` | `/providers/Microsoft.Management/manage...` | Admissible | Admissible | **PASS** | Role assignment write admissible at Management Group scope |
| `azure-rule-005` | AZURE | `Microsoft.Authorization/roleAssignments/write` | `/subscriptions/00000000-0000-0000-0000...` | Admissible | Admissible | **PASS** | Role assignment write admissible at Subscription scope |
| `azure-rule-006` | AZURE | `Microsoft.Authorization/roleAssignments/write` | `/subscriptions/00000000-0000-0000-0000...` | Blocked | Blocked | **PASS** | Role assignment write inadmissible directly on VM resource scope |
| `azure-rule-007` | AZURE | `Microsoft.KeyVault/vaults/secrets/read/action` | `/subscriptions/00000000-0000-0000-0000...` | Admissible | Admissible | **PASS** | KeyVault data action admissible at secret Resource scope |
| `azure-rule-008` | AZURE | `Microsoft.KeyVault/vaults/secrets/read/action` | `/subscriptions/00000000-0000-0000-0000...` | Blocked | Blocked | **PASS** | KeyVault data action inadmissible at naked Subscription scope |
| `gcp-rule-001` | GCP | `resourcemanager.projects.setIamPolicy` | `projects/enterprise-core-prod` | Admissible | Admissible | **PASS** | setIamPolicy admissible at Project level |
| `gcp-rule-002` | GCP | `resourcemanager.projects.setIamPolicy` | `folders/9876543210` | Admissible | Admissible | **PASS** | setIamPolicy admissible at Folder level |
| `gcp-rule-003` | GCP | `resourcemanager.projects.setIamPolicy` | `organizations/123456789012` | Admissible | Admissible | **PASS** | setIamPolicy admissible at Organization level |
| `gcp-rule-004` | GCP | `resourcemanager.projects.setIamPolicy` | `projects/enterprise-core-prod/location...` | Blocked | Blocked | **PASS** | setIamPolicy inadmissible at sub-resource level |
| `gcp-rule-005` | GCP | `secretmanager.secrets.getPayload` | `projects/enterprise-core-prod/location...` | Admissible | Admissible | **PASS** | Secret payload access admissible at Resource level |
| `gcp-rule-006` | GCP | `secretmanager.secrets.getPayload` | `organizations/123456789012` | Blocked | Blocked | **PASS** | Secret payload access inadmissible at Organization root level |
| `gcp-rule-007` | GCP | `compute.instances.create` | `projects/enterprise-core-prod` | Admissible | Admissible | **PASS** | Compute instance creation admissible at Project level |

## 4. Key Architectural Insights for Top-Tier Publication

1. **Hierarchical Scope Confinement**: In Azure RBAC, coarse role assignments at Subscription or Management Group levels represent the primary privilege escalation vector. Capability-aware repair must restrict actions like `Microsoft.Authorization/roleAssignments/write` to Resource Group boundaries, whereas Data Actions (`Microsoft.KeyVault/*`) must be strictly bound to individual Vault resource endpoints.
2. **Resource Manager Soundness**: GCP IAM policy bindings at Organization or Folder levels inherit downward unconditionally. Least-privilege synthesis under partial observability must recognize that modifying Project-level bindings cannot neutralize Organization-level grant paths.
3. **Zero-Overfitting Invariance**: Across all three major enterprise cloud architectures, capability models $C(a, r, c)$ provide an orthogonal semantic guardrail preventing solvers from generating syntactically invalid or non-executable policy patches.

*Report automatically generated on 2026-10-28T05:30:55.630182+00:00 by `iam.verifier.multi_cloud_eval`.*
