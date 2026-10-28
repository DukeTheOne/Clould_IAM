"""Industrial AWS CloudTrail telemetry ingestion and canonical identity resolver.

Implements Phase 9 / Section 6.6 Level 3 Workload Pipeline:
- Ingests raw AWS CloudTrail JSON, JSON Lines (.jsonl), and gzip-compressed (.gz) logs.
- Resolves STS assumed-role sessions and federated identities to canonical IAM graph nodes.
- Normalizes CloudTrail eventSource and eventName into canonical AWS actions (C(a, r, c)).
- Extracts and reconstructs resource ARNs from resources[] lists and requestParameters.
- Filters unauthorized/denied events and chronologically orders activity traces.
- Partitions real telemetry into observation (T_1) and holdout (T_2) evaluation windows.
- Evaluates empirical log conformance against authorization multigraphs (G_o).
"""

from __future__ import annotations

import contextlib
import gzip
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from iam.parser.evaluator import EvalDecision
from iam.parser.wildcard import normalize_action_name
from iam.verifier.workload import DriftType, TemporalWorkloadSplit, WorkloadEvent

if TYPE_CHECKING:
    from iam.generator.graph import IAMGraph

logger = logging.getLogger(__name__)

# Pattern to extract account and role name from STS assumed-role ARN:
# arn:aws:sts::<account-id>:assumed-role/<role-name>/<session-name>
STS_ASSUMED_ROLE_PATTERN = re.compile(
    r"^arn:aws:sts::(?P<account>\d{12}):assumed-role/(?P<role>[^/]+)/(?P<session>.+)$"
)

# Pattern to extract account and federated user name:
# arn:aws:sts::<account-id>:federated-user/<user-name>
STS_FEDERATED_USER_PATTERN = re.compile(
    r"^arn:aws:sts::(?P<account>\d{12}):federated-user/(?P<user>.+)$"
)


class CloudTrailParserConfig(BaseModel):
    """Configuration governing CloudTrail log parsing, filtering, and normalization."""

    model_config = ConfigDict(frozen=True)

    only_successful: bool = Field(
        default=True,
        description="Filter out records with errorCode (e.g. AccessDenied) to preserve baseline conformance",
    )
    default_account_id: str = Field(
        default="123456789012",
        description="Fallback AWS account ID when absent from log record",
    )
    default_region: str = Field(
        default="us-east-1",
        description="Fallback AWS region when absent from log record",
    )
    resolve_assumed_roles: bool = Field(
        default=True,
        description="Map STS assumed-role ARNs to canonical IAM Role ARNs",
    )
    skip_event_names: list[str] = Field(
        default_factory=lambda: ["ConsoleLogin", "CreateLogStream", "PutLogEvents"],
        description="Low-signal administrative or logging events to ignore",
    )


class CloudTrailConformanceReport(BaseModel):
    """Detailed evaluation report assessing empirical CloudTrail log conformance on G_o."""

    model_config = ConfigDict(frozen=True)

    total_events: int = Field(description="Total events evaluated")
    conforming_events: int = Field(
        description="Count of events authorized (ALLOW) by graph policies"
    )
    non_conforming_events: int = Field(
        description="Count of events not authorized (DENY) by graph policies"
    )
    conformance_rate: float = Field(description="Proportion of conforming events (0.0 to 1.0)")
    unique_principals_evaluated: int = Field(description="Distinct principal ARNs tested")
    unique_resources_evaluated: int = Field(description="Distinct resource ARNs tested")
    unique_actions_evaluated: int = Field(description="Distinct actions tested")
    non_conforming_details: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Details of events that failed authorization evaluation on G_o",
    )


class CloudTrailParser:
    """Production-grade parser and canonical resolver for AWS CloudTrail log telemetry."""

    def __init__(self, config: CloudTrailParserConfig | None = None) -> None:
        """Initialize parser with operational configuration."""
        self.config = config if config is not None else CloudTrailParserConfig()

    def resolve_principal_arn(
        self, user_identity: dict[str, Any]
    ) -> tuple[str, str, dict[str, Any]]:
        """Resolve CloudTrail userIdentity block to canonical IAM principal ARN.

        Returns:
            Tuple of (canonical_principal_arn, department_hint, context_dict)
        """
        id_type = user_identity.get("type", "")
        raw_arn = user_identity.get("arn", "")
        account_id = user_identity.get("accountId") or self.config.default_account_id
        user_name = user_identity.get("userName", "")
        context: dict[str, Any] = {
            "identity_type": id_type,
            "raw_principal_arn": raw_arn,
        }

        # 1. AssumedRole Identity (STS assumed-role session)
        if id_type == "AssumedRole":
            session_ctx = user_identity.get("sessionContext") or {}
            session_issuer = session_ctx.get("sessionIssuer") or {}
            issuer_arn = session_issuer.get("arn", "")
            issuer_type = session_issuer.get("type", "")

            context["sts_session_arn"] = raw_arn
            context["session_issuer_type"] = issuer_type

            if self.config.resolve_assumed_roles:
                # Prefer explicit sessionIssuer ARN from CloudTrail sessionContext
                if issuer_arn and issuer_arn.startswith("arn:aws:iam::"):
                    role_name = session_issuer.get("userName") or issuer_arn.split("/")[-1]
                    dept = self._infer_department(role_name)
                    return issuer_arn, dept, context

                # Regex fallback on raw STS assumed-role ARN
                match = STS_ASSUMED_ROLE_PATTERN.match(raw_arn)
                if match:
                    acc = match.group("account")
                    role_name = match.group("role")
                    canonical_role = f"arn:aws:iam::{acc}:role/{role_name}"
                    dept = self._infer_department(role_name)
                    return canonical_role, dept, context

            return raw_arn, self._infer_department(raw_arn), context

        # 2. IAM User Identity
        if id_type == "IAMUser":
            if raw_arn and raw_arn.startswith("arn:aws:iam::"):
                return raw_arn, self._infer_department(user_name or raw_arn), context
            if user_name:
                arn = f"arn:aws:iam::{account_id}:user/{user_name}"
                return arn, self._infer_department(user_name), context

        # 3. Federated User Identity
        if id_type in ("FederatedUser", "SAMLEntity", "WebIdentityUser"):
            session_ctx = user_identity.get("sessionContext") or {}
            session_issuer = session_ctx.get("sessionIssuer") or {}
            issuer_arn = session_issuer.get("arn", "")
            if issuer_arn and self.config.resolve_assumed_roles:
                return issuer_arn, self._infer_department(issuer_arn), context
            match = STS_FEDERATED_USER_PATTERN.match(raw_arn)
            if match:
                acc = match.group("account")
                uname = match.group("user")
                return (
                    f"arn:aws:sts::{acc}:federated-user/{uname}",
                    self._infer_department(uname),
                    context,
                )
            if raw_arn:
                return raw_arn, self._infer_department(raw_arn), context

        # 4. Root Account
        if id_type == "Root":
            root_arn = f"arn:aws:iam::{account_id}:root"
            return root_arn, "Security", context

        # 5. AWS Service Principal (e.g. lambda.amazonaws.com)
        if id_type == "AWSService":
            invoked_by = (
                user_identity.get("invokedBy") or user_identity.get("principalId") or "aws-service"
            )
            return invoked_by, "Infrastructure", context

        # Fallback resolution
        if raw_arn:
            return raw_arn, self._infer_department(raw_arn), context
        principal_id = user_identity.get("principalId", "unknown")
        fallback_arn = f"arn:aws:iam::{account_id}:principal/{principal_id}"
        return fallback_arn, "Unknown", context

    def resolve_action(self, event_source: str, event_name: str) -> str:
        """Resolve CloudTrail eventSource and eventName into canonical AWS action name.

        Example:
            ('s3.amazonaws.com', 'GetObject') -> 's3:GetObject'
            ('kms.amazonaws.com', 'Decrypt') -> 'kms:Decrypt'
            ('dynamodb.us-east-1.amazonaws.com', 'Query') -> 'dynamodb:Query'
        """
        # Strip domain extensions and AWS region infixes
        source_prefix = event_source.lower()
        if source_prefix.endswith(".amazonaws.com"):
            source_prefix = source_prefix[:-14]
        # In case of regional endpoint like dynamodb.us-east-1
        if "." in source_prefix:
            source_prefix = source_prefix.split(".")[0]

        raw_action = f"{source_prefix}:{event_name}"
        return normalize_action_name(raw_action)

    def resolve_resource_arn(
        self,
        resources: list[dict[str, Any]] | None,
        request_params: dict[str, Any] | None,
        service: str,
        event_name: str,
        account_id: str,
        region: str,
    ) -> str:
        """Resolve targeted resource ARN from resources list or requestParameters.

        Handles S3 object/bucket scoping, KMS key resolution, IAM resource targeting,
        and STS role assumption targets.
        """
        _ = event_name
        # 1. Prefer resources list if present
        if resources:
            # For S3, prefer Object ARN over Bucket ARN if both present
            if service == "s3":
                for r in resources:
                    r_arn = r.get("ARN", "")
                    r_type = r.get("type", "")
                    if "Object" in r_type or (r_arn and "/" in r_arn.split(":::")[-1]):
                        return str(r_arn)
            # Return first non-empty ARN
            for r in resources:
                r_arn = r.get("ARN")
                if r_arn:
                    return str(r_arn)

        # 2. Extract and reconstruct from requestParameters
        params = request_params or {}

        if service == "s3":
            bucket = params.get("bucketName") or params.get("Bucket")
            key = params.get("key") or params.get("Key")
            if bucket and key:
                key_clean = str(key).lstrip("/")
                return f"arn:aws:s3:::{bucket}/{key_clean}"
            if bucket:
                return f"arn:aws:s3:::{bucket}"

        elif service == "kms":
            key_id = params.get("keyId") or params.get("KeyId")
            if key_id:
                key_str = str(key_id)
                if key_str.startswith("arn:aws:kms:"):
                    return key_str
                return f"arn:aws:kms:{region}:{account_id}:key/{key_str}"

        elif service == "iam":
            role_arn = params.get("roleArn") or params.get("RoleArn")
            if role_arn:
                return str(role_arn)
            role_name = params.get("roleName") or params.get("RoleName")
            if role_name:
                return f"arn:aws:iam::{account_id}:role/{role_name}"
            policy_arn = params.get("policyArn") or params.get("PolicyArn")
            if policy_arn:
                return str(policy_arn)
            user_name = params.get("userName") or params.get("UserName")
            if user_name:
                return f"arn:aws:iam::{account_id}:user/{user_name}"

        elif service == "sts":
            role_arn = params.get("roleArn") or params.get("RoleArn")
            if role_arn:
                return str(role_arn)

        elif service == "ec2":
            instances = params.get("instancesSet") or params.get("instanceId")
            if instances and isinstance(instances, str):
                return f"arn:aws:ec2:{region}:{account_id}:instance/{instances}"

        # 3. Fallback to wildcard ARN
        return "*"

    def parse_record(
        self,
        record: dict[str, Any],
        base_epoch: datetime | None = None,
    ) -> WorkloadEvent | None:
        """Parse a single raw CloudTrail JSON record into a normalized WorkloadEvent.

        Returns None if record is filtered (denied, skipped event name, etc.).
        """
        # Skip low-signal event names
        event_name = record.get("eventName", "")
        if event_name in self.config.skip_event_names:
            return None

        # Filter unauthorized/denied events if configured
        error_code = record.get("errorCode")
        if self.config.only_successful and error_code:
            logger.debug(
                "Skipping CloudTrail record with errorCode=%s (eventName=%s)",
                error_code,
                event_name,
            )
            return None

        # Parse user identity
        user_identity = record.get("userIdentity") or {}
        principal_arn, dept, context = self.resolve_principal_arn(user_identity)

        # Parse action
        event_source = record.get("eventSource", "")
        action = self.resolve_action(event_source, event_name)
        service = action.split(":")[0] if ":" in action else event_source

        # Parse account and region
        account_id = (
            record.get("recipientAccountId")
            or user_identity.get("accountId")
            or self.config.default_account_id
        )
        region = record.get("awsRegion") or self.config.default_region

        # Parse resource ARN
        resources = record.get("resources")
        request_params = record.get("requestParameters")
        resource_arn = self.resolve_resource_arn(
            resources=resources,
            request_params=request_params,
            service=service,
            event_name=event_name,
            account_id=account_id,
            region=region,
        )

        # Parse event timestamp
        event_time_raw = record.get("eventTime")
        event_dt = self._parse_iso_datetime(event_time_raw)
        if base_epoch is not None:
            day_offset = max(0.0, (event_dt - base_epoch).total_seconds() / 86400.0)
        else:
            day_offset = 0.0

        # Record context metadata
        context["event_time"] = event_dt.isoformat()
        context["aws_region"] = region
        context["source_ip"] = record.get("sourceIPAddress", "")
        if error_code:
            context["error_code"] = error_code
            context["error_message"] = record.get("errorMessage", "")

        event_id = record.get("eventID") or str(uuid.uuid4())

        return WorkloadEvent(
            event_id=event_id,
            principal_arn=principal_arn,
            action=action,
            resource_arn=resource_arn,
            day_offset=day_offset,
            department=dept,
            service=service,
            is_drift=False,
            context=context,
        )

    def parse_json_string(self, content: str) -> list[WorkloadEvent]:
        """Parse raw CloudTrail JSON content (Records wrapper or array of records)."""
        data = json.loads(content)
        records: list[dict[str, Any]]
        if isinstance(data, dict):
            records = data.get("Records", [])
        elif isinstance(data, list):
            records = data
        else:
            raise ValueError(f"Unexpected CloudTrail root JSON type: {type(data)}")

        return self._process_raw_records(records)

    def parse_file(self, file_path: str | Path) -> list[WorkloadEvent]:
        """Parse CloudTrail file (.json, .jsonl, .json.gz, .jsonl.gz)."""
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(f"CloudTrail log file not found: {p}")

        raw_records: list[dict[str, Any]] = []

        if p.name.endswith(".gz"):
            with gzip.open(p, "rt", encoding="utf-8") as f:
                raw_records = self._read_records_from_stream(f, p.name)
        else:
            with open(p, encoding="utf-8") as f:
                raw_records = self._read_records_from_stream(f, p.name)

        return self._process_raw_records(raw_records)

    def parse_directory(self, dir_path: str | Path, recursive: bool = True) -> list[WorkloadEvent]:
        """Scan directory and parse all CloudTrail JSON/JSONL/GZ files in chronological order."""
        root = Path(dir_path)
        if not root.is_dir():
            raise NotADirectoryError(f"Directory not found: {root}")

        glob_pattern = "**/*" if recursive else "*"
        all_raw_records: list[dict[str, Any]] = []

        for fpath in sorted(root.glob(glob_pattern)):
            if not fpath.is_file():
                continue
            fname = fpath.name.lower()
            if fname.endswith((".json", ".jsonl", ".json.gz", ".jsonl.gz")):
                try:
                    if fname.endswith(".gz"):
                        with gzip.open(fpath, "rt", encoding="utf-8") as f:
                            records = self._read_records_from_stream(f, fname)
                    else:
                        with open(fpath, encoding="utf-8") as f:
                            records = self._read_records_from_stream(f, fname)
                    all_raw_records.extend(records)
                except Exception as e:
                    logger.warning("Error reading CloudTrail file %s: %s", fpath, e)

        return self._process_raw_records(all_raw_records)

    def create_temporal_split(
        self,
        events: list[WorkloadEvent],
        t1_ratio: float = 0.75,
        t1_days: float | None = None,
    ) -> TemporalWorkloadSplit:
        """Partition chronologically ordered events into T_1 (synthesis) and T_2 (holdout).

        Automatically detects and tags operational drift in T_2:
        - Resource drift: target resource ARN unseen in T_1
        - Action drift: action unseen in T_1
        - Federated pivot: principal identity is federated/STS assumed-role unseen in T_1
        """
        if not events:
            return TemporalWorkloadSplit()

        # Ensure events are ordered by day_offset
        sorted_events = sorted(events, key=lambda e: e.day_offset)

        # Determine cutoff boundary
        if t1_days is not None:
            t1_events = [e for e in sorted_events if e.day_offset < t1_days]
            t2_raw = [e for e in sorted_events if e.day_offset >= t1_days]
        else:
            split_idx = int(len(sorted_events) * max(0.1, min(0.95, t1_ratio)))
            t1_events = sorted_events[:split_idx]
            t2_raw = sorted_events[split_idx:]

        # Collect T_1 observation vocabulary
        seen_resources: set[str] = {e.resource_arn for e in t1_events}
        seen_actions: set[str] = {e.action for e in t1_events}
        seen_principals: set[str] = {e.principal_arn for e in t1_events}

        # Tag operational drift in T_2
        t2_events: list[WorkloadEvent] = []
        for e in t2_raw:
            is_drift = False
            drift_type: DriftType | None = None

            if e.resource_arn not in seen_resources:
                is_drift = True
                drift_type = DriftType.RESOURCE_DRIFT
            elif e.action not in seen_actions:
                is_drift = True
                drift_type = DriftType.ACTION_DRIFT
            elif (
                e.principal_arn not in seen_principals
                and "sts" in e.context.get("identity_type", "").lower()
            ):
                is_drift = True
                drift_type = DriftType.FEDERATED_PIVOT

            t2_events.append(
                WorkloadEvent(
                    event_id=e.event_id,
                    principal_arn=e.principal_arn,
                    action=e.action,
                    resource_arn=e.resource_arn,
                    day_offset=e.day_offset,
                    department=e.department,
                    service=e.service,
                    is_drift=is_drift,
                    drift_type=drift_type,
                    context=e.context,
                )
            )

        metadata = {
            "source": "AWS CloudTrail Telemetry Pipeline",
            "t1_ratio": t1_ratio,
            "t1_days_cutoff": t1_days,
            "t1_count": len(t1_events),
            "t2_count": len(t2_events),
            "drift_count": sum(1 for e in t2_events if e.is_drift),
        }

        return TemporalWorkloadSplit(
            t1_events=t1_events,
            t2_events=t2_events,
            metadata=metadata,
        )

    def evaluate_conformance(
        self,
        graph: IAMGraph,
        events: list[WorkloadEvent],
    ) -> CloudTrailConformanceReport:
        """Evaluate empirical authorization conformance of real CloudTrail events on G_o.

        Quantifies how accurately graph policies explain observed historical telemetry.
        """
        if not events:
            return CloudTrailConformanceReport(
                total_events=0,
                conforming_events=0,
                non_conforming_events=0,
                conformance_rate=1.0,
                unique_principals_evaluated=0,
                unique_resources_evaluated=0,
                unique_actions_evaluated=0,
            )

        from iam.optimizer.repair import WorkloadConformanceChecker

        checker = WorkloadConformanceChecker()
        conforming_count = 0
        non_conforming_details: list[dict[str, Any]] = []

        principals: set[str] = set()
        resources: set[str] = set()
        actions: set[str] = set()

        for event in events:
            principals.add(event.principal_arn)
            resources.add(event.resource_arn)
            actions.add(event.action)

            auth_req = event.to_auth_request()
            eval_res = checker.evaluate_request(graph, auth_req)

            if eval_res.decision == EvalDecision.ALLOW:
                conforming_count += 1
            else:
                non_conforming_details.append(
                    {
                        "event_id": event.event_id,
                        "principal_arn": event.principal_arn,
                        "action": event.action,
                        "resource_arn": event.resource_arn,
                        "decision": eval_res.decision.value,
                        "num_matched_allow": len(eval_res.matched_allow_statements),
                        "num_matched_deny": len(eval_res.matched_deny_statements),
                    }
                )

        total = len(events)
        rate = conforming_count / float(total) if total > 0 else 1.0

        return CloudTrailConformanceReport(
            total_events=total,
            conforming_events=conforming_count,
            non_conforming_events=len(non_conforming_details),
            conformance_rate=round(rate, 4),
            unique_principals_evaluated=len(principals),
            unique_resources_evaluated=len(resources),
            unique_actions_evaluated=len(actions),
            non_conforming_details=non_conforming_details,
        )

    # --------------------------------------------------------------------------
    # Private Helper Methods
    # --------------------------------------------------------------------------

    def _read_records_from_stream(self, stream: Any, filename: str) -> list[dict[str, Any]]:
        """Read records from open text stream (JSON or JSON Lines)."""
        if filename.endswith((".jsonl", ".jsonl.gz")):
            records: list[dict[str, Any]] = []
            for line in stream:
                line_str = line.strip()
                if line_str:
                    records.append(json.loads(line_str))
            return records
        else:
            content = stream.read()
            if not content.strip():
                return []
            data = json.loads(content)
            if isinstance(data, dict):
                records_list = data.get("Records", [])
                if isinstance(records_list, list):
                    return records_list
                return []
            elif isinstance(data, list):
                return data
            return []

    def _process_raw_records(self, raw_records: list[dict[str, Any]]) -> list[WorkloadEvent]:
        """Process and sort raw records chronologically into WorkloadEvents."""
        if not raw_records:
            return []

        # Find minimum timestamp to anchor epoch
        timestamps: list[datetime] = []
        for r in raw_records:
            t_raw = r.get("eventTime")
            if t_raw:
                with contextlib.suppress(Exception):
                    timestamps.append(self._parse_iso_datetime(t_raw))

        base_epoch = min(timestamps) if timestamps else datetime.now(timezone.utc)

        events: list[WorkloadEvent] = []
        for r in raw_records:
            ev = self.parse_record(r, base_epoch=base_epoch)
            if ev is not None:
                events.append(ev)

        # Sort chronologically by day offset
        events.sort(key=lambda e: e.day_offset)
        return events

    def _parse_iso_datetime(self, time_raw: Any) -> datetime:
        """Parse ISO-8601 CloudTrail timestamp string into timezone-aware datetime."""
        if not time_raw or not isinstance(time_raw, str):
            return datetime.now(timezone.utc)
        # Handle 'Z' suffix
        normalized = time_raw.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(normalized)
        except Exception:
            return datetime.now(timezone.utc)

    def _infer_department(self, name: str) -> str:
        """Infer enterprise department hint from principal name or ARN."""
        low = name.lower()
        if any(k in low for k in ("data", "bi", "lake", "analyst", "pipeline", "etl")):
            return "DataBI"
        if any(k in low for k in ("dev", "ops", "ci", "worker", "builder", "deploy")):
            return "DevOps"
        if any(k in low for k in ("sec", "audit", "compliance", "guard")):
            return "Security"
        if any(k in low for k in ("app", "backend", "frontend", "service")):
            return "Engineering"
        return "Core"
