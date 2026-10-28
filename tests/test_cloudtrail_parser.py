"""Unit and integration test suite for AWS CloudTrail telemetry ingestion and canonical resolution.

Tests Phase 9 / Section 6.6 Level 3 Workload Pipeline:
- Canonical identity resolution across IAMUser, AssumedRole (STS session), FederatedUser, Root, and AWSService.
- Action normalization and resource ARN resolution from resources[] and requestParameters.
- File format support: standard JSON, JSON Lines (.jsonl), and gzip-compressed (.json.gz, .jsonl.gz).
- Chronological ordering, timestamp normalization, and day_offset computation.
- Unauthorized event filtering (errorCode) and low-signal event skipping.
- Temporal workload partitioning (T_1/T_2) with operational drift tagging.
- Empirical graph authorization conformance evaluation against IAMGraph.
- CLI command invocation and output file serialization.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from iam.generator.graph import (
    EdgeRelation,
    GraphEdge,
    GraphNode,
    IAMGraph,
    NodeType,
)
from iam.parser.schema import Effect, PolicyDocument, Statement
from iam.verifier.cloudtrail_parser import (
    CloudTrailConformanceReport,
    CloudTrailParser,
    CloudTrailParserConfig,
)


@pytest.fixture
def parser() -> CloudTrailParser:
    """Fixture providing default CloudTrailParser instance."""
    return CloudTrailParser()


@pytest.fixture
def sample_graph() -> IAMGraph:
    """Fixture providing an authorization graph matching sample telemetry."""
    graph = IAMGraph("cloudtrail_test_graph")

    # Principals
    analyst = GraphNode(
        id="user:analyst-1",
        node_type=NodeType.USER,
        arn="arn:aws:iam::123456789012:user/analyst-1",
        name="analyst-1",
        department="DataBI",
    )
    worker = GraphNode(
        id="role:legit-worker",
        node_type=NodeType.ROLE,
        arn="arn:aws:iam::123456789012:role/legit-worker",
        name="legit-worker",
        department="DevOps",
    )
    dev = GraphNode(
        id="user:dev-1",
        node_type=NodeType.USER,
        arn="arn:aws:iam::123456789012:user/dev-1",
        name="dev-1",
        department="DevOps",
    )

    # Resources
    s3_res = GraphNode(
        id="res:s3",
        node_type=NodeType.RESOURCE,
        arn="arn:aws:s3:::databi-lake-bucket/raw/data.csv",
        name="s3-data",
    )
    kms_res = GraphNode(
        id="res:kms",
        node_type=NodeType.RESOURCE,
        arn="arn:aws:kms:us-east-1:123456789012:key/databi-kms-key-0",
        name="kms-key",
    )

    # Policies
    analyst_policy = GraphNode(
        id="pol:analyst",
        node_type=NodeType.POLICY,
        arn="arn:aws:iam::123456789012:policy/analyst-policy",
        name="analyst-policy",
        policy_document=PolicyDocument(
            Statement=[
                Statement(
                    Effect=Effect.ALLOW,
                    Action=["s3:GetObject"],
                    Resource=["arn:aws:s3:::databi-lake-bucket/*"],
                ),
                Statement(
                    Effect=Effect.ALLOW,
                    Action=["kms:Decrypt"],
                    Resource=["arn:aws:kms:us-east-1:123456789012:key/databi-kms-key-0"],
                ),
            ]
        ),
    )

    dev_policy = GraphNode(
        id="pol:dev",
        node_type=NodeType.POLICY,
        arn="arn:aws:iam::123456789012:policy/dev-policy",
        name="dev-policy",
        policy_document=PolicyDocument(
            Statement=[
                Statement(
                    Effect=Effect.ALLOW,
                    Action=["ec2:DescribeInstances"],
                    Resource=["*"],
                )
            ]
        ),
    )

    worker_policy = GraphNode(
        id="pol:worker",
        node_type=NodeType.POLICY,
        arn="arn:aws:iam::123456789012:policy/worker-policy",
        name="worker-policy",
        policy_document=PolicyDocument(
            Statement=[
                Statement(
                    Effect=Effect.ALLOW,
                    Action=["s3:GetObject"],
                    Resource=["arn:aws:s3:::databi-lake-bucket/*"],
                )
            ]
        ),
    )

    graph.add_nodes(
        [analyst, worker, dev, s3_res, kms_res, analyst_policy, dev_policy, worker_policy]
    )
    graph.add_edge(
        GraphEdge(source=analyst.id, target=analyst_policy.id, relation=EdgeRelation.ATTACHED_WITH)
    )
    graph.add_edge(
        GraphEdge(source=dev.id, target=dev_policy.id, relation=EdgeRelation.ATTACHED_WITH)
    )
    graph.add_edge(
        GraphEdge(source=worker.id, target=worker_policy.id, relation=EdgeRelation.ATTACHED_WITH)
    )

    return graph


# ==============================================================================
# 1. Identity Resolution Tests
# ==============================================================================


class TestCloudTrailIdentityResolution:
    """Test canonical principal resolution across all AWS identity mechanisms."""

    def test_resolve_iam_user(self, parser: CloudTrailParser) -> None:
        """Resolve standard IAMUser identity block."""
        identity = {
            "type": "IAMUser",
            "principalId": "AIDA1234567890EXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/Alice",
            "accountId": "123456789012",
            "userName": "Alice",
        }
        arn, dept, ctx = parser.resolve_principal_arn(identity)
        assert arn == "arn:aws:iam::123456789012:user/Alice"
        assert dept == "Core"
        assert ctx["identity_type"] == "IAMUser"

    def test_resolve_assumed_role_via_session_issuer(self, parser: CloudTrailParser) -> None:
        """Resolve STS assumed role session to canonical IAM Role ARN via sessionIssuer."""
        identity = {
            "type": "AssumedRole",
            "principalId": "AROA1234567890EXAMPLE:session-ci",
            "arn": "arn:aws:sts::123456789012:assumed-role/DataWorkerRole/session-ci",
            "accountId": "123456789012",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROA1234567890EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:role/DataWorkerRole",
                    "accountId": "123456789012",
                    "userName": "DataWorkerRole",
                }
            },
        }
        arn, dept, ctx = parser.resolve_principal_arn(identity)
        assert arn == "arn:aws:iam::123456789012:role/DataWorkerRole"
        assert dept == "DataBI"
        assert (
            ctx["sts_session_arn"]
            == "arn:aws:sts::123456789012:assumed-role/DataWorkerRole/session-ci"
        )

    def test_resolve_assumed_role_regex_fallback(self, parser: CloudTrailParser) -> None:
        """Resolve STS assumed role when sessionContext is absent using regex parsing."""
        identity = {
            "type": "AssumedRole",
            "principalId": "AROA9999999999EXAMPLE:build-42",
            "arn": "arn:aws:sts::987654321098:assumed-role/DevOpsBuildRole/build-42",
        }
        arn, dept, ctx = parser.resolve_principal_arn(identity)
        assert arn == "arn:aws:iam::987654321098:role/DevOpsBuildRole"
        assert dept == "DevOps"

    def test_resolve_federated_user(self, parser: CloudTrailParser) -> None:
        """Resolve federated identity and SAML sessions."""
        identity = {
            "type": "FederatedUser",
            "principalId": "123456789012:okta-analyst",
            "arn": "arn:aws:sts::123456789012:federated-user/okta-analyst",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "arn": "arn:aws:iam::123456789012:role/OktaDataAnalystRole",
                }
            },
        }
        arn, dept, ctx = parser.resolve_principal_arn(identity)
        assert arn == "arn:aws:iam::123456789012:role/OktaDataAnalystRole"
        assert dept == "DataBI"

    def test_resolve_root_and_service(self, parser: CloudTrailParser) -> None:
        """Resolve root identity and AWS service principals."""
        root_identity = {"type": "Root", "accountId": "123456789012"}
        arn_root, dept_root, _ = parser.resolve_principal_arn(root_identity)
        assert arn_root == "arn:aws:iam::123456789012:root"
        assert dept_root == "Security"

        svc_identity = {"type": "AWSService", "invokedBy": "lambda.amazonaws.com"}
        arn_svc, dept_svc, _ = parser.resolve_principal_arn(svc_identity)
        assert arn_svc == "lambda.amazonaws.com"
        assert dept_svc == "Infrastructure"


# ==============================================================================
# 2. Action & Resource Resolution Tests
# ==============================================================================


class TestActionAndResourceResolution:
    """Test normalization of CloudTrail eventSource and targeted resource ARNs."""

    def test_resolve_action_normalization(self, parser: CloudTrailParser) -> None:
        """Normalize eventSource prefixes and action names."""
        assert parser.resolve_action("s3.amazonaws.com", "GetObject") == "s3:getobject"
        assert parser.resolve_action("kms.amazonaws.com", "Decrypt") == "kms:decrypt"
        assert parser.resolve_action("sts.amazonaws.com", "AssumeRole") == "sts:assumerole"
        assert (
            parser.resolve_action("dynamodb.us-west-2.amazonaws.com", "Query") == "dynamodb:query"
        )

    def test_resolve_s3_resources(self, parser: CloudTrailParser) -> None:
        """Resolve S3 Object ARN over Bucket ARN from resources array."""
        resources = [
            {"type": "AWS::S3::Bucket", "ARN": "arn:aws:s3:::my-bucket"},
            {"type": "AWS::S3::Object", "ARN": "arn:aws:s3:::my-bucket/logs/app.log"},
        ]
        res_arn = parser.resolve_resource_arn(
            resources=resources,
            request_params=None,
            service="s3",
            event_name="GetObject",
            account_id="123456789012",
            region="us-east-1",
        )
        assert res_arn == "arn:aws:s3:::my-bucket/logs/app.log"

    def test_reconstruct_s3_from_request_parameters(self, parser: CloudTrailParser) -> None:
        """Reconstruct S3 object ARN when resources list is absent."""
        params = {"bucketName": "analytics-store", "key": "2026/01/report.parquet"}
        res_arn = parser.resolve_resource_arn(
            resources=[],
            request_params=params,
            service="s3",
            event_name="PutObject",
            account_id="123456789012",
            region="us-east-1",
        )
        assert res_arn == "arn:aws:s3:::analytics-store/2026/01/report.parquet"

    def test_reconstruct_kms_key_arn(self, parser: CloudTrailParser) -> None:
        """Reconstruct KMS key ARN from keyId string."""
        params = {"keyId": "12345678-1234-1234-1234-123456789012"}
        res_arn = parser.resolve_resource_arn(
            resources=[],
            request_params=params,
            service="kms",
            event_name="Decrypt",
            account_id="123456789012",
            region="us-east-1",
        )
        assert (
            res_arn == "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        )


# ==============================================================================
# 3. File Formats & Ingestion Pipeline Tests
# ==============================================================================


class TestCloudTrailFileFormats:
    """Test multi-format ingestion: JSON, JSON Lines, and gzip archives."""

    def test_parse_sample_cloudtrail_json(self, parser: CloudTrailParser) -> None:
        """Parse official sample_cloudtrail.json fixture."""
        sample_path = Path("data/sample_cloudtrail.json")
        assert sample_path.is_file(), "data/sample_cloudtrail.json must exist"

        events = parser.parse_file(sample_path)
        # Default config excludes AccessDenied and ConsoleLogin
        assert len(events) == 4
        # Verify event order by day offset
        for i in range(len(events) - 1):
            assert events[i].day_offset <= events[i + 1].day_offset

    def test_parse_jsonl_file(self, parser: CloudTrailParser, tmp_path: Path) -> None:
        """Parse newline-delimited JSON Lines (.jsonl) file."""
        jsonl_path = tmp_path / "telemetry.jsonl"
        records = [
            {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "dev-1",
                    "accountId": "123456789012",
                },
                "eventTime": "2026-02-01T10:00:00Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "DescribeInstances",
            },
            {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "dev-1",
                    "accountId": "123456789012",
                },
                "eventTime": "2026-02-02T12:00:00Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "DescribeInstances",
            },
        ]
        with open(jsonl_path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

        events = parser.parse_file(jsonl_path)
        assert len(events) == 2
        assert events[0].day_offset == 0.0
        assert events[1].day_offset > 0.9

    def test_parse_gzip_compressed_file(self, parser: CloudTrailParser, tmp_path: Path) -> None:
        """Parse gzip compressed CloudTrail file (.json.gz)."""
        gz_path = tmp_path / "cloudtrail_log.json.gz"
        payload = {
            "Records": [
                {
                    "eventVersion": "1.08",
                    "userIdentity": {
                        "type": "IAMUser",
                        "userName": "analyst-1",
                        "accountId": "123456789012",
                    },
                    "eventTime": "2026-03-01T00:00:00Z",
                    "eventSource": "s3.amazonaws.com",
                    "eventName": "GetObject",
                    "requestParameters": {"bucketName": "data-lake", "key": "daily.csv"},
                }
            ]
        }
        with gzip.open(gz_path, "wt", encoding="utf-8") as f:
            f.write(json.dumps(payload))

        events = parser.parse_file(gz_path)
        assert len(events) == 1
        assert events[0].action == "s3:getobject"
        assert events[0].resource_arn == "arn:aws:s3:::data-lake/daily.csv"

    def test_parse_directory_recursive(self, parser: CloudTrailParser, tmp_path: Path) -> None:
        """Parse multiple files across subdirectories recursively."""
        sub1 = tmp_path / "day1"
        sub2 = tmp_path / "day2"
        sub1.mkdir()
        sub2.mkdir()

        (sub1 / "ev1.json").write_text(
            json.dumps(
                {
                    "Records": [
                        {
                            "eventVersion": "1.08",
                            "userIdentity": {"type": "IAMUser", "userName": "u1"},
                            "eventTime": "2026-01-01T12:00:00Z",
                            "eventSource": "s3.amazonaws.com",
                            "eventName": "ListBucket",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (sub2 / "ev2.json").write_text(
            json.dumps(
                {
                    "Records": [
                        {
                            "eventVersion": "1.08",
                            "userIdentity": {"type": "IAMUser", "userName": "u1"},
                            "eventTime": "2026-01-02T12:00:00Z",
                            "eventSource": "s3.amazonaws.com",
                            "eventName": "GetObject",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        events = parser.parse_directory(tmp_path, recursive=True)
        assert len(events) == 2
        assert events[0].action == "s3:listbucket"
        assert events[1].action == "s3:getobject"


# ==============================================================================
# 4. Temporal Workload Splitting & Conformance Tests
# ==============================================================================


class TestTemporalSplittingAndConformance:
    """Test T_1/T_2 partitioning, operational drift classification, and graph validation."""

    def test_temporal_workload_split_drift_tagging(self, parser: CloudTrailParser) -> None:
        """Verify automatic operational drift classification in holdout window T_2."""
        sample_path = Path("data/sample_cloudtrail.json")
        events = parser.parse_file(sample_path)

        # Split with t1_ratio=0.5 -> 2 events in T_1, 2 in T_2
        split = parser.create_temporal_split(events, t1_ratio=0.5)
        assert split.num_t1 == 2
        assert split.num_t2 == 2

        # In T_2:
        # Event 3 is ec2:DescribeInstances (action unseen in T_1) -> ACTION_DRIFT
        # Event 4 is legit-worker reading S3 (role unseen in T_1) -> FEDERATED_PIVOT
        assert split.drift_count >= 1
        assert split.drift_rate > 0.0

    def test_evaluate_conformance_on_iam_graph(
        self, parser: CloudTrailParser, sample_graph: IAMGraph
    ) -> None:
        """Evaluate empirical baseline conformance against IAMGraph."""
        sample_path = Path("data/sample_cloudtrail.json")
        events = parser.parse_file(sample_path)

        report = parser.evaluate_conformance(sample_graph, events)
        assert isinstance(report, CloudTrailConformanceReport)
        assert report.total_events == 4
        # All 4 successful events are authorized by sample_graph policies
        assert report.conforming_events == 4
        assert report.non_conforming_events == 0
        assert report.conformance_rate == 1.0

    def test_evaluate_conformance_detects_unauthorized_events(self, sample_graph: IAMGraph) -> None:
        """Ensure denied/unauthorized calls evaluate as non-conforming."""
        cfg = CloudTrailParserConfig(only_successful=False)
        p_with_denied = CloudTrailParser(config=cfg)
        events = p_with_denied.parse_file(Path("data/sample_cloudtrail.json"))

        report = p_with_denied.evaluate_conformance(sample_graph, events)
        assert report.total_events == 5
        # The 5th event is iam:CreateAccessKey by attacker-attempt (DENIED)
        assert report.non_conforming_events == 1
        assert report.conformance_rate == 0.8
        assert len(report.non_conforming_details) == 1
        assert (
            report.non_conforming_details[0]["principal_arn"]
            == "arn:aws:iam::123456789012:user/attacker-attempt"
        )


# ==============================================================================
# 5. CLI Subcommand Integration Tests
# ==============================================================================


class TestCLICloudTrailIngest:
    """Test CLI subcommand 'iam ingest-cloudtrail'."""

    def test_cli_ingest_cloudtrail_command(self, tmp_path: Path) -> None:
        """Execute cmd_ingest_cloudtrail through CLI handler."""
        from iam.cli import build_parser, cmd_ingest_cloudtrail

        out_ev = str(tmp_path / "events.json")
        out_sp = str(tmp_path / "split.json")

        parser = build_parser()
        args = parser.parse_args(
            [
                "ingest-cloudtrail",
                "--file",
                "data/sample_cloudtrail.json",
                "--output-events",
                out_ev,
                "--output-split",
                out_sp,
            ]
        )
        ret = cmd_ingest_cloudtrail(args)
        assert ret == 0

        assert Path(out_ev).is_file()
        assert Path(out_sp).is_file()

        with open(out_ev, encoding="utf-8") as f:
            ev_data = json.load(f)
            assert len(ev_data) == 4

        with open(out_sp, encoding="utf-8") as f:
            sp_data = json.load(f)
            assert "t1_events" in sp_data
            assert "t2_events" in sp_data
            assert "summary" in sp_data
