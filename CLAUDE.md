# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository manages Prowler and AWS Security Hub findings in OpenSearch. Prowler is an open-source AWS security assessment tool that scans AWS accounts for security best practices and compliance checks. This system runs Prowler scans across an entire AWS Organization and indexes the findings into OpenSearch for searchability and analysis.

## Architecture

### Core Components

1. **Prowler Container (ECS)**
   - Dockerized Prowler that runs on ECS Fargate
   - Executes security scans across AWS Organization accounts
   - Outputs findings to S3 in OCSF (Open Cybersecurity Schema Framework) format
   - Container defined in [Dockerfile](Dockerfile)
   - Scan orchestration scripts: [scripts/scan_organization.sh](scripts/scan_organization.sh)

2. **Lambda Processing Pipeline**
   - **process_prowler_file.py**: Triggered by S3 events when Prowler outputs findings, splits the file and queues individual findings to SQS
   - **import_prowler_findings.py**: Consumes findings from SQS and bulk ingests them into OpenSearch using the `_bulk` API
   - **decorate_prowler_findings.py**: Enriches findings with additional metadata before indexing
   - **alert_prowler_findings.py**: Monitors DynamoDB stream for critical findings and sends Slack alerts based on configuration
   - **process_regional_finding.py**: Handles AWS Security Hub findings from regional services
   - **process_sechub.py**: Processes Security Hub findings and indexes them to OpenSearch
   - **common.py**: Shared utilities for S3 operations, Secrets Manager, Slack messaging, and DynamoDB operations

3. **OpenSearch Cluster**
   - Stores and indexes Prowler findings
   - Two main indices: `prowler_findings_oscf` (AWS) and `prowler_findings_gcp` (GCP)
   - Uses IAM authentication via AWS4Auth
   - Can be integrated with AWS IAM Identity Center (formerly SSO) for dashboard access

4. **Google Sheets Scorecard Integration** (gsheet-lambda/)
   - Exports Prowler and Security Hub findings to Google Sheets for reporting
   - Lambdas: [gsheet-lambda/prowler_scorecard.py](gsheet-lambda/prowler_scorecard.py), [gsheet-lambda/sechub_scorecard.py](gsheet-lambda/sechub_scorecard.py)

### Data Flow

1. CloudWatch Event triggers ECS Task to run Prowler container
2. Prowler assumes role into each account and runs security checks
3. Findings written to S3 bucket as JSON-OCSF files
4. S3 event triggers `process_prowler_file` Lambda
5. Lambda splits findings and queues them to SQS
6. `import_prowler_findings` Lambda batch processes from SQS and bulk-indexes to OpenSearch
7. Findings are also written to DynamoDB
8. DynamoDB stream triggers `alert_prowler_findings` for critical findings
9. Slack alerts sent for findings matching configured checks

### CloudFormation Templates

- **Prowler-Template.yaml**: Main stack for Prowler ECS task, Lambda processors, SQS queues, and DynamoDB table
- **OpenSearch-Template.yaml**: OpenSearch cluster with optional SAML integration
- **Scorecards-Template.yaml**: Google Sheets scorecard Lambda functions
- **RegionalFindings-Template.yaml**: Regional Security Hub finding processors
- **SecurityHubToOpenSearch-Template.yaml**: Security Hub to OpenSearch integration

## Build and Development Commands

### Environment Configuration

All deployment commands require an environment config file (e.g., `config.FOO`):
```bash
export DEPLOY_BUCKET=fooli-deploy
export DEPLOY_PREFIX=prowler
export PROWLER_VERSION=4.x.x  # Required for all builds
export IMAGE_VERSION=20230805-1201
export ROLENAME=fooli-audit
export PAYER_ID=123456789012
export OUTPUT_BUCKET=fooli-prowler
```

Source your config before running make commands:
```bash
source config.FOO
```

### Docker Container Commands

Build Prowler container:
```bash
make env=FOO PROWLER_VERSION=4.x.x build
```

Force rebuild without cache:
```bash
make env=FOO PROWLER_VERSION=4.x.x force-build
```

Build GCP variant:
```bash
make env=FOO build-gcp
```

Run container locally for testing:
```bash
make env=FOO run
```

Push container to ECR:
```bash
make env=FOO push
# Updates IMAGE_VERSION in your config after pushing
```

Create ECR repository:
```bash
make env=FOO repo
```

### Lambda Dependency Management

Install/update Lambda dependencies:
```bash
cd lambda && make deps
cd gsheet-lambda && make scorecard-deps
```

Clean Lambda dependencies:
```bash
make clean  # Cleans both lambda/ and gsheet-lambda/
```

### Deployment Commands

Package and deploy Prowler stack:
```bash
make env=FOO prowler-package  # Packages and uploads to S3
make env=FOO prowler-deploy PROWLER_MANIFEST=Manifests/Fooli-Prowler-Manifest.yaml
```

Deploy OpenSearch cluster:
```bash
make env=FOO opensearch-package
make env=FOO opensearch-deploy SEARCH_MANIFEST=Manifests/Fooli-OpenSearch-Manifest.yaml
```

Deploy Scorecards:
```bash
make env=FOO scorecard-package
make env=FOO scorecard-deploy SCORECARD_MANIFEST=Manifests/Fooli-Scorecard-Manifest.yaml
```

Deploy Regional Findings:
```bash
make env=FOO findings-package
make env=FOO findings-deploy FINDINGS_MANIFEST=cloudformation/Fooli-Findings-Manifest.yaml
```

### Utility Scripts

Enable IAM role mapping in OpenSearch:
```bash
./scripts/enable_iam_roles.sh <OpenSearch-StackName> <Prowler-StackName>
```

Enable Lambda IAM role access to OpenSearch:
```bash
./scripts/enable_lambda_role.sh <OpenSearch-StackName> <Prowler-StackName>
```

Trigger manual Prowler scan:
```bash
./scripts/trigger-prowler-scan.sh
```

Scan specific account:
```bash
./scripts/scan_account.sh
```

Replay findings from S3 to reprocess:
```bash
./scripts/replay_findings.py
```

Backfill findings:
```bash
./scripts/backfill_prowler_findings_replay.py
```

Create OpenSearch index:
```bash
./scripts/create_index.py
```

## Configuration Files

### Prowler Configuration (stored in S3 bucket)

- **checks.json**: List of Prowler checks to run
- **config.yaml**: Prowler configuration settings
- **metadata.yaml**: Custom metadata for checks
- **allow_list.yaml**: Exceptions and allowlisted findings
- **slack_alert.yaml**: Configuration for which checks trigger Slack alerts (under `ProwlerChecks` key)

### Lambda Environment Variables

Key environment variables used by Lambda functions:
- `ES_DOMAIN_ENDPOINT`: OpenSearch domain endpoint
- `FINDING_QUEUE_URL`: SQS queue URL for findings
- `CONFIG_BUCKET`: S3 bucket for configuration files
- `SLACK_SECRET`: ARN of Secrets Manager secret with Slack credentials
- `LOG_LEVEL`: Logging level (default: INFO)

### Secrets Manager

Slack alerts require a secret with:
- `SLACK_API_TOKEN`: Bot token for Slack API
- `SLACK_CHANNEL_ID`: Channel ID to post alerts

## Key Technical Details

### OpenSearch Authentication

The Lambda functions use AWS4Auth (SigV4) to authenticate to OpenSearch. The IAM roles must be mapped in the OpenSearch security configuration using the enable scripts.

### Finding Deduplication

Findings are deduplicated by document ID: `{finding_info_uid}-{event_date}`. This allows tracking findings over time by creating one document per finding per day.

### Bulk Indexing

The `import_prowler_findings` Lambda uses OpenSearch's `_bulk` API for efficient batch indexing. Each SQS batch is converted to a newline-delimited JSON bulk request.

### Data Cleanup

To prevent unbounded index growth, certain fields are removed before indexing:
- `unmapped.compliance`: Removed from findings
- `resources[0].data.metadata`: Removed to reduce payload size

### Alert Filtering

The `alert_prowler_findings` Lambda only alerts on findings where:
1. The check code is listed in `slack_alert.yaml` under `ProwlerChecks`
2. The severity is `critical`

### GCP Support

Limited GCP support exists via [Dockerfile-GCP](Dockerfile-GCP) and [scripts/scan_gcp_org.sh](scripts/scan_gcp_org.sh). Findings are indexed to `prowler_findings_gcp`.

## Common Workflows

### Initial Deployment

1. Create and source config file
2. Create ECR repo: `make env=FOO repo`
3. Build and push container: `make env=FOO build push`
4. Generate manifest: `cft-generate-manifest -m Manifests/Foo-Prowler-Manifest.yaml -t cloudformation/Prowler-Template.yaml`
5. Edit manifest with stack parameters
6. Deploy: `make env=FOO prowler-deploy PROWLER_MANIFEST=Manifests/Foo-Prowler-Manifest.yaml`

### Updating Prowler Version

1. Update `PROWLER_VERSION` in config file
2. Rebuild container: `make env=FOO force-build`
3. Push to ECR: `make env=FOO push`
4. Note the new `IMAGE_VERSION` output
5. Update stack: `make env=FOO prowler-deploy PROWLER_MANIFEST=Manifests/Foo-Prowler-Manifest.yaml`

### Adding New Lambda Code

1. Modify Lambda function in `lambda/` directory
2. Update dependencies if needed: `cd lambda && make deps`
3. Package stack: `make env=FOO prowler-package`
4. Deploy: `make env=FOO prowler-deploy PROWLER_MANIFEST=...`

### Debugging Findings

1. Check CloudWatch Logs for Lambda functions
2. Review S3 bucket for raw finding files
3. Query OpenSearch directly using index patterns
4. Check DynamoDB table for finding records
5. Review `prowler-logs/` prefix in S3 for container execution logs
