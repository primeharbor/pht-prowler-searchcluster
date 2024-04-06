#!/bin/bash
# Copyright 2024 Chris Farris <chris@primeharbor.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if [[ -z "$OUTPUT_BUCKET" ]] ; then
	echo "OUTPUT_BUCKET not defined. Aborting..."
	exit 1
fi

if [[ -z "$GCP_CREDS" ]] ; then
	echo "GCP_CREDS not defined. Aborting..."
	exit 1
fi

echo "Fetching $GCP_CREDS credentials"
aws secretsmanager get-secret-value --secret-id $GCP_CREDS --query SecretString --output text > gcp_creds.json
if [[ $? -ne 0 ]] ; then
	echo "Failed to get GCP Creds. Aborting"
	exit 1
fi

ulimit -n 4096

# Slack Support
SLACK=" --slack "
if [[ -z "$SLACK_API_TOKEN" ]] ; then
	SLACK=""
fi
if [[ -z "$SLACK_CHANNEL_ID" ]] ; then
	SLACK=""
fi

# Download the list of checks from S3
aws s3 cp --quiet s3://${OUTPUT_BUCKET}/checks.json .
aws s3 cp --quiet s3://${OUTPUT_BUCKET}/config.yaml .
aws s3 cp --quiet s3://${OUTPUT_BUCKET}/metadata.yaml .
aws s3 cp --quiet s3://${OUTPUT_BUCKET}/allow_list.yaml .

TODAY=`date +%Y-%m-%d`
START=`date +%s`

echo "Starting Scan of all projects for $GCP_CREDS at epoch timestamp $START."
echo "Command: prowler gcp -M csv json-ocsf json-asff -b -z $SLACK  \
	--checks-file checks.json \
	--config-file config.yaml \
	--mutelist-file allow_list.yaml \
	--custom-checks-metadata-file metadata.yaml \
	--log-file prowler-logs-${TODAY}.json \
	--output-filename prowler-gcp-${TODAY} \
	--log-level WARNING \
	--credentials-file gcp_creds.json \
	--output-directory prowler-output 2>&1 > prowler-logs-${TODAY}.log"

prowler gcp -M csv json-ocsf json-asff -b -z $SLACK  \
	--checks-file checks.json \
	--config-file config.yaml \
	--mutelist-file allow_list.yaml \
	--custom-checks-metadata-file metadata.yaml \
	--log-file prowler-logs-${TODAY}.json \
	--output-filename prowler-gcp-${TODAY} \
	--log-level WARNING \
	--credentials-file gcp_creds.json \
	--output-directory prowler-output 2> prowler-errors-${TODAY}.log > prowler-logs-${TODAY}.log
RC=$?

END=`date +%s`
DUR=`expr $END - $START`

aws s3 sync prowler-output/ s3://${OUTPUT_BUCKET}/prowler-gcp-output/$GCP_CREDS/

# cat prowler-logs-${ACCOUNT_ID}-${TODAY}.json  # Send this to CWL
grep "Enable it by visiting" prowler-logs-${TODAY}.log

# # Archive everything because storage is cheap or something
aws s3 cp prowler-logs-${TODAY}.log s3://${OUTPUT_BUCKET}/prowler-gcp-logs/
aws s3 cp prowler-logs-${TODAY}.json s3://${OUTPUT_BUCKET}/prowler-gcp-logs/
aws s3 cp prowler-errors-${TODAY}.log s3://${OUTPUT_BUCKET}/prowler-gcp-logs/

echo "Log of run can be found at s3://${OUTPUT_BUCKET}/prowler-gcp-logs/prowler-errors-${TODAY}.log"
echo "Prowler Exited with error code $RC after $DUR seconds"

