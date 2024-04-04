#!/bin/bash
# Copyright 2023 Chris Farris <chris@primeharbor.com>
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

if [[ -z "$ROLENAME" ]] ; then
	echo "ROLENAME not defined. Aborting..."
	exit 1
fi

if [[ -z "$OUTPUT_BUCKET" ]] ; then
	echo "OUTPUT_BUCKET not defined. Aborting..."
	exit 1
fi

if [[ -z "$PAYER_ID" ]] ; then
	echo "PAYER_ID not defined. Aborting..."
	exit 1
fi

ulimit -n 4096

if [[ -z "$REGIONS" ]] ; then
	REGIONS="ap-south-1 eu-north-1 eu-west-3 eu-west-2 eu-west-1 ap-northeast-3 ap-northeast-2 ap-northeast-1 ca-central-1 sa-east-1 ap-southeast-1 ap-southeast-2 eu-central-1 us-east-1 us-east-2 us-west-1 us-west-2"
fi

# Slack Support
SLACK=" --slack "
if [[ -z "$SLACK_API_TOKEN" ]] ; then
	SLACK=""
fi
if [[ -z "$SLACK_CHANNEL_ID" ]] ; then
	SLACK=""
fi

if [[ ! -z "$SECURITY_HUB" ]] ; then
	if [[ $SECURITY_HUB == "ENABLED" ]] ; then
		SECURITY_HUB_FLAG=" -S "
		./enable_prowler_securityhub_integration.py --product-name prowler --company-name prowler --role-name $ROLENAME
	fi
fi

# Download the list of checks from S3
aws s3 cp s3://${OUTPUT_BUCKET}/checks.json .
aws s3 cp s3://${OUTPUT_BUCKET}/config.yaml .
aws s3 cp s3://${OUTPUT_BUCKET}/metadata.yaml .
aws s3 cp s3://${OUTPUT_BUCKET}/allow_list.yaml .

TODAY=`date +%Y-%m-%d`

# Log this in the CW Logs
prowler --version

while read line ; do

	START=`date +%s`
	# extract the values we need
	ACCOUNT_ID=`echo $line | awk '{print $1}'`
	ACCOUNT_STATUS=`echo $line | awk '{print $2}'`

	if [ -f prowler-output/prowler-${ACCOUNT_ID}-${TODAY}.json ] ; then
		echo "$ACCOUNT_ID was already scanned on $TODAY"
		continue
	fi

	echo "Starting Scan of account $ACCOUNT_ID at epoch timestamp $START."
	echo "Command: 	prowler aws -M csv json-ocsf json-asff -b -z $SLACK $SECURITY_HUB_FLAG \
		--checks-file checks.json -f $REGIONS \
		--config-file config.yaml -w allow_list.yaml \
		--custom-checks-metadata-file metadata.yaml \
		--log-file prowler-logs-${ACCOUNT_ID}-${TODAY}.json \
		--output-filename prowler-${ACCOUNT_ID}-${TODAY} --log-level WARNING \
		--role arn:aws:iam::$ACCOUNT_ID:role/$ROLENAME \
		--organizations-role arn:aws:iam::$PAYER_ID:role/$ROLENAME \
		--output-bucket-no-assume ${OUTPUT_BUCKET} \
		--output-directory prowler4-output 2> prowler-errors-${ACCOUNT_ID}-${TODAY}.log > prowler-logs-${ACCOUNT_ID}-${TODAY}.log"

	prowler aws -M csv json-ocsf json-asff -b -z $SLACK $SECURITY_HUB_FLAG \
		--checks-file checks.json -f $REGIONS \
		--config-file config.yaml -w allow_list.yaml \
		--custom-checks-metadata-file metadata.yaml \
		--log-file prowler-logs-${ACCOUNT_ID}-${TODAY}.json \
		--output-filename prowler-${ACCOUNT_ID}-${TODAY} --log-level WARNING \
		--role arn:aws:iam::$ACCOUNT_ID:role/$ROLENAME \
		--organizations-role arn:aws:iam::$PAYER_ID:role/$ROLENAME \
		--output-bucket-no-assume ${OUTPUT_BUCKET} \
		--output-directory prowler4-output 2> prowler-errors-${ACCOUNT_ID}-${TODAY}.log > prowler-logs-${ACCOUNT_ID}-${TODAY}.log
	RC=$?

	END=`date +%s`
	DUR=`expr $END - $START`

	cat prowler-logs-${ACCOUNT_ID}-${TODAY}.json  # Send this to CWL

    # We want to see this in the CWLogs
	grep "AWS Security Hub!" prowler-logs-${ACCOUNT_ID}-${TODAY}.log

    # Archive everything because storage is cheap or something
	aws s3 cp prowler-logs-${ACCOUNT_ID}-${TODAY}.log s3://${OUTPUT_BUCKET}/prowler-logs/
	aws s3 cp prowler-logs-${ACCOUNT_ID}-${TODAY}.json s3://${OUTPUT_BUCKET}/prowler-logs/
	aws s3 cp prowler-errors-${ACCOUNT_ID}-${TODAY}.log s3://${OUTPUT_BUCKET}/prowler-logs/
	echo "Prowler Exited for $ACCOUNT_ID with error code $RC after $DUR seconds"

done < <(aws organizations list-accounts --query Accounts[].[Id,Status] --output text | grep ACTIVE )