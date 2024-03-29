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

ACCOUNT_ID=$1

if [[ -z "$ACCOUNT_ID" ]] ; then
        echo "Usage: $0 <account_id>"
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
        if [[ $SECURITY_HUB -eq 1 ]] ; then
                SECURITY_HUB_FLAG=" -S "
        fi
fi

# Download the list of checks from S3 if needed
if [[ ! -f checks.json ]] ; then
        aws s3 cp s3://${OUTPUT_BUCKET}/checks.json .
fi

if [[ ! -f config.yaml ]] ; then
        aws s3 cp s3://${OUTPUT_BUCKET}/config.yaml .
fi


TODAY=`date +%Y-%m-%d`
START=`date +%s`

echo "Starting Scan of account $ACCOUNT_ID at epoch timestamp $START."
prowler aws -M csv json json-asff html -b -z $SLACK $SECURITY_HUB_FLAG \
        --checks-file checks.json -f $REGIONS \
        --config-file config.yaml \
        --log-file prowler-logs-${ACCOUNT_ID}-${TODAY}.log \
        -F prowler-${ACCOUNT_ID}-${TODAY} --log-level ERROR \
        -R arn:aws:iam::$ACCOUNT_ID:role/$ROLENAME \
        -O arn:aws:iam::$PAYER_ID:role/$ROLENAME \
        -D ${OUTPUT_BUCKET} -o prowler-output # 2> prowler-errors-${ACCOUNT_ID}-${TODAY}.log
RC=$?

END=`date +%s`
DUR=`expr $END - $START`

# aws s3 cp prowler-logs-${ACCOUNT_ID}-${TODAY}.log s3://${OUTPUT_BUCKET}/prowler-logs/
# aws s3 cp prowler-errors-${ACCOUNT_ID}-${TODAY}.log s3://${OUTPUT_BUCKET}/prowler-logs/
echo "Prowler Exited for $ACCOUNT_ID with error code $RC after $DUR seconds"
