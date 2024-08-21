# Copyright 2023 Chris Farris <chrisf@primeharbor.com>
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


import json
import logging
import os
from typing import Dict, List

from boto3.dynamodb.conditions import Key

from common import DynamoDBTable, get_object, put_dict_object


logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

# Using environ to raise KeyError if not provided
TABLE_NAME = os.environ["TRACKING_TABLE_NAME"]
OUTPUT_BUCKET = os.environ["OUTPUT_BUCKET"]
OUTPUT_PREFIX = "prowler4-output/json-ocsf-processed/"

logger.info("decorate_prowler_findings initiated")

# Lambda execution starts here
def handler(event, context):
    logger.debug("Received event: " + json.dumps(event, sort_keys=True))

    for record in event["Records"]:
        body = json.loads(record["body"])
        if "Message" in body:
            message = json.loads(body["Message"])
            if message.get("Event") == "s3:TestEvent":
                logger.warning(f"Received Test Event. Doing Nothing.")
                continue
            s3_records = message["Records"]
        else:
            s3_records = body["Records"]

        logger.info(f"received {len(s3_records)} S3 objects to process")
        # Is there a possibility for many objects here?
        for s3_record in s3_records:
            bucket = s3_record['s3']['bucket']['name']
            obj_key = s3_record['s3']['object']['key']
            file_name = os.path.basename(obj_key)
            output_key = f"{OUTPUT_PREFIX}{file_name}"

            logger.info(f"Processing file s3://{bucket}/{obj_key}")
            findings_to_process = get_object(bucket, obj_key)
            if not findings_to_process:
                raise Exception(f"Failed to get s3://{bucket}/{obj_key}") # This will force a requeue?

            logger.info(f"{len(findings_to_process)} findings to process in s3://{bucket}/{obj_key}")
            processed_findings = process_account_findings(findings_to_process)
            logger.info(f"writing findings to s3://{OUTPUT_BUCKET}/{output_key}")
            put_dict_object(OUTPUT_BUCKET, output_key, processed_findings)
            

def process_account_findings(findings_to_process: List[Dict]) -> List[Dict]:
    """
    Given a list of Prowler findings for an AWS account:
        - Looks up all findings for the AWS account in DynamoDB
        - If not in DynamoDB, adds a start_time field to the finding (from the event_time). Adds the finding to DDB.
        - If in DynamoDB, adds the start_time field from DynamoDB to the finding
    Important assumption that all findings are from the same account.

    Args:
        findings_to_process (List[Dict]): List of prowler dictionary findings

    Returns:
        processed_findings (List[Dict]): List of prowler dictionary findings with additional fields from DDB
    """
    table_handler = DynamoDBTable(TABLE_NAME)

    logger.info(f"processing {len(findings_to_process)} findings")
    # Query for all findings just from the account number
    account_id = findings_to_process[0]["cloud"]["account"]["uid"]
    account_findings: Dict = table_handler.table.query(
        IndexName="CloudAccountIndex",
        KeyConditionExpression=Key("cloud_account_uid").eq(account_id),
        ProjectionExpression="finding_info_uid, cloud_account_uid, metadata_event_code, start_time"
    )
    finding_uids = []
    for item in account_findings.get("Items", {}):
        finding_uids.append(item.get("finding_info_uid"))

    findings_to_add = []
    processed_findings = []
    for f in findings_to_process:
        finding_uid = f["finding_info"]["uid"]
        # If the finding is PASS/MANUAL, just write to output file as-is
        if f["status_code"] != "FAIL":
            logger.debug(f"finding uid {finding_uid} status is {f['status_code']}, skipping")
            processed_findings.append(f)
            continue
        
        if finding_uid not in finding_uids:
            logger.debug(f"finding uid {finding_uid} not found in dynamodb, adding to table")
            f["start_time"] = f["event_time"]
            processed_findings.append(f)
            # Don't want to add these to the output file (unnecessary), but do want them to be added to DDB
            f["finding_info_uid"] = f["finding_info"]["uid"]
            f["metadata_event_code"] = f["metadata"]["event_code"]
            f["cloud_account_uid"] = f["cloud"]["account"]["uid"]
            findings_to_add.append(f)
            continue
        
        logger.debug(f"finding uid {finding_uid} found in dynamodb")
        start_time = item["start_time"]
        logger.debug(f"finding uid {finding_uid} has a dynamodb start time of {start_time}, adding to output file")
        f["start_time"] = item["start_time"]
        processed_findings.append(f)

    logger.debug(f"adding {len(findings_to_add)} findings to dynamodb")
    table_handler.batch_write_items(findings_to_add)

    logger.info(f"processed {len(processed_findings)} findings")

    return processed_findings