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

from boto3.dynamodb.conditions import Key
from datetime import datetime
from typing import Dict, List, Tuple
import copy
import json
import logging
import os

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
TABLE_HANDLER = DynamoDBTable(TABLE_NAME)

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

            if 'event_code' not in findings_to_process[0]["metadata"]:
                logger.warning(f"event_code not present in finding metadata. Is s3://{bucket}/{obj_key} from before prowler v4.2.0?")
                continue

            logger.info(f"{len(findings_to_process)} findings to process in s3://{bucket}/{obj_key}")
            processed_findings, new_findings = process_account_findings(findings_to_process)
            logger.debug(f"adding {len(new_findings)} findings to dynamodb")
            TABLE_HANDLER.batch_write_items(new_findings)

            logger.info(f"writing findings to s3://{OUTPUT_BUCKET}/{output_key}")
            put_dict_object(OUTPUT_BUCKET, output_key, processed_findings)


def process_account_findings(findings_to_process: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """
    Given a list of Prowler findings for an AWS account:
        - Looks up all findings for the AWS account in DynamoDB
        - If not in DynamoDB, adds a start_time field to the finding (from the event_time). Adds the finding to DDB.
        - If in DynamoDB, adds the start_time field from DynamoDB to the finding
    Important assumption that all findings are from the same account.

    Args:
        findings_to_process (List[Dict]): List of prowler dictionary findings

    Returns:
        processed_findings, new_findings (Tuple[List[Dict], List[Dict]]): List of prowler dictionary findings with additional fields from DDB,
all new findings to be written to DDB
    """
    logger.info(f"processing {len(findings_to_process)} findings")
    # Query for all findings just from the account number
    account_id = findings_to_process[0]["cloud"]["account"]["uid"]
    account_findings = TABLE_HANDLER.paginate_query(index_name="CloudAccountIndex", key_condition_expression=Key("cloud_account_uid").eq(account_id), projection_expression="finding_info_uid, start_time")
    existing_finding_uids = {}
    for item in account_findings:
        existing_finding_uids[item.get("finding_info_uid")] = {"start_time": item.get("start_time")}

    new_findings = [] # findings to be added to dynamodb
    processed_findings = [] # full list of processed findings
    for f in findings_to_process:
        # Prowler changed the format of the OSCF output and renamed event_time to time_dt.
        # We copy it back
        f['event_time'] = f['time_dt']

        finding_uid = f["finding_info"]["uid"]
        # If the finding is PASS/MANUAL, just write to output file as-is
        if f["status_code"] != "FAIL":
            logger.debug(f"finding uid {finding_uid} status is {f['status_code']}, skipping")
            processed_findings.append(f)
            continue

        existing_finding = existing_finding_uids.get(finding_uid, {})
        if not existing_finding or f["event_time"] < existing_finding.get("start_time"):
            if finding_uid not in existing_finding_uids:
                logger.debug(f"finding uid {finding_uid} not found in dynamodb, adding to table")
            # Handle possible scenario where incoming finding was processed out of order and the start time is earlier even though the finding has already been written to table
            elif f["event_time"] < existing_finding.get("start_time"):
                logger.debug("finding event time is before dynamodb start time, updating table")
            f["start_time"] = f["event_time"]
            processed_findings.append(f)
            ddb_finding = create_ddb_finding(f)
            new_findings.append(ddb_finding)
        # If finding already in table and the finding event time is after the existing record's start time, just write new start time to S3 output file
        else:
            logger.debug(f"finding uid {finding_uid} found in dynamodb and has a start time of {existing_finding.get('start_time')}, adding to output file")
            # Need to ensure start time is unchanged from original start time when overwriting to ddb
            f["start_time"] = existing_finding.get("start_time")
            processed_findings.append(f)
            ddb_finding = create_ddb_finding(f)
            logger.debug(f"finding uid {finding_uid} found in dynamodb and has an event time of {ddb_finding.get('event_time')}, updating in table")
            new_findings.append(ddb_finding)

    new_findings = remove_duplicate_findings(new_findings)

    logger.info(f"account id {account_id}: processed {len(processed_findings)} findings with {len(new_findings)} new findings")

    return processed_findings, new_findings

def create_ddb_finding(finding: Dict) -> Dict:
    """Given a finding dictionary, clean up fields and add required fields for writing to DDB"""
    ddb_finding = {}

    ddb_finding["finding_info_uid"] = finding["finding_info"]["uid"]
    ddb_finding["metadata_event_code"] = finding["metadata"]["event_code"]
    ddb_finding["cloud_account_uid"] = finding["cloud"]["account"]["uid"]
    ddb_finding["event_time"] = finding["event_time"]
    ddb_finding["severity"] = finding["severity"]
    ddb_finding["start_time"] = finding["start_time"]
    ddb_finding["status_detail"] = finding["status_detail"][:512]
    ddb_finding["title"] = finding["finding_info"]["title"]

    # Define the format of the date string
    date_format = "%Y-%m-%dT%H:%M:%S.%f"

    # Convert the date string to a datetime object
    date_obj = datetime.strptime(finding["event_time"], date_format)
    ddb_finding["event_time_epoch_ts"] = int(date_obj.timestamp())
    date_obj = datetime.strptime(finding["start_time"], date_format)
    ddb_finding["start_time_epoch_ts"] =  int(date_obj.timestamp())

    return ddb_finding

def remove_duplicate_findings(findings: List[Dict]) -> List[Dict]:
    """
    Stopgap measure to handle when Prowler provides a duplicate finding IDs.
    Iterates through the findings, and if a duplicate finding is found - only keep one with older start time.
    """
    uid_dict = {}
    for finding in findings:
        uid = finding["finding_info_uid"]
        start_time = finding["start_time"]

        # If UID is not in the dictionary or the current start_time is earlier, update the dictionary
        if uid not in uid_dict or start_time < uid_dict[uid]["start_time"]:
            if uid not in uid_dict:
                logger.debug(f"finding {uid} is unique, adding to new_findings")
            else:
                logger.info(f"finding {uid} is a duplicate and has an earlier start time, replacing previous value")

            uid_dict[uid] = finding
        else:
            logger.info(f"finding {uid} is a duplicate and has a newer start time, not adding to new_findings")

    # Convert the dictionary back to a list
    return list(uid_dict.values())