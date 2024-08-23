#!/usr/bin/env python3
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

import argparse
import concurrent.futures
import json
import logging
import os
import re
from typing import Dict, List, Optional

import boto3
from boto3.dynamodb.conditions import Key
from urllib.parse import unquote


logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='DEBUG')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

file_handler = logging.FileHandler("backfill_output.log")
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

parser = argparse.ArgumentParser()
parser.add_argument("--profile", help="AWS profile to use")
parser.add_argument("--bucket", help="S3 bucket where findings are", required=True)
parser.add_argument("--table-name", help="DynamoDB table to write output", required=True)
parser.add_argument("--prefix", help="Prefix where json files live in bucket", default="prowler4-output/json-ocsf/")


args = parser.parse_args()


s3 = boto3.client("s3")

def list_objects(bucket, prefix) -> List[str]:
    objects = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        if "Contents" in page:
            for obj in page["Contents"]:
                objects.append(obj["Key"])

    return objects

def get_json_object(bucket, obj_key) -> List[Dict]:
    response = s3.get_object(Bucket=bucket, Key=unquote(obj_key))

    return json.loads(response["Body"].read())

class DynamoDBTable:
    """
    General wrapper for DynamoDB operations
    """
    def __init__(self, table_name: str) -> None:
        self.table_name = table_name
        dynamodb = boto3.resource("dynamodb")
        self.table = dynamodb.Table(self.table_name)

    def batch_write_items(self, items: List[Dict], batch_size: Optional[int] = 25) -> None:
        """
        Given a list of dictionaries, batch write them all to the table

        Args:
            items (List[Dict]): list of dictionaries to write
            batch_size (Optional[int]): size of the batches to write. Default (and max) is 25
        """
        if batch_size > 25:
            batch_size = 25
            
        logger.info(f"writing {len(items)} items to DynamoDB table {self.table_name}")

        written_items = 0
        for i in range(0, len(items), batch_size):
            batch = items[i:i+batch_size]
            written_items += len(batch)
            with self.table.batch_writer() as batch_writer:
                for item in batch:
                    try:
                        batch_writer.put_item(Item=item)
                    except Exception:
                        logger.exception(f"error writing {item} to dynamodb")
                        raise
        
        logger.info(f"wrote {written_items} items to DynamoDB table {self.table_name}")

def process_findings_for_account(account: str, account_files: List[str], table_handler: DynamoDBTable, account_finding_uids: Dict):
    findings_to_add = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_s3 = {executor.submit(get_json_object, args.bucket, obj_name): obj_name for obj_name in account_files}
        for future in concurrent.futures.as_completed(future_to_s3):
            obj_name = future_to_s3[future]
            try:
                s3_findings = future.result()
                for s3_finding in s3_findings:
                    process_single_finding(s3_finding, account_finding_uids, findings_to_add)
            except Exception as e:
                logger.error(f"Error processing {obj_name}: {e}")

    logger.info(f"{len(findings_to_add)} findings to add or replace for account {account}")
    # there may have been multiple days where the finding appears, need to only keep the newest one
    deduped_findings = {}
    for finding in findings_to_add:
        if finding["finding_info_uid"] in deduped_findings:
            if finding["start_time"] < deduped_findings[finding["finding_info_uid"]]["start_time"]:
                deduped_findings[finding["finding_info_uid"]] = finding
        else:
            deduped_findings[finding["finding_info_uid"]] = finding
    
    logger.info(f"{len(deduped_findings)} unique findings to add or replace for account {account}")
    table_handler.batch_write_items(list(deduped_findings.values()))

def process_single_finding(s3_finding: Dict, account_finding_uids: Dict, findings_to_add: List):
    s3_finding_uid = s3_finding["finding_info"]["uid"]
    if s3_finding["status_code"] != "FAIL":
        logger.debug(f"finding uid {s3_finding_uid} status is {s3_finding['status_code']}, skipping")
        return

    s3_finding.pop("unmapped")
    s3_finding["finding_info_uid"] = s3_finding["finding_info"]["uid"]
    s3_finding["metadata_event_code"] = s3_finding["metadata"]["event_code"]
    s3_finding["cloud_account_uid"] = s3_finding["cloud"]["account"]["uid"]
    s3_finding["start_time"] = s3_finding["event_time"]
    # if finding not in account_findings, add to DDB
    if s3_finding_uid not in account_finding_uids:
        logger.info(f"finding uid {s3_finding_uid} doesn't exist in DDB, adding to table")
        findings_to_add.append(s3_finding)
    # if finding in account_findings, compare start_time
    else:
        # if start_time in file finding is earlier than DDB, replace DDB finding (remove unmapped field)
        s3_event_time = s3_finding["event_time"]
        if s3_event_time < account_finding_uids[s3_finding_uid]:
            logger.info(f"finding uid {s3_finding_uid}'s start time in DDB ({account_finding_uids[s3_finding_uid]}) is later than the S3 start time ({s3_event_time}). Replacing in DDB")
            findings_to_add.append(s3_finding)
        else:
            logger.info(f"finding uid {s3_finding_uid}'s start time in DDB ({account_finding_uids[s3_finding_uid]}) is earlier than the S3 start time ({s3_event_time}). Skipping")

def main():
    table_handler = DynamoDBTable(args.table_name)

    file_name_account_id_regex = r'\b\d{12}\b'
    objects = list_objects(args.bucket, args.prefix)
    account_files = {}
    for object in objects:
        match = re.search(file_name_account_id_regex, object)
        account_number = match.group(0)
        account_files.setdefault(account_number, []).append(object)

    for account, account_object_names in account_files.items():
        logger.info(f"backfilling findings for account {account}")
        
        # query once for the whole account so we can reduce DDB interaction
        account_findings: Dict = table_handler.table.query(
            IndexName="CloudAccountIndex",
            KeyConditionExpression=Key("cloud_account_uid").eq(account),
            ProjectionExpression="finding_info_uid, cloud_account_uid, metadata_event_code, start_time"
        )
        account_finding_uids = {item["finding_info_uid"]: item["start_time"] for item in account_findings.get("Items", {})}

        process_findings_for_account(account, account_object_names, table_handler, account_finding_uids)

if __name__ == "__main__":
    main()