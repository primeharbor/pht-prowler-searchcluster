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

from botocore.exceptions import ClientError
from datetime import datetime
from google.oauth2 import service_account
from googleapiclient.discovery import build
from gspread.exceptions import WorksheetNotFound, APIError, SpreadsheetNotFound
from time import sleep
import boto3
import gspread
import json
import os
import re

from common import *

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)


HEADER_ROW = ['FindingUniqueId', 'AssessmentStartTime', 'AccountId', 'AccountName', 'CheckID', "Severity", 'Status', "CheckTitle", "ServiceName", "SubServiceName", "Region", "ResourceArn", "ResourceName",  "StatusExtended"]



# Lambda execution starts here
def handler(event, context):
    logger.debug("Received event: " + json.dumps(event, sort_keys=True))

    for record in event['Records']:
        if 'body' in record:
            sns_message = json.loads(record['body'])
            if 'Message' in sns_message:
                sns_message2 = json.loads(sns_message['Message'])
                if 'Event' in sns_message2 and sns_message2['Event'] == "s3:TestEvent":
                    logger.warning(f"Received Test Event. Doing Nothing.")
                    continue
                s3_record_list = sns_message2['Records']
            else:
                s3_record_list = sns_message['Records']
        else:
            s3_record_list = event['Records']

        for s3_record in s3_record_list:
            bucket = s3_record['s3']['bucket']['name']
            obj_key = s3_record['s3']['object']['key']
            process_file(bucket, obj_key)


def process_file(bucket, obj_key):
    logger.info(f"Processing file s3://{bucket}/{obj_key}")
    findings_to_process = get_object(bucket, obj_key)
    if findings_to_process is None:
        raise Exception(f"Failed to get s3://{bucket}/{obj_key}") # This will force a requeue?

    # figure out which worksheet (by date) from the S3 Object Name (thanks chatgpt)
    pattern = r'\d{4}-\d{2}-\d{2}' # Regular expression to match the date pattern
    match = re.search(pattern, obj_key)

    if match:
        # Extract the matched date
        today = match.group(0)
    else:
        logger.critical(f"Date not found in {obj_key}.")
        return(None)

    sheet_name = f"Prowler-Scorecard-{today}"
    worksheet_name = f"All-Findings"
    gsheet = open_or_create_gsheet(sheet_name, worksheet_name, HEADER_ROW)

    if gsheet is None:
        logger.critical(f"Failed to open {sheet_name}. Aborting...")
        raise Exception(f"Failed to open {sheet_name}. Aborting...")

    try:
        worksheet = gsheet.worksheet(worksheet_name)
    except WorksheetNotFound as e:
        raise Exception(f"Cannot find Worksheet {worksheet_name} in {sheet_name}")

    row_of_rows = []
    count = 0

    logger.info(f"{len(findings_to_process)} findings to process in s3://{bucket}/{obj_key}")
    for f in findings_to_process:
        row = process_prowler_ocsf(f)

        if row is not None:
            row_of_rows.append(row)
        if len(row_of_rows) >= BATCH_SIZE:
            count += write_to_gsheet(worksheet, row_of_rows)
            row_of_rows = []

    # Write the remaining data for this file
    count += write_to_gsheet(worksheet, row_of_rows)
    row_of_rows = []

    logger.info(f"Processed {count} records from {obj_key}")


def process_prowler_ocsf(f):
    if f['status_code'] == "PASS" or f['status_code'] == "MANUAL":
        return(None)

    status = f['status_code']
    if f['status'] == "Suppressed":
        status = "Suppressed"

    if len(f['resources']) > 1:
        logger.warning(f"Finding {f['finding_info']['uid']} has multiple resources")

    row = [
        f['finding_info']['uid'],
        f['event_time'],
        f['cloud']['account']['uid'],
        f['cloud']['account']['name'],
        f['metadata']['event_code'],
        f['severity'],
        status,
        f['finding_info']['title'],
        f['resources'][0]['group']['name'],
        f['resources'][0]['type'],
        f['resources'][0]['region'],
        f['resources'][0]['uid'],
        f['resources'][0]['name'],
        f['status_detail'],
    ]
    return(row)


def process_prowler_native(f):
    if f['Status'] == "PASS" or f['Status'] == "INFO":
        return(None)
    resource_name = ""
    if 'Name' in f['ResourceTags']:
        resource_name = f['ResourceTags']['Name']
    row = [
        f['FindingUniqueId'],
        f['AssessmentStartTime'],
        f['AccountId'],
        f['OrganizationsInfo']['account_details_name'],
        f['CheckID'],
        f['Severity'],
        f['Status'],
        f['CheckTitle'],
        f['ServiceName'],
        f['SubServiceName'],
        f['Region'],
        f['ResourceArn'],
        resource_name,
        f['StatusExtended'],
    ]
    return(row)

