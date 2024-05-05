# Copyright 2024 Chris Farris <chrisf@primeharbor.com>
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

HEADER_ROW = [ "FindingId", "LastObservedAt", "FirstObservedAt", "AwsAccountId", "AwsAccountName", "Region", "Severity", "ProductName", "Title",  "Description", "Resource", "ConsoleURL" ]
PRODUCTS = ["GuardDuty", "Macie"]

# Lambda execution starts here
def handler(event, context):
    logger.debug("Received event: " + json.dumps(event, sort_keys=True))

    # Only open the sheet if necessary
    worksheet = None

    row_of_rows = []
    count = 0

    # Only grab the detail from the event. The other stuff is related to the eventbridge event wraper
    for finding in event['detail']['findings']:

        if finding['ProductName'] == "GuardDuty":
            row = process_guardduty(finding)
        elif finding['ProductName'] == "Macie":
            row = process_macie(finding)
        else:
            logger.warning(f"Not processing Product {finding['ProductName']}")
            continue

        if row is not None:
            row_of_rows.append(row)
        if len(row_of_rows) >= BATCH_SIZE:
            if worksheet is None:
                worksheet = open_worksheet()
            count += write_to_gsheet(worksheet, row_of_rows)
            row_of_rows = []

    # Write the remaining data for this file
    if worksheet is None:
        worksheet = open_worksheet()
    count += write_to_gsheet(worksheet, row_of_rows)
    row_of_rows = []

    logger.info(f"Processed {count} findings from SecurityHub")


def open_worksheet():
    # Create a new Sheet for each month
    month = f"{datetime.now().year}-{datetime.now().month}"

    sheet_name = f"SecurityHub-Scorecard-{month}"
    worksheet_name = f"All-Findings"
    gsheet = open_or_create_gsheet(sheet_name, worksheet_name, HEADER_ROW)

    try:
        worksheet = gsheet.worksheet(worksheet_name)
        return(worksheet)
    except WorksheetNotFound as e:
        raise Exception(f"Cannot find Worksheet {worksheet_name} in {sheet_name}")

def process_guardduty(finding):

    resources = []
    for r in finding['Resources']:
        resources.append(r['Id'])

    row = [
        finding['Id'],
        finding['FirstObservedAt'],
        finding['LastObservedAt'],
        finding['AwsAccountId'],
        finding['AwsAccountName'],
        finding['Region'],
        finding['Severity']['Label'],
        finding['ProductName'],
        finding['Title'],
        finding['Description'],
        " ".join(resources),
        finding['SourceUrl'],
    ]
    return(row)


def process_macie(finding):
    row = [
        finding['Id'],
        finding['CreatedAt'],
        finding['UpdatedAt'],
        finding['AwsAccountId'],
        finding['AwsAccountName'],
        finding['Region'],
        finding['Severity']['Label'],
        finding['ProductName'],
        finding['Title'],
        finding['Description'],
        finding['Resources'][0]['Id'],
        f"https://{os.environ['AWS_REGION']}.console.aws.amazon.com/securityhub/home?region={os.environ['AWS_REGION']}#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A{finding['Id']}"
    ]
    return(row)