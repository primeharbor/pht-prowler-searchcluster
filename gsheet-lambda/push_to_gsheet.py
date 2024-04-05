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
from gspread.exceptions import WorksheetNotFound, APIError
import boto3
import gspread
import json
import os
import re
from time import sleep

from common import *

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)


HEADER_ROW = ['FindingUniqueId', 'AssessmentStartTime', 'AccountId', 'AccountName', 'CheckID', "Severity", 'Status', "CheckTitle", "ServiceName", "SubServiceName", "Region", "ResourceArn", "ResourceName",  "StatusExtended"]

SCOPES = [
    'https://www.googleapis.com/auth/drive',
    'https://spreadsheets.google.com/feeds'
]

BATCH_SIZE=250
SLEEP_INTERVAL=10

# Lambda execution starts here
def handler(event, context):
    logger.debug("Received event: " + json.dumps(event, sort_keys=True))

    sheet_name = os.environ['GSHEET_NAME']
    logger.info(f"Attempting to open {sheet_name} using {GOOGLE_SECRET['client_email']}")
    try:
        credentials = service_account.Credentials.from_service_account_info(GOOGLE_SECRET, scopes=SCOPES)
        gc = gspread.authorize(credentials)
        gsheet = gc.open(sheet_name)
    except Exception as e:
        logger.critical(f"Failed to open Google Sheet: {e}")
        return(False)

    for record in event['Records']:
        if 'body' in record:
            sns_message = json.loads(record['body'])
            if 'Message' in sns_message:
                sns_message2 = json.loads(sns_message['Message'])
                if sns_message2['Event'] == "s3:TestEvent":
                    logger.warning(f"Received Test Event. Doing Nothing.")
                    continue
                s3_record_list = sns_message2['Records']
            else:
                s3_record_list = message['Records']
        else:
            s3_record_list = event['Records']

        for s3_record in s3_record_list:
            bucket = s3_record['s3']['bucket']['name']
            obj_key = s3_record['s3']['object']['key']
            process_file(bucket, obj_key, gsheet)


def process_file(bucket, obj_key, gsheet):
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

    worksheet_name = f"Findings-{today}"
    try:
        worksheet = gsheet.worksheet(worksheet_name)
    except WorksheetNotFound as e:
        worksheet = gsheet.add_worksheet(worksheet_name, 1, len(HEADER_ROW), index=0)
        worksheet.append_row(HEADER_ROW, value_input_option='RAW', insert_data_option="INSERT_ROWS", include_values_in_response=False)

        # Format the google sheet
        sheetId = worksheet._properties['sheetId']
        body = {
            "requests": [
                {
                    "updateDimensionProperties": {
                        "range": {
                            "sheetId": sheetId,
                            "dimension": "COLUMNS",
                            "startIndex": 0,
                            "endIndex": 2
                        },
                        "properties": {"hiddenByUser": True},
                        "fields": "hiddenByUser"
                    }
                },
                {
                    "setBasicFilter":
                    {
                        "filter":
                        {
                        "range":
                            {
                                "sheetId": sheetId,
                                "startColumnIndex": 0, #column A
                                "endColumnIndex": len(HEADER_ROW)
                            }
                        }
                    }
                },
                {
                    'updateSheetProperties': {
                        'properties': {
                            "sheetId": sheetId,
                            'gridProperties': {'frozenRowCount': 1}},
                        'fields': 'gridProperties.frozenRowCount',
                    }
                }
            ]
        }
        res = gsheet.batch_update(body)

    row_of_rows = []
    count = 0

    logger.info(f"{len(findings_to_process)} findings to process in s3://{bucket}/{obj_key}")
    for f in findings_to_process:
        if 'FindingUniqueId' in f:  # Native Prowler
            row = process_prowler_native(f)
        else:
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
        "NotInOCSF", # f['CheckID'],
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


def write_to_gsheet(wks, rows):
    try:
        logger.debug(f"Writing {len(rows)} rows to google")
        wks.append_rows(rows, value_input_option='RAW', insert_data_option="INSERT_ROWS", include_values_in_response=False)
        return(len(rows))
    except APIError as e:
        if e.response.status_code == 429:
            logger.warning(f"Getting Throttled. Sleeping for {SLEEP_INTERVAL}s {e.response.reason}")
            sleep(SLEEP_INTERVAL)
            return(write_to_gsheet(wks, rows))
        else:
            logger.error(f"Got API Error: {e.response.reason}")
            raise


def getSecret(secretName):
    """
    If a secret name is correctly passed in at runtime, in this class, this will using the sm reference,
    go and retrieve the SecretString value and return it to the user
    as a json body.
    """
    session = boto3.session.Session()
    sm = session.client('secretsmanager')

    try:
        secretData = sm.get_secret_value(SecretId=secretName)
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            logger.exception("Provided KMS Key Decryption Failure: {}".format(e))
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            logger.exception("Server Side Service Level Error: {}".format(e))
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logger.exception("Invalid Value for Parameter: {}".format(e))
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            logger.exception("Invalid Request: {}".format(e))
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.exception("Requested Provided Does Not Exist: {}".format(e))
            raise e
        elif e.response['Error']['Code'] == 'AccessDeniedException':
            logger.exception(f"Function doesn't have access to secret {secretName}: {e}")
            raise e
        else:
            logger.exception(f"Undefined Error fetching secret: {secretName} Auth?")
            raise e

    if 'SecretString' in secretData:
        secret = secretData['SecretString']  # dictionary
    else:
        secret = base64.b64decode(secretData['SecretBinary'])  # binary

    secret = json.loads(secret)
    return secret


GOOGLE_SECRET=getSecret(os.environ['GSHEET_SECRET'])