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
from gspread.exceptions import WorksheetNotFound
import boto3
import gspread
import json
import os

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

# Lambda execution starts here
def handler(event, context):
    logger.debug("Received event: " + json.dumps(event, sort_keys=True))

    sheet_name = os.environ['GSHEET_NAME']
    today = datetime.today().strftime('%Y-%m-%d')
    worksheet_name = f"Findings-{today}"


    logger.info(f"Attempting to open {sheet_name} using {GOOGLE_SECRET['client_email']}")
    try:
        credentials = service_account.Credentials.from_service_account_info(GOOGLE_SECRET, scopes=SCOPES)
        gc = gspread.authorize(credentials)
        gsheet = gc.open(sheet_name)
        try:
            worksheet = gsheet.worksheet(worksheet_name)
        except WorksheetNotFound as e:
            worksheet = gsheet.add_worksheet(worksheet_name, 100, len(HEADER_ROW), index=0)
            worksheet.append_row(HEADER_ROW, value_input_option='RAW', insert_data_option="INSERT_ROWS", include_values_in_response=False)
    except Exception as e:
        logger.critical(f"Failed to open Google Sheet: {e}")
        return(False)

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
                    "properties": {
                        "hiddenByUser": True,
                    },
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
            }
        ]
    }
    res = gsheet.batch_update(body)

    for record in event['Records']:
        sns_message = json.loads(record['body'])
        if 'Message' in sns_message:
            sns_message2 = json.loads(sns_message['Message'])
            s3_record_list = sns_message2['Records']
        else:
            s3_record_list = message['Records']

        for s3_record in s3_record_list:
            bucket = s3_record['s3']['bucket']['name']
            obj_key = s3_record['s3']['object']['key']

            logger.info(f"Processing file s3://{bucket}/{obj_key}")
            findings_to_process = get_object(bucket, obj_key)
            if findings_to_process is None:
                raise Exception(f"Failed to get s3://{bucket}/{obj_key}") # This will force a requeue?

            row_of_rows = []

            logger.info(f"{len(findings_to_process)} findings to process in s3://{bucket}/{obj_key}")
            for f in findings_to_process:
                if f['Status'] == "PASS" or f['Status'] == "INFO":
                    continue
                # Remove verbose and deep top-level keys
                del f['Compliance']
                del f['Remediation']
                logger.debug(f"queueing {json.dumps(f, default=str)}")
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
                row_of_rows.append(row)
                if len(row_of_rows) > 20:
                    logger.debug(f"Writing {len(row_of_rows)} rows to google")
                    worksheet.append_rows(row_of_rows, value_input_option='RAW', insert_data_option="INSERT_ROWS", include_values_in_response=False)
                    row_of_rows = []

            # Write the remaining data for this file
            logger.debug(f"Writing {len(row_of_rows)} rows to google")
            worksheet.append_rows(row_of_rows, value_input_option='RAW', insert_data_option="INSERT_ROWS", include_values_in_response=False)
            row_of_rows = []


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