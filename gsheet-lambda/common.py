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
from urllib.parse import unquote
import boto3
import gspread
import json
import os

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

# Throttle Settings for Google Sheets
BATCH_SIZE=250
SLEEP_INTERVAL=10

SCOPES = [
    'https://www.googleapis.com/auth/drive',
    'https://spreadsheets.google.com/feeds'
]

def get_object(bucket, obj_key):
    '''get the object to index from S3 and return the parsed json'''
    s3 = boto3.client('s3')
    try:
        response = s3.get_object(
            Bucket=bucket,
            Key=unquote(obj_key)
        )
        return(json.loads(response['Body'].read()))
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            logger.error("Unable to find resource s3://{}/{}".format(bucket, obj_key))
        else:
            logger.error("Error getting resource s3://{}/{}: {}".format(bucket, obj_key, e))
        return(None)

def open_or_create_gsheet(sheet_name, worksheet_name, header_row):

    google_secret = getSecret(os.environ['GSHEET_SECRET'])
    new_folder_id = os.environ['GOOGLE_DRIVE_ID']

    credentials = service_account.Credentials.from_service_account_info(google_secret, scopes=SCOPES)
    gc = gspread.authorize(credentials)

    logger.info(f"Attempting to open {sheet_name} using {google_secret['client_email']}")
    try:
        gsheet = gc.open(sheet_name)
        return(gsheet)

    except SpreadsheetNotFound:
        logger.info(f"Google Sheet {sheet_name} doesn't exist, creating it.")

        drive_service = build('drive', 'v3', credentials=credentials)
        # new_folder_id = create_folder(drive_service, folder_name, parent_folder_id=os.environ['GOOGLE_DRIVE_ID'])
        gsheet = gc.create(title=sheet_name, folder_id=new_folder_id)
        # share_response = gsheet.share('chris@primeharbor.com', perm_type='user', role='writer', notify=True, email_message="You Have a New Scorecard")
        # print(json.dumps(share_response.json(), default=str))
        # permissionId = share_response.json()["id"]
        # gsheet.transfer_ownership(permissionId)

        worksheet = gsheet.add_worksheet(worksheet_name, 1, len(header_row), index=0)
        worksheet.append_row(header_row, value_input_option='RAW', insert_data_option="INSERT_ROWS", include_values_in_response=False)

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
                                "endColumnIndex": len(header_row)
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

        return(gsheet)

    except Exception as e:
        logger.critical(f"Failed to open Google Sheet: {e}")
        return(None)

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
        import base64
        secret = base64.b64decode(secretData['SecretBinary'])  # binary

    secret = json.loads(secret)
    return secret

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