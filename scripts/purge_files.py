#!/usr/bin/env python3
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
from gspread.exceptions import WorksheetNotFound, APIError
from time import sleep
import boto3
import gspread
import json
import os
import re

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

SCOPES = [
    'https://www.googleapis.com/auth/drive',
    'https://spreadsheets.google.com/feeds'
]

# Lambda execution starts here
def main(args):
    google_secret = getSecret(args.secret_name)

    logger.info(f"Purging contents of {args.folder_id} using {google_secret['client_email']}")
    try:
        credentials = service_account.Credentials.from_service_account_info(google_secret, scopes=SCOPES)

        drive_service = build('drive', 'v3', credentials=credentials)
        stuff_to_delete = list_folder(drive_service, args.folder_id)
        logger.debug(stuff_to_delete)
        for file in stuff_to_delete:
            logger.info(f"Deleting {file['name']}")
            try:
                drive_service.files().delete(fileId=file['id']).execute()
            except Exception as e:
                logger.error(f"Error deleting file/folder with ID {file['id']}: {e.reason}")

    except Exception as e:
        logger.critical(f"Failed to open Folder: {e}")
        return(False)

    exit(1)

def list_folder(drive_service, parent_folder_id=None):
    """List folders and files in Google Drive."""
    results = drive_service.files().list(
        q=f"'{parent_folder_id}' in parents and trashed=false" if parent_folder_id else None,
        pageSize=1000,
        fields="nextPageToken, files(id, name, mimeType)"
    ).execute()
    items = results.get('files', [])
    return(items)

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


def do_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--folder-id", help="Folder ID to purge", required=True)
    parser.add_argument("--secret-name", help="Secrets Manager Secret for Service Account", required=True)

    args = parser.parse_args()

    return(args)


if __name__ == '__main__':

    args = do_args()

    # Logging idea stolen from: https://docs.python.org/3/howto/logging.html#configuring-logging
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # create formatter
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatter = logging.Formatter('%(levelname)s - %(message)s')
    # add formatter to ch
    ch.setFormatter(formatter)
    # add ch to logger
    logger.addHandler(ch)

    try:
        main(args)
    except KeyboardInterrupt:
        exit(1)
