#!/usr/bin/env python3

# Copyright 2024 Chris Farris <chris@primeharbor.com>
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

# ChatGPT wrote most of this

import os
from google.oauth2 import service_account
from googleapiclient.discovery import build

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

# Scopes required for accessing Google Drive
SCOPES = [
    'https://www.googleapis.com/auth/drive',
    'https://spreadsheets.google.com/feeds'
]

def delete_google_sheet(args):

    # Authenticate and construct service
    creds = service_account.Credentials.from_service_account_file(args.service_account_cred_file, scopes=SCOPES)
    service = build('drive', 'v3', credentials=creds)

    try:
        service.files().delete(fileId=args.sheet_id).execute()
        print(f"Google Sheet with ID {args.sheet_id} has been deleted.")
    except Exception as e:
        print(f"An error occurred: {e}")


def do_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--service-account-cred-file", help="Credentials File", required=True)
    parser.add_argument("--sheet-id", help="Sheet ID to Delete", required=True)

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
        delete_google_sheet(args)
    except KeyboardInterrupt:
        exit(1)