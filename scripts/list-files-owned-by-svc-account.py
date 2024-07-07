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
import json
from google.oauth2 import service_account
from googleapiclient.discovery import build

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('googleapiclient').setLevel(logging.WARNING)

# Scopes required for accessing Google Drive
SCOPES = ['https://www.googleapis.com/auth/drive.readonly']

def list_google_sheets(args):

    # Authenticate and construct service
    creds = service_account.Credentials.from_service_account_file(args.service_account_cred_file, scopes=SCOPES)
    service = build('drive', 'v3', credentials=creds)

    if args.mine:
        query = f"mimeType='application/vnd.google-apps.spreadsheet' and '{creds.service_account_email}' in owners"
    else:
        query = "mimeType='application/vnd.google-apps.spreadsheet'"

    results = service.files().list(q=query, pageSize=100,
        fields="nextPageToken, files(id, name, parents, ownedByMe, teamDriveId, driveId)",
        corpora='allDrives', includeItemsFromAllDrives=True, supportsAllDrives=True
        ).execute()
    items = results.get('files', [])

    if not items:
        print('No files found.')
    else:
        print('Google Sheets:')
        for item in items:
            parents = item.get('parents', [])
            if parents:
                parent_names = [get_folder_name(parent, service) for parent in parents]
                parents_str = str(parent_names[0])
            else:
                parents_str = 'No parent folder'
            # parents_str = str(item.get('parents', []))
            if 'driveId' not in item:
                item['driveId'] = "N/A"
            print(f"\t{item['name']} ({item['id']}), Parent Folder: {parents_str}, DriveID: {item['driveId']}")
            logger.debug(json.dumps(item))


def get_folder_name(folder_id, service):
    try:
        folder = service.files().get(fileId=folder_id, fields='name').execute()
        return folder['name']
    except Exception as e:
        logger.debug(f"get_folder_name(): An error occurred: {e}")
        return folder_id


def do_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--mine", help="Only Show files the service account owns", action='store_true')
    parser.add_argument("--service-account-cred-file", help="Credentials File", required=True)

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
        list_google_sheets(args)
    except KeyboardInterrupt:
        exit(1)