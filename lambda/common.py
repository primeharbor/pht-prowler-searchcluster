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
from requests_aws4auth import AWS4Auth
from time import sleep
from urllib.parse import unquote
import boto3
import json
import os
import requests

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

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

def get_org_account_details():
    org_client = boto3.client('organizations')
    try:
        account_list = []
        response = org_client.list_accounts(MaxResults=20)
        while 'NextToken' in response:
            account_list = account_list + response['Accounts']
            response = org_client.list_accounts(MaxResults=20, NextToken=response['NextToken'])
        account_list = account_list + response['Accounts']

        # Make it a dictionary
        output = {}
        for a in account_list:
            output[a['Id']] = a
        return(output)
    except ClientError as e:
        if e.response['Error']['Code'] == 'AWSOrganizationsNotInUseException':
            logger.error(f"This is not part of an AWS Organization")
        elif e.response['Error']['Code'] == 'AccessDeniedException':
            logger.error(f"This is not an Organization Management or Delegated Admin Account")
        elif e.response['Error']['Code'] == 'TooManyRequestsException':
            logger.warning(f"Got RateLimited. Sleeping for 10sec")
            sleep(10)
            return(get_org_account_details())
        else:
            raise