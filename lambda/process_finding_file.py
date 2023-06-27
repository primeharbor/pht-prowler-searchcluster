# Copyright 2019-2020 Turner Broadcasting Inc. / WarnerMedia
# Copyright 2021 Chris Farris <chrisf@primeharbor.com>
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
from urllib.parse import unquote
import boto3
import json
import os

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)


# Lambda execution starts here
def handler(event, context):
    logger.debug("Received event: " + json.dumps(event, sort_keys=True))

    sqs_client = boto3.client('sqs')
    queue_url = os.environ['FINDING_QUEUE_URL']

    org_details = get_org_account_details()

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

            logger.info(f"{len(findings_to_process)} findings to process in s3://{bucket}/{obj_key}")
            for f in findings_to_process:
                # Remove verbose and deep top-level keys
                del f['Compliance']
                del f['Remediation']
                # Decorate the finding with Org Info
                if f['AccountId'] in org_details:
                    f['AccountInfo'] = org_details[f['AccountId']]
                logger.debug(f"queueing {json.dumps(f, default=str)}")
                response = sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(f, default=str))


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
        else:
            raise


