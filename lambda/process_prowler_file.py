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
import boto3
import json
import os
import requests

from common import *

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
                s3_record_list = message['Records']
        else:
            s3_record_list = event['Records']

        for s3_record in s3_record_list:
            bucket = s3_record['s3']['bucket']['name']
            obj_key = s3_record['s3']['object']['key']

            logger.info(f"Processing file s3://{bucket}/{obj_key}")
            findings_to_process = get_object(bucket, obj_key)
            if findings_to_process is None:
                raise Exception(f"Failed to get s3://{bucket}/{obj_key}") # This will force a requeue?

            logger.info(f"{len(findings_to_process)} findings to process in s3://{bucket}/{obj_key}")
            for f in findings_to_process:
                if f['status_code'] == "MANUAL":
                    continue
                logger.debug(f"queueing {json.dumps(f, default=str)}")
                try:
                    response = sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(f, default=str))
                except Exception as e:
                    logger.error(f"Failed to process finding {f['finding_info']['uid']} in s3://{bucket}/{obj_key}. Error: {e}")

