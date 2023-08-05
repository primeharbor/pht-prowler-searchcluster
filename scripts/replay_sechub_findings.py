#!/usr/bin/env python3
# Copyright 2023 Chris Farris <chris@primeharbor.com>
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

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

BATCH_SIZE=20

def main(args, logger):

    client = boto3.client('securityhub')

    response = client.get_findings(
        Filters={
            'ProductName': [
                 {"Comparison": "EQUALS",
                 "Value": args.product}
             ],
            'RecordState': [{"Comparison": "EQUALS", "Value": "ACTIVE"}]
            },
        MaxResults=BATCH_SIZE
        )

    while 'NextToken' in response:
        logger.info(f"Got {len(response['Findings'])} findings")
        event = {'detail': {'findings': [] } }
        for f in response['Findings']:
            event['detail']['findings'].append(f)
        invoke_function(event, args.function_name)
        response = client.get_findings(
            Filters={
                'ProductName': [
                     {"Comparison": "EQUALS",
                     "Value": args.product}
                 ],
                'RecordState': [{"Comparison": "EQUALS", "Value": "ACTIVE"}]
                },
            MaxResults=BATCH_SIZE,
            NextToken=response['NextToken']
            )
        # End loop

    logger.info(f"Got {len(response['Findings'])} findings")
    event = {'detail': {'findings': [] } }
    for f in response['Findings']:
        event['detail']['findings'].append(f)
    invoke_function(event, args.function_name)

    exit(0)


def invoke_function(event, function_name):
    print("Invoking Lambda")
    try:
        client = boto3.client('lambda')
        response = client.invoke(
            FunctionName=function_name,
            InvocationType='Event',
            Payload=json.dumps(event, default=str),
        )
    except ClientError as e:
        logger.error(f"Got error invoking lambda: {e}")
        exit(1)


def do_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--error", help="print error info only", action='store_true')
    parser.add_argument("--product", help="Security Hub Product to replay", required=True)
    parser.add_argument("--function-name", help="Lambda Function Name to invoke", required=True)

    args = parser.parse_args()

    return(args)

if __name__ == '__main__':

    args = do_args()

    # Logging idea stolen from: https://docs.python.org/3/howto/logging.html#configuring-logging
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    if args.error:
        logger.setLevel(logging.ERROR)
    elif args.debug:
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

    # # Sanity check region
    # if args.region:
    #     os.environ['AWS_DEFAULT_REGION'] = args.region

    # if 'AWS_DEFAULT_REGION' not in os.environ:
    #     logger.error("AWS_DEFAULT_REGION Not set. Aborting...")
    #     exit(1)

    main(args, logger)