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
import boto3
import json
import os
import time

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)


def main(args, logger):

    sh_client = boto3.client('securityhub')
    count = 0

    response = sh_client.get_findings(
        Filters={
            'ProductArn': [ { 'Value': args.product_arn, 'Comparison': 'EQUALS' } ],
            'WorkflowStatus': [ { 'Value': 'RESOLVED', 'Comparison': 'NOT_EQUALS' } ],
            'RecordState': [ { 'Value': 'ACTIVE', 'Comparison': 'EQUALS' } ],
            },
        MaxResults=100
        )
    while 'NextToken' in response:
        for f in response['Findings']:
            logger.debug(f"{f['Id']}:{f['UpdatedAt']}:{f['WorkflowState']}")
            count += 1
        if args.purge:
            purge_findings(sh_client, response['Findings'], args.product_arn)
        response = sh_client.get_findings(
            Filters={
                'ProductArn': [ { 'Value': args.product_arn, 'Comparison': 'EQUALS' } ],
                'WorkflowStatus': [ { 'Value': 'RESOLVED', 'Comparison': 'NOT_EQUALS' } ],
                'RecordState': [ { 'Value': 'ACTIVE', 'Comparison': 'EQUALS' } ],
                },
            MaxResults=100,
            NextToken=response['NextToken']
            )

    for f in response['Findings']:
        logger.debug(f"{f['Id']}:{f['UpdatedAt']}:{f['WorkflowState']}")
        count += 1
    if args.purge:
        purge_findings(sh_client, response['Findings'], args.product_arn)

    print(f"Found {count} findings")
    return(True)

def purge_findings(sh_client, findings, product_arn):
    if len(findings) == 0:
        return(True)
    logger.info(f"Purging {len(findings)} findings")
    FindingIdentifiers=[]
    for f in findings:
        FindingIdentifiers.append({'ProductArn': product_arn, 'Id': f['Id']})
    response = sh_client.batch_update_findings(
        FindingIdentifiers=FindingIdentifiers,
        Workflow={'Status': 'RESOLVED'}
    )

def do_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--purge", help="Actually do the purge", action='store_true')
    parser.add_argument("--product-arn", help="Product Arn to purge", required=True)
    parser.add_argument("--region", help="Product Arn to purge", required=True)
    args = parser.parse_args()

    return (args)


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

    main(args, logger)
