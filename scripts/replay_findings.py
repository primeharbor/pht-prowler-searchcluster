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
import datetime as dt
import time

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

BATCH_SIZE=20

def main(args, logger):

    all_regions = get_regions(args)

    if args.service == 'guardduty':
        for region in all_regions:
            replay_guardduty(args, logger, region)
        exit(0)
    elif args.service == 'access-analyzer':
        for region in all_regions:
            replay_ia2(args, logger, region)
        exit(0)
    else:
        logger.warning(f"Invalid Service: {args.service}. Aborting")
        exit(1)



def replay_ia2(args, logger, region):

    logger.info(f"Processing Access Analyser in {region}")
    client = boto3.client('accessanalyzer', region_name=region)

    response = client.list_analyzers(type='ORGANIZATION')
    analyzer_arn = response['analyzers'][0]['arn']  # There can be only one (for now)

    count = 0
    response = client.list_findings(
        analyzerArn=analyzer_arn,
        maxResults=50
        )

    # while 'nextToken' in response:
    #     logger.debug(f"Got {len(response['findings'])} findings")
    #     for f in response['findings']:
    #         event = {'source': 'aws.access-analyzer', 'detail': f, "event_replay": "replay_script" }
    #         # print(json.dumps(event, default=str))
    #         count +=1
    #         invoke_function(event, args.function_name)

    #     response = client.list_findings(
    #         analyzerArn=analyzer_arn,
    #         maxResults=50,
    #         nextToken=response['nextToken']
    #         )
    #     # End loop

    logger.debug(f"Got final {len(response['findings'])} findings")
    for f in response['findings']:
        event = {'source': 'aws.access-analyzer', 'detail': f, "event_replay": "replay_script" }
        # print(json.dumps(event, default=str))
        count +=1
        invoke_function(event, args.function_name)

    logger.info(f"Invoked {count} lambda in {region}")


def replay_guardduty(args, logger, region):

    logger.info(f"Processing GuardDuty in {region}")

    client = boto3.client('guardduty', region_name=region)

    target_datetime = dt.datetime.now() - dt.timedelta(days=int(args.days))
    target_timestamp = int(target_datetime.timestamp())

    finding_criteria = {
        'Criterion': {
            'updatedAt': {  # Type: Timestamp in Unix Epoch millisecond format: 1486685375000
                'GreaterThanOrEqual': target_timestamp * 1000
            }
        }
    }

    findings = []

    response = client.list_detectors()
    detector_id = response['DetectorIds'][0]  # There can be only one (for now)

    response = client.list_findings(
        DetectorId=detector_id,
        FindingCriteria=finding_criteria,
        MaxResults=50
        )

    while response['NextToken'] != "":
        logger.debug(f"Got {len(response['FindingIds'])} findings")
        finding_response = client.get_findings(
            DetectorId=detector_id,
            FindingIds=response['FindingIds']
        )
        for f in finding_response['Findings']:
            findings.append(f)
        response = client.list_findings(
            DetectorId=detector_id,
            FindingCriteria=finding_criteria,
            MaxResults=50,
            NextToken=response['NextToken']
            )
        # End loop

    logger.debug(f"Got final {len(response['FindingIds'])} findings")
    finding_response = client.get_findings(
        DetectorId=detector_id,
        FindingIds=response['FindingIds']
    )
    for f in finding_response['Findings']:
        findings.append(f)

    logger.debug("Invoking Lambda")
    for f in findings:
        # print(f['Id'])
        lowercase_key_findings = lowercase_keys(f)
        event = {'source': 'aws.guardduty', 'detail': lowercase_key_findings, "event_replay": "replay_script" }
        # print(json.dumps(event, default=str))
        invoke_function(event, args.function_name)

    logger.info(f"Invoked {len(findings)} lambda in {region}")


# Thanks ChatGPT
def lowercase_keys(data):
    if isinstance(data, dict):
        new_dict = {}
        for key, value in data.items():
            new_key = key[0].lower() + key[1:]
            new_dict[new_key] = lowercase_keys(value) if isinstance(value, (dict, list)) else value
        return new_dict
    elif isinstance(data, list):
        return [lowercase_keys(item) if isinstance(item, (dict, list)) else item for item in data]
    else:
        return data


def invoke_function(event, function_name):
    # print("Invoking Lambda")
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


def get_regions(args):
    '''Return a list of regions with us-east-1 first. If --region was specified, return a list wth just that'''

    # If we specifed a region on the CLI, return a list of just that
    if args.region:
        return([args.region])

    # otherwise return all the regions, us-east-1 first
    ec2 = boto3.client('ec2')
    response = ec2.describe_regions()
    output = ['us-east-1']
    for r in response['Regions']:
        # return us-east-1 first, but dont return it twice
        if r['RegionName'] == "us-east-1":
            continue
        output.append(r['RegionName'])

    if args.exclude_regions:
        exclude_regions = ' '.join(args.exclude_regions).replace(',',' ').split()
        output = list(set(output) - set(exclude_regions))

    return(output)


def do_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--error", help="print error info only", action='store_true')
    parser.add_argument("--service", help="AWS Service to replay", required=True)
    parser.add_argument("--days", help="Replay this many days back", default=7)
    parser.add_argument("--function-name", help="Lambda Function Name to invoke", required=True)

    parser.add_argument("--region", help="Only look for default VPCs in this region")
    parser.add_argument("--exclude-regions", nargs='+', help="REGION1, REGION2 Do not attempt to delete default VPCs in these regions")


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

    try:
        main(args, logger)
    except KeyboardInterrupt:
        exit(1)

