#!/usr/bin/env python3
# Copyright 2019-2020 Turner Broadcasting Inc. / WarnerMedia
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

from elasticsearch import Elasticsearch
from requests_aws4auth import AWS4Auth
import boto3
import json
import os
import requests

import logging
logger = logging.getLogger()
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('elasticsearch').setLevel(logging.WARNING)


# Lambda execution starts here
def main(args, logger):
    logger.debug(f"Running {args.action} against {args.stackname}")

    config = get_stack_outputs(args)

    if 'DomainEndpoint' not in config:
        print("Failed to get Endpoint. Aborting....")
        exit(1)

    region = os.environ['AWS_DEFAULT_REGION']
    service = 'es'
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)

    if args.action == "register":
        register_repo(config, args, awsauth)

    elif args.action == "list":
        list_snapshots(config, args, awsauth)

    elif args.action == "status":
        if not is_snapshot_in_progress(config, args, awsauth):
            print("No Snapshots in progress")

    elif args.action == "take":
        if not args.snapshot_name:
            print("No Snapshot name specified. Aborting....")
            exit(1)
        if is_snapshot_in_progress(config, args, awsauth):
            print("Snapshot is in progress. Aborting...")
            exit(1)
        take_snapshot(config, args, awsauth)

    elif args.action == "restore":
        if not args.snapshot_name:
            print("No Snapshot name specified. Aborting....")
            exit(1)
        if is_snapshot_in_progress(config, args, awsauth):
            print("Snapshot is in progress. Aborting...")
            exit(1)
        restore_snapshot(config, args, awsauth)

    elif args.action == "load":
        if not args.file_name:
            print("No file name specified. Aborting....")
            exit(1)
        load_file(config, args, awsauth)


    else:
        print("Invalid Action")


def load_file(config, args, awsauth):
    url = f"{config['DomainEndpoint']}/_dashboards/api/saved_objects/_import?overwrite=true"
    headers = {'osd-xsrf': 'true'}

    try:
        if os.path.exists(args.file_name):
            with open(args.file_name, 'rb') as fd:
                r = requests.post(url=url, files={'file': fd}, headers=headers, auth=awsauth)
                logger.info(r.text)

    except Exception as e:
        print(f"Error: {e}")
        exit(1)

    if r.status_code == 200:
        print("Success")
        exit(0)
    else:
        print(f"Error {r.status_code}: {r.text}")
        exit(1)


def take_snapshot(config, args, awsauth):
    url = f"{config['DomainEndpoint']}/_snapshot/{args.snapshot_repo}/{args.snapshot_name}"
    try:
        logger.debug(f"PUT to {url}")
        r = requests.put(url, auth=awsauth)
    except Exception as e:
        print(f"Error: {e}")
        exit(1)

    if r.status_code == 200:
        print("Success")
        exit(0)
    else:
        print(f"Error {r.status_code}: {r.text}")
        exit(1)


def restore_snapshot(config, args, awsauth):
    url = f"{config['DomainEndpoint']}/_snapshot/{args.snapshot_repo}/{args.snapshot_name}/_restore"
    # payload = {"indices": "-.kibana*,-.opendistro*,-*findings"}
    # payload = {"indices": "-.opendistro_security", "include_global_state": False}
    payload = {"indices": "prowler_findings"}
    headers = {"Content-Type": "application/json"}
    try:
        logger.debug(f"POST to {url}")
        r = requests.post(url, auth=awsauth, json=payload, headers=headers)
    except Exception as e:
        print(f"Error: {e}")
        exit(1)

    if r.status_code == 200:
        print("Success")
        exit(0)
    else:
        print(f"Error {r.status_code}: {r.text}")
        exit(1)


def register_repo(config, args, awsauth):

    if 'SnapshotRoleArn' not in config:
        print("No Role ARN specified. Aborting....")
        exit(1)
    if 'SnapshotBucketName' not in config:
        print("No Bucket specified. Aborting....")
        exit(1)
    if not args.snapshot_prefix:
        print("No snapshot_prefix specified. Aborting....")
        exit(1)
    if not args.snapshot_repo:
        print("No snapshot_repo specified. Aborting....")
        exit(1)

    path = f"/_snapshot/{args.snapshot_repo}" # the Elasticsearch API endpoint
    url = config['DomainEndpoint'] + path

    payload = {
      "type": "s3",
      "settings": {
        "bucket": config['SnapshotBucketName'],
        "role_arn": config['SnapshotRoleArn'],
        "base_path": args.snapshot_prefix,
        "server_side_encryption": True
      }
    }

    if os.environ['AWS_DEFAULT_REGION'] == "us-east-1":
        payload['settings']['endpoint'] = "s3.amazonaws.com"
    else:
        payload['settings']['region'] = os.environ['AWS_DEFAULT_REGION']

    headers = {"Content-Type": "application/json"}
    try:
        logger.debug(f"PUT to {url}")
        logger.debug(f"Payload: {json.dumps(payload)}")
        r = requests.put(url, auth=awsauth, json=payload, headers=headers)
    except Exception as e:
        print(f"Error: {e}")
        exit(1)

    if r.status_code == 200:
        print("Success")
        exit(0)
    else:
        print(f"Error {r.status_code}: {r.text}")
        exit(1)


#
# Run a simple GET against the cluster and return the json results as a dict
#
def es_get(awsauth, host, path):
    url = host + path
    logger.debug(f"GET to {url}")
    r = requests.get(url, auth=awsauth)
    logger.debug(r.status_code)
    if r.status_code == 200:
        response = json.loads(r.text)
        logger.debug(json.dumps(response, sort_keys=True, indent=2))
        return(response)
    else:
        logger.error(f"Got error {r.status_code} from request to {url}: {r.text}")


def is_snapshot_in_progress(config, args, awsauth):
    path = '/_snapshot/_status'
    response = es_get(awsauth, config['DomainEndpoint'], path)
    if len(response['snapshots']) == 0:
        return(False)
    else:
        for s in response['snapshots']:
            print(f"Snapshot {s['snapshot']} in {s['repository']} is state {s['state']}")
        return(True)


def list_snapshots(config, args, awsauth):
    path = f"/_snapshot/{args.snapshot_repo}/_all?pretty"
    response = es_get(awsauth, config['DomainEndpoint'], path)
    if 'snapshots' not in response:
        logger.error(f"No Snapshots returned: {response}")
        return(None)
    for s in response['snapshots']:
        print(f"Snapshot {s['snapshot']} taken at {s['start_time']} is state {s['state']}")


def get_stack_outputs(args):
    try:
        client = boto3.client('cloudformation')
        response = client.describe_stacks(StackName=args.stackname)
        output = {}
        for o in response['Stacks'][0]['Outputs']:
            output[o['OutputKey']] = o['OutputValue']

        # apply overrides
        if args.domain:
            output['DomainEndpoint'] = args.domain
        if args.role_arn:
            output['SnapshotRoleArn'] = args.role_arn
        if args.bucket:
            output['SnapshotBucketName'] = args.bucket

        return(output)
    except Exception as e:
        logger.critical(f"Failed to get stack outputs from {stackname}: {e}")
        exit(1)


def do_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--error", help="print error info only", action='store_true')
    parser.add_argument("--stackname", help="OpenSearch Stack Name", required=True)


    parser.add_argument("--domain", help="Override OpenSearch DomainName (must include https://)")
    parser.add_argument("--bucket", help="Override Snapshot Bucket")
    parser.add_argument("--role-arn", help="Override Snapshot Role Arn")

    parser.add_argument("--action", help="Action to take", required=True, choices=['register', 'list', 'status', 'take', 'restore', 'load'])
    parser.add_argument("--snapshot-name", help="Snapshot name")
    parser.add_argument("--snapshot-repo", help="Snapshot Repository Name", default="opensearch-snapshots")
    parser.add_argument("--snapshot-prefix", help="S3 Prefix for Snapshot Repository")

    parser.add_argument("--file-name", help="filename to load")

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

