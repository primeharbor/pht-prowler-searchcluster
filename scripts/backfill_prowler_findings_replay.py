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

import argparse
import json
import logging
import os
import re
from typing import List
from time import sleep

import boto3
import boto3.session


logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='DEBUG')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


def list_objects(session, bucket, prefix) -> List[str]:
    s3 = session.client("s3")
    objects = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        if "Contents" in page:
            for obj in page["Contents"]:
                objects.append(obj["Key"])

    return objects

def replay_object(session, topic_arn: str, bucket_name: str, key: str):
    sns = session.client("sns")
    logger.info(f"replaying object {key}")
    sns_message = {"Records": [{"s3": {"bucket": {"name": bucket_name}, "object": {"key": key}}}]}
    sns_message = json.dumps(sns_message)
    sns.publish(TopicArn=topic_arn, Message=sns_message)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bucket", help="S3 bucket where findings are", required=True)
    parser.add_argument("--topic", help="SNS topic to replay topics to", required=True)
    parser.add_argument("--prefix", help="Prefix where json files live in bucket", default="prowler4-output/json-ocsf/")
    parser.add_argument("--profile", help="AWS profile to use. Default will default to 'default'")
    parser.add_argument("--region", help="AWS region to use. Defaults to us-east-1", default="us-east-1")
    parser.add_argument("--account-id", help="Only process this account")
    parser.add_argument("--pause", help="Pause this number of seconds between files", default=1)

    args = parser.parse_args()

    session = boto3.session.Session(profile_name=args.profile, region_name=args.region)
    sts = session.client("sts")
    account_id = sts.get_caller_identity().get("Account")
    topic_arn = f"arn:aws:sns:{args.region}:{account_id}:{args.topic}"
    logger.info(f"replaying to topic {topic_arn}")

    file_name_account_id_regex = r'\b\d{12}\b'
    objects = list_objects(session, args.bucket, args.prefix)
    account_files = {}
    for object in objects:
        match = re.search(file_name_account_id_regex, object)
        account_number = match.group(0)
        account_files.setdefault(account_number, []).append(object)

    for account, account_object_names in account_files.items():
        if args.account_id is not None and account != args.account_id:
            continue
        logger.info(f"backfilling findings for account {account} from {len(account_object_names)} objects")
        for object_name in account_object_names:
            replay_object(session, topic_arn, args.bucket, object_name)
            sleep(args.pause)

if __name__ == "__main__":
    main()