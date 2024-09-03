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


import json
import logging
import os
from typing import Dict, List

import boto3
from dynamodb_json import json_util as ddb_json

from common import get_cache_secret, get_object, send_slack_message


logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv("LOG_LEVEL", default="INFO")))
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

# Using environ to raise KeyError if not provided
SLACK_SECRET_ARN = os.environ["SLACK_SECRET"]
CONFIG_BUCKET = os.environ["CONFIG_BUCKET"]
CONFIG_PREFIX = os.getenv("CONFIG_PREFIX", "slack_alert.yaml")

s3 = boto3.client("s3")
config_data = get_object(CONFIG_BUCKET, CONFIG_PREFIX, type="yaml")
if not config_data:
    logger.warning("Config data/file not found. No alerts will be sent")
    config_data = {}

logger.info("alert_prowler_findings initiated")

# Lambda execution starts here
def handler(event, context):
    logger.debug("Received event: " + json.dumps(event, sort_keys=True))
    slack_secret = get_cache_secret(SLACK_SECRET_ARN)
    # Also want a key error here if this fails
    slack_api_token = slack_secret["SLACK_API_TOKEN"]
    slack_channel_id = slack_secret["SLACK_CHANNEL_ID"]

    for record in event["Records"]:
        ddb_entry = record["dynamodb"]
        ddb_entry = ddb_json.loads(ddb_entry)
        finding_uid = ddb_entry.get("NewImage", {}).get("finding_info_uid")
        metadata_event_code = ddb_entry.get("NewImage", {}).get("metadata_event_code")
        if metadata_event_code in config_data.get("alert_event_codes", []):
            send_slack_message(slack_api_token, slack_channel_id, blocks=generate_finding_alert(ddb_entry))
            logger.info(f"succesfully sent alert to slack for finding id {finding_uid}")
        
def generate_finding_alert(finding: Dict) -> List[Dict]:
    new_finding_data = finding.get("NewImage", {})
    finding_title = new_finding_data["finding_info"]["title"]
    aws_account = new_finding_data["cloud_account_uid"]
    aws_account_name = new_finding_data.get("cloud", {}).get("account", {}).get("name")
    metadata_event_code = new_finding_data["metadata_event_code"]
    status_detail = new_finding_data["status_detail"]
    severity = new_finding_data["severity"]
    resource_fields = []
    for resource in new_finding_data.get("resources", []):
        resource_fields.append(
            {
                "type": "mrkdwn",
                "text": f"*Resource Name:* `{resource.get('name')}`"
            }
        )
        resource_fields.append(
            {
                "type": "mrkdwn",
                "text": f"*Resource ARN:* `{resource.get('uid')}`"
            }
        )

    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{severity} severity prowler finding `{metadata_event_code}` discovered in account `{aws_account}`*"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Finding Title:* {finding_title}"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Status Detail:* {status_detail}"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Account Name:* `{aws_account_name}`"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Account ID:* `{aws_account}`"
                },
            ]
        },
        {
            "type": "section",
            "fields": resource_fields
        }
    ]

    return blocks