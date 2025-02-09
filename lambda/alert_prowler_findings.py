# Copyright 2025 Chris Farris <chrisf@primeharbor.com>
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


from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError
from typing import Dict, List
import json
import logging
import os

from common import get_object, get_slack_secret, send_slack_message, SlackAuthException

logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv("LOG_LEVEL", default="INFO")))
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

# Using environ to raise KeyError if not provided
SLACK_SECRET_ARN = os.environ["SLACK_SECRET"]
SLACK_API_TOKEN, SLACK_CHANNEL_ID = get_slack_secret(SLACK_SECRET_ARN)
CONFIG_BUCKET = os.environ["CONFIG_BUCKET"]
CONFIG_PREFIX = os.getenv("CONFIG_PREFIX", "slack_alert.yaml")

config_data = get_object(CONFIG_BUCKET, CONFIG_PREFIX, type="yaml")
if not config_data:
    logger.warning("Config data/file not found. No alerts will be sent")
    config_data = {}

logger.info("alert_prowler_findings initiated")

# Lambda execution starts here
def handler(event, context):
    logger.debug("Received event: " + json.dumps(event, sort_keys=True))

    for record in event["Records"]:
        if record['eventSource'] != "aws:dynamodb":
            continue
        if record['eventName'] == "INSERT":
            ddb_record = record['dynamodb']['NewImage']
            logger.debug(ddb_record)
            new_image = deseralize(ddb_record)
            finding_uid = new_image.get("finding_info_uid")
            metadata_event_code = new_image.get("metadata_event_code")
            if metadata_event_code not in config_data.get("ProwlerChecks", []):
                logger.info(f"Check {metadata_event_code} is not in the list of checks to alert on")
                continue
            blocks = generate_finding_alert(new_image)
            logger.debug(json.dumps(blocks, default=str))
            try:
                send_slack_message(SLACK_API_TOKEN, SLACK_CHANNEL_ID, blocks=blocks)
                logger.info(f"Successfully sent alert to slack for finding id {finding_uid}")
            except SlackAuthException:
                slack_api_token, slack_channel_id = get_slack_secret(SLACK_SECRET_ARN)
                try:
                    send_slack_message(slack_api_token, slack_channel_id, blocks=blocks)
                    logger.info(f"Successfully sent alert to slack for finding id {finding_uid} after refreshing slack secret")
                except SlackAuthException:
                    logger.error(f"Slack secret is not working properly. Failed to send alert to slack for finding id {finding_uid}")


def generate_finding_alert(new_finding_data: Dict) -> List[Dict]:
    """Given a finding, create the slack formatted message"""
    aws_account = new_finding_data["cloud_account_uid"]
    finding_info_uid = new_finding_data["finding_info_uid"]
    finding_title = new_finding_data["title"]
    metadata_event_code = new_finding_data["metadata_event_code"]
    severity = new_finding_data["severity"]
    status_detail = new_finding_data["status_detail"]
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"""
*{severity} severity prowler finding discovered in account `{aws_account}`*
*Finding Title:* {finding_title}
*Status Detail:* {status_detail}
*Finding ID:* `{finding_info_uid}`
                """
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Finding Type:* `{metadata_event_code}`"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Account ID:* `{aws_account}`"
                },
            ]
        }
    ]

    return blocks

def deseralize(ddb_record):
    # This is probablt a semi-dangerous hack.
    # https://github.com/boto/boto3/blob/e353ecc219497438b955781988ce7f5cf7efae25/boto3/dynamodb/types.py#L233
    ds = TypeDeserializer()
    output = {}
    for k, v in ddb_record.items():
        output[k] = ds.deserialize(v)
    return(output)