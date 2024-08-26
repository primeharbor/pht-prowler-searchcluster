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

import requests

from common import get_cache_secret


logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

# Using environ to raise KeyError if not provided
SLACK_SECRET_ARN = os.environ["SLACK_SECRET"]

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
        # send_slack_message(slack_api_token, slack_channel_id, ddb_entry)
        
def send_slack_message(token: str, channel_id: str, text: str):
    url = 'https://slack.com/api/chat.postMessage'
    headers = {'Authorization': f'Bearer {token}'}
    payload = {
        'channel': channel_id,
        'text': text
    }

    response = requests.post(url, headers=headers, json=payload)

    response.raise_for_status()

    logger.info("successfully sent alert to slack")