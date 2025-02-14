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
import urllib3
from time import sleep
from typing import Dict, List, Optional
import yaml

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from urllib.parse import unquote

logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

def get_object(bucket, obj_key, type: Optional[str] = "json"):
    '''get the object to index from S3 and return the parsed json or yaml'''
    s3 = boto3.client('s3')
    try:
        response = s3.get_object(
            Bucket=bucket,
            Key=unquote(obj_key)
        )
        body = response["Body"].read()
        if type == "yaml":
            return yaml.safe_load(body)
        else:
            return json.loads(body)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            logger.error("Unable to find resource s3://{}/{}".format(bucket, obj_key))
        else:
            logger.error("Error getting resource s3://{}/{}: {}".format(bucket, obj_key, e))
        return(None)

def put_object(bucket: str, obj_key: str, content: bytes, **kwargs):
    s3 = boto3.client("s3")
    put_object_kwargs = {"Bucket": bucket, "Key": unquote(obj_key), "Body": content}
    put_object_kwargs.update(kwargs)

    try:
        s3.put_object(**put_object_kwargs)
    except ClientError as e:
        logger.error(f"Error putting resource s3://{bucket}/{obj_key}: {e}")
        raise

def put_dict_object(bucket: str, obj_key: str, content: Dict, **kwargs):
    json_content = json.dumps(content, indent=4)
    kwargs.update({"ContentType": "application/json"})
    put_object(bucket, obj_key, json_content, **kwargs)

def get_org_account_details():
    org_client = boto3.client('organizations')
    try:
        account_list = []
        response = org_client.list_accounts(MaxResults=20)
        while 'NextToken' in response:
            account_list = account_list + response['Accounts']
            response = org_client.list_accounts(MaxResults=20, NextToken=response['NextToken'])
        account_list = account_list + response['Accounts']

        # Make it a dictionary & fetch the tags
        output = {}
        for a in account_list:
            output[a['Id']] = a
            output[a['Id']]['Tags'] = {}
            tags_response = org_client.list_tags_for_resource(ResourceId=a['Id'])
            for t in tags_response['Tags']:
                output[a['Id']]['Tags'][t['Key']] = t['Value']
        return(output)
    except ClientError as e:
        if e.response['Error']['Code'] == 'AWSOrganizationsNotInUseException':
            logger.error(f"This is not part of an AWS Organization")
        elif e.response['Error']['Code'] == 'AccessDeniedException':
            logger.error(f"This is not an Organization Management or Delegated Admin Account")
        elif e.response['Error']['Code'] == 'TooManyRequestsException':
            logger.warning(f"Got RateLimited. Sleeping for 10sec")
            sleep(10)
            return(get_org_account_details())
        else:
            raise

def get_secret(secret_arn):
    sm = boto3.client("secretsmanager")

    try:
        response = sm.get_secret_value(SecretId=secret_arn)

        # Check if the secret contains the secret string or binary data
        if "SecretString" in response:
            secret = response["SecretString"]
        else:
            secret = response["SecretBinary"]

        # Parse secret if it's in JSON format
        try:
            secret = json.loads(secret)
        except json.JSONDecodeError:
            # If it's not JSON, just return the string
            pass

        return secret

    except ClientError as e:
        if e.response["Error"]["Code"] == "DecryptionFailureException":
            logger.error(f"Failed to decrypt secret {secret_arn}")
        elif e.response["Error"]["Code"] == "ResourceNotFoundException":
            logger.error(f"The requested secret ({secret_arn}) does not exist")
        else:
            logger.error(f"Unexpected ClientError: {e}")

        return None

def get_slack_secret(secret_arn):
    """Re-usable function specifically for the expected slack secret"""
    slack_secret = get_secret(secret_arn)
    # Also want a key error here if this fails
    slack_api_token = slack_secret["SLACK_API_TOKEN"]
    slack_channel_id = slack_secret["SLACK_CHANNEL_ID"]

    return slack_api_token, slack_channel_id

class SlackException(Exception):
    pass

class SlackAuthException(SlackException):
    pass

def send_slack_message(token: str, channel_id: str, text: Optional[str] = None, blocks: Optional[List[Dict]] = None):
    url = "https://slack.com/api/chat.postMessage"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"channel": channel_id}

    if text:
        payload["text"] = text
    elif blocks:
        payload["blocks"] = blocks
    else:
        raise ValueError("Either 'text' or 'blocks' are required.")

    http = urllib3.PoolManager()
    response = http.request("POST", url, body=json.dumps(payload), headers=headers)

    if response.status == 429: # Rate Limit
        sleep(10)
        response = http.request("POST", url, body=json.dumps(payload), headers=headers)

    if response.status != 200:
        raise SlackException(f"HTTP error {response.status}: {response.data.decode('utf-8')}")

    response_content = json.loads(response.data.decode("utf-8"))
    if not response_content.get("ok", True):
        if response_content.get("error") == "invalid_auth":
            raise SlackAuthException()
        else:
            raise SlackException(f"Unhandled exception while sending message - {response_content.get('error')}")

class DynamoDBTable:
    """
    General wrapper for DynamoDB operations
    """
    def __init__(self, table_name: str) -> None:
        self.table_name = table_name
        dynamodb = boto3.resource("dynamodb")
        self.table = dynamodb.Table(self.table_name)

    def batch_write_items(self, items: List[Dict], batch_size: Optional[int] = 25) -> None:
        """
        Given a list of dictionaries, batch write them all to the table

        Args:
            items (List[Dict]): list of dictionaries to write
            batch_size (Optional[int]): size of the batches to write. Default (and max) is 25
        """
        if batch_size > 25:
            batch_size = 25

        logger.info(f"writing {len(items)} items to DynamoDB table {self.table_name}")

        written_items = 0
        for i in range(0, len(items), batch_size):
            batch = items[i:i+batch_size]
            written_items += len(batch)
            with self.table.batch_writer() as batch_writer:
                for item in batch:
                    batch_writer.put_item(Item=item)

        logger.info(f"wrote {written_items} items to DynamoDB table {self.table_name}")

    def paginate_query(self, index_name: str, key_condition_expression: "Key", projection_expression: str) -> List[Dict]:
        """
        Standard table query that will automatically paginate, if applicable

        Args:
            index_name (str): index to query
            key_condition_expression (Key): ddb KeyConditionExpression
            projection_expression (str): which fields to return

        Returns:
            combined_response (List[Dict]): list of dictionary items returned from query
        """
        combined_response = []
        response = self.table.query(
            IndexName=index_name,
            KeyConditionExpression=key_condition_expression,
            ProjectionExpression=projection_expression
        )
        combined_response.extend(response.get("Items", []))

        while "LastEvaluatedKey" in response:
            response = self.table.query(
                IndexName=index_name,
                KeyConditionExpression=key_condition_expression,
                ProjectionExpression=projection_expression,
                ExclusiveStartKey=response["LastEvaluatedKey"]
            )
            combined_response.extend(response.get("Items", []))

        logger.info(f"paginated query returned {len(combined_response)} items")

        return combined_response