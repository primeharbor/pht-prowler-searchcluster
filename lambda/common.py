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
import requests
from time import sleep
from typing import Dict, List, Optional

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from urllib.parse import unquote

logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

def get_object(bucket, obj_key):
    '''get the object to index from S3 and return the parsed json'''
    s3 = boto3.client('s3')
    try:
        response = s3.get_object(
            Bucket=bucket,
            Key=unquote(obj_key)
        )
        return(json.loads(response['Body'].read()))
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

def get_cache_secret(secret_arn):
    headers = {"X-Aws-Parameters-Secrets-Token": os.environ.get("AWS_SESSION_TOKEN")}

    secrets_extension_endpoint = (
        "http://localhost:"
        + "2773"
        + "/secretsmanager/get?secretId="
        + secret_arn
    )

    r = requests.get(secrets_extension_endpoint, headers=headers)
    secret = json.loads(r.text)["SecretString"]
    secret = json.loads(secret)

    return secret

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